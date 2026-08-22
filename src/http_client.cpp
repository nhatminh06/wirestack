#include "wirestack/http_client.hpp"

#include <algorithm>
#include <cctype>
#include <cstdint>
#include <limits>
#include <string_view>

namespace wirestack {

namespace {

std::string_view asView(std::span<const std::byte> bytes) {
    return {reinterpret_cast<const char*>(bytes.data()), bytes.size()};
}

// Same tchar/control-byte rules as http.cpp's request parser (RFC 7230);
// duplicated rather than shared because the two parsers otherwise have no
// meaningful coupling and each stays independently readable.
bool isTokenChar(char c) {
    if ((c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9')) {
        return true;
    }
    static constexpr std::string_view kExtra = "!#$%&'*+-.^_`|~";
    return kExtra.find(c) != std::string_view::npos;
}

bool isControlByte(unsigned char c) {
    return c < 0x20 || c == 0x7f;
}

std::string toLower(std::string_view s) {
    std::string out(s);
    for (char& c : out) {
        c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
    }
    return out;
}

// Structural check only: "HTTP/" DIGIT "." DIGIT.
bool isValidVersionSyntax(std::string_view version) {
    static constexpr std::string_view kPrefix = "HTTP/";
    if (version.size() != kPrefix.size() + 3) return false;
    if (version.substr(0, kPrefix.size()) != kPrefix) return false;
    unsigned char major = static_cast<unsigned char>(version[kPrefix.size()]);
    unsigned char dot = static_cast<unsigned char>(version[kPrefix.size() + 1]);
    unsigned char minor = static_cast<unsigned char>(version[kPrefix.size() + 2]);
    return std::isdigit(major) != 0 && dot == '.' && std::isdigit(minor) != 0;
}

bool isAllDigits(std::string_view s) {
    if (s.empty()) return false;
    return std::all_of(s.begin(), s.end(), [](char c) { return c >= '0' && c <= '9'; });
}

std::string_view trimTrailingOws(std::string_view s) {
    while (!s.empty() && (s.back() == ' ' || s.back() == '\t')) {
        s.remove_suffix(1);
    }
    return s;
}

enum class StatusLineOutcome { Malformed, UnsupportedVersion, Ok };

struct StatusLineParse {
    StatusLineOutcome outcome;
    int code = 0;
};

// `line` excludes the trailing CRLF.
StatusLineParse parseStatusLine(std::string_view line) {
    auto first_space = line.find(' ');
    if (first_space == std::string_view::npos) {
        return {StatusLineOutcome::Malformed};
    }
    std::string_view version = line.substr(0, first_space);
    if (!isValidVersionSyntax(version)) {
        return {StatusLineOutcome::Malformed};
    }
    if (version != "HTTP/1.0") {
        return {StatusLineOutcome::UnsupportedVersion};
    }

    std::string_view rest = line.substr(first_space + 1);
    if (rest.empty() || rest.front() == ' ') {
        return {StatusLineOutcome::Malformed}; // no status code, or a second space
    }
    auto second_space = rest.find(' ');
    if (second_space == std::string_view::npos) {
        return {StatusLineOutcome::Malformed}; // no separator before the reason phrase
    }
    std::string_view code_str = rest.substr(0, second_space);
    if (code_str.size() != 3 || !isAllDigits(code_str)) {
        return {StatusLineOutcome::Malformed};
    }
    int code = (code_str[0] - '0') * 100 + (code_str[1] - '0') * 10 + (code_str[2] - '0');
    if (code < 200 || code > 599) {
        return {StatusLineOutcome::Malformed}; // covers 1xx and any other out-of-range value
    }

    std::string_view reason = rest.substr(second_space + 1);
    for (char c : reason) {
        unsigned char uc = static_cast<unsigned char>(c);
        if (uc != '\t' && isControlByte(uc)) {
            return {StatusLineOutcome::Malformed};
        }
    }

    return {StatusLineOutcome::Ok, code};
}

HttpResponseParseResult reject(HttpResponseParseStatus status) {
    return HttpResponseParseResult{status, std::nullopt, {}, false};
}

} // namespace

HttpResponseParseResult parseHttpResponse(std::span<const std::byte> buffer, bool peer_closed) {
    std::string_view view = asView(buffer);

    auto status_line_end = view.find("\r\n");
    if (status_line_end == std::string_view::npos) {
        if (view.size() > kMaxHttpResponseStatusLineLength) {
            return reject(HttpResponseParseStatus::TooLarge);
        }
        if (peer_closed) {
            return reject(HttpResponseParseStatus::Truncated);
        }
        return reject(HttpResponseParseStatus::Incomplete);
    }
    if (status_line_end + 2 > kMaxHttpResponseStatusLineLength) {
        return reject(HttpResponseParseStatus::TooLarge);
    }

    auto status_parse = parseStatusLine(view.substr(0, status_line_end));
    if (status_parse.outcome == StatusLineOutcome::Malformed) {
        return reject(HttpResponseParseStatus::Malformed);
    }
    if (status_parse.outcome == StatusLineOutcome::UnsupportedVersion) {
        return reject(HttpResponseParseStatus::UnsupportedVersion);
    }

    auto terminator = view.find("\r\n\r\n");
    if (terminator == std::string_view::npos) {
        if (view.size() > kMaxHttpResponseHeaderBlockLength) {
            return reject(HttpResponseParseStatus::TooLarge);
        }
        if (peer_closed) {
            return reject(HttpResponseParseStatus::Truncated);
        }
        return reject(HttpResponseParseStatus::Incomplete);
    }
    if (terminator + 4 > kMaxHttpResponseHeaderBlockLength) {
        return reject(HttpResponseParseStatus::TooLarge);
    }

    std::string_view header_block = view.substr(0, terminator + 4);
    std::string_view extra = view.substr(terminator + 4);

    if (header_block.find('\0') != std::string_view::npos) {
        return reject(HttpResponseParseStatus::Malformed);
    }

    std::vector<std::string_view> lines;
    std::size_t pos = 0;
    while (true) {
        auto crlf = header_block.find("\r\n", pos);
        if (crlf == std::string_view::npos) {
            return reject(HttpResponseParseStatus::Malformed); // unreachable given terminator found
        }
        std::string_view line = header_block.substr(pos, crlf - pos);
        if (line.find('\r') != std::string_view::npos ||
            line.find('\n') != std::string_view::npos) {
            return reject(HttpResponseParseStatus::Malformed); // bare CR or bare LF inside a line
        }
        lines.push_back(line);
        pos = crlf + 2;
        if (line.empty()) break;
    }

    bool seen_content_length = false;
    bool has_transfer_encoding = false;
    std::uint64_t content_length = 0;
    bool content_length_overflowed = false;

    for (std::size_t i = 1; i + 1 < lines.size(); ++i) {
        std::string_view line = lines[i];
        if (line.empty()) {
            return reject(HttpResponseParseStatus::Malformed); // only the last line may be empty
        }
        if (line.front() == ' ' || line.front() == '\t') {
            return reject(HttpResponseParseStatus::Malformed); // obsolete folded continuation
        }
        auto colon = line.find(':');
        if (colon == std::string_view::npos || colon == 0) {
            return reject(HttpResponseParseStatus::Malformed);
        }
        std::string_view name = line.substr(0, colon);
        if (!std::all_of(name.begin(), name.end(), isTokenChar)) {
            return reject(HttpResponseParseStatus::Malformed);
        }
        std::string_view rest = line.substr(colon + 1);
        std::size_t value_start = 0;
        while (value_start < rest.size() &&
               (rest[value_start] == ' ' || rest[value_start] == '\t')) {
            ++value_start;
        }
        std::string_view value = trimTrailingOws(rest.substr(value_start));
        for (char c : value) {
            unsigned char uc = static_cast<unsigned char>(c);
            if (uc != '\t' && isControlByte(uc)) {
                return reject(HttpResponseParseStatus::Malformed);
            }
        }

        std::string lower_name = toLower(name);
        if (lower_name == "transfer-encoding") {
            has_transfer_encoding = true;
        } else if (lower_name == "content-length") {
            if (seen_content_length) {
                return reject(HttpResponseParseStatus::Malformed); // duplicate, even if values match
            }
            seen_content_length = true;
            if (!isAllDigits(value)) {
                return reject(HttpResponseParseStatus::Malformed); // sign, comma, hex, empty, junk
            }
            std::uint64_t v = 0;
            for (char c : value) {
                std::uint64_t d = static_cast<std::uint64_t>(c - '0');
                if (v > (std::numeric_limits<std::uint64_t>::max() - d) / 10) {
                    content_length_overflowed = true;
                    break;
                }
                v = v * 10 + d;
            }
            content_length = v;
        }
    }

    if (has_transfer_encoding) {
        return reject(HttpResponseParseStatus::UnsupportedTransferEncoding);
    }

    if (seen_content_length) {
        if (content_length_overflowed || content_length > kMaxHttpResponseBodyLength) {
            return reject(HttpResponseParseStatus::TooLarge);
        }
        auto n = static_cast<std::size_t>(content_length);
        if (extra.size() > n) {
            return reject(HttpResponseParseStatus::Malformed); // more than declared, or pipelined bytes
        }
        if (extra.size() < n) {
            return peer_closed ? reject(HttpResponseParseStatus::Truncated)
                                : reject(HttpResponseParseStatus::Incomplete);
        }
        HttpResponseParseResult result;
        result.status = HttpResponseParseStatus::Complete;
        result.status_code = status_parse.code;
        result.content_length_present = true;
        result.body.assign(buffer.begin() + static_cast<std::ptrdiff_t>(terminator + 4),
                            buffer.end());
        return result;
    }

    if (extra.size() > kMaxHttpResponseBodyLength) {
        return reject(HttpResponseParseStatus::TooLarge);
    }
    if (!peer_closed) {
        return reject(HttpResponseParseStatus::Incomplete);
    }
    HttpResponseParseResult result;
    result.status = HttpResponseParseStatus::Complete;
    result.status_code = status_parse.code;
    result.content_length_present = false;
    result.body.assign(buffer.begin() + static_cast<std::ptrdiff_t>(terminator + 4), buffer.end());
    return result;
}

std::optional<HttpClientTargetError> validateHttpClientTarget(std::string_view target) {
    if (target.empty()) {
        return HttpClientTargetError::Empty;
    }
    if (target.front() != '/') {
        return HttpClientTargetError::MissingLeadingSlash;
    }
    for (char c : target) {
        unsigned char uc = static_cast<unsigned char>(c);
        if (c == ' ' || isControlByte(uc)) {
            return HttpClientTargetError::InvalidByte;
        }
    }
    return std::nullopt;
}

namespace {

std::vector<std::byte> toBytes(std::string_view text) {
    std::vector<std::byte> out;
    out.reserve(text.size());
    for (char c : text) {
        out.push_back(static_cast<std::byte>(static_cast<unsigned char>(c)));
    }
    return out;
}

} // namespace

std::optional<std::vector<std::byte>> buildHttpGetRequest(Ipv4Address remote_ip,
                                                            std::uint16_t remote_port,
                                                            std::string_view target) {
    if (validateHttpClientTarget(target)) {
        return std::nullopt;
    }

    std::string text;
    text += "GET ";
    text += target;
    text += " HTTP/1.0\r\n";
    text += "Host: ";
    text += remote_ip.toString();
    text += ":";
    text += std::to_string(remote_port);
    text += "\r\n";
    text += "Connection: close\r\n";
    text += "\r\n";
    return toBytes(text);
}

} // namespace wirestack
