#include "wirestack/http.hpp"

#include <algorithm>
#include <array>
#include <cctype>
#include <string_view>

namespace wirestack {

namespace {

std::string_view asView(std::span<const std::byte> bytes) {
    return {reinterpret_cast<const char*>(bytes.data()), bytes.size()};
}

// RFC 7230 tchar: letters, digits, and a fixed punctuation set. Used for
// both method tokens and header field names.
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

// Splits `s` on `sep`, requiring exactly `count` non-empty fields (no
// leading/trailing/consecutive separators). Returns an empty vector if
// the structure doesn't match.
std::vector<std::string_view> splitExact(std::string_view s, char sep, std::size_t count) {
    std::vector<std::string_view> fields;
    std::size_t start = 0;
    while (true) {
        auto pos = s.find(sep, start);
        if (pos == std::string_view::npos) {
            fields.push_back(s.substr(start));
            break;
        }
        fields.push_back(s.substr(start, pos - start));
        start = pos + 1;
    }
    if (fields.size() != count) {
        return {};
    }
    for (auto field : fields) {
        if (field.empty()) {
            return {};
        }
    }
    return fields;
}

bool isValidMethodToken(std::string_view method) {
    if (method.empty()) return false;
    return std::all_of(method.begin(), method.end(), isTokenChar);
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

bool isValidTarget(std::string_view target) {
    if (target.empty() || target.front() != '/') return false;
    for (char c : target) {
        if (c == ' ' || isControlByte(static_cast<unsigned char>(c))) return false;
    }
    return true;
}

std::string toLower(std::string_view s) {
    std::string out(s);
    for (char& c : out) {
        c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
    }
    return out;
}

enum class HeadOutcome { Malformed, UnsupportedMethod, UnsupportedVersion, Complete };

struct HeadParse {
    HeadOutcome outcome;
    HttpRequest request; // valid only when outcome == Complete
};

HeadParse parseHead(std::string_view head_block) {
    // head_block ends with "\r\n\r\n" and has already been bound-checked
    // and confirmed free of embedded NUL by the caller.
    std::vector<std::string_view> lines;
    std::size_t pos = 0;
    while (true) {
        auto crlf = head_block.find("\r\n", pos);
        if (crlf == std::string_view::npos) {
            // Bound-checked caller guarantees the block ends in
            // "\r\n\r\n", so this only happens if a bare CR/LF earlier
            // consumed the pairing we expected -- treat as malformed.
            return {HeadOutcome::Malformed, {}};
        }
        std::string_view line = head_block.substr(pos, crlf - pos);
        if (line.find('\r') != std::string_view::npos ||
            line.find('\n') != std::string_view::npos) {
            return {HeadOutcome::Malformed, {}}; // bare CR or bare LF inside a line
        }
        lines.push_back(line);
        pos = crlf + 2;
        if (line.empty()) break; // terminating blank line
    }

    // lines[0] is the request-line. An empty first line means the block
    // started with "\r\n\r\n" -- no request-line at all.
    if (lines.front().empty()) {
        return {HeadOutcome::Malformed, {}};
    }

    auto tokens = splitExact(lines.front(), ' ', 3);
    if (tokens.empty()) {
        return {HeadOutcome::Malformed, {}};
    }
    std::string_view method = tokens[0];
    std::string_view target = tokens[1];
    std::string_view version = tokens[2];

    if (!isValidMethodToken(method)) return {HeadOutcome::Malformed, {}};
    if (!isValidVersionSyntax(version)) return {HeadOutcome::Malformed, {}};
    if (!isValidTarget(target)) return {HeadOutcome::Malformed, {}};

    if (method != "GET") return {HeadOutcome::UnsupportedMethod, {}};
    if (version != "HTTP/1.0") return {HeadOutcome::UnsupportedVersion, {}};

    bool seen_content_length = false;
    for (std::size_t i = 1; i + 1 < lines.size(); ++i) {
        std::string_view line = lines[i];
        if (line.empty()) {
            return {HeadOutcome::Malformed, {}}; // only the last line may be empty
        }
        if (line.front() == ' ' || line.front() == '\t') {
            return {HeadOutcome::Malformed, {}}; // obsolete folded continuation
        }
        auto colon = line.find(':');
        if (colon == std::string_view::npos || colon == 0) {
            return {HeadOutcome::Malformed, {}};
        }
        std::string_view name = line.substr(0, colon);
        if (!std::all_of(name.begin(), name.end(), isTokenChar)) {
            return {HeadOutcome::Malformed, {}};
        }
        std::string_view rest = line.substr(colon + 1);
        std::size_t value_start = 0;
        while (value_start < rest.size() &&
               (rest[value_start] == ' ' || rest[value_start] == '\t')) {
            ++value_start;
        }
        std::string_view value = rest.substr(value_start);
        for (char c : value) {
            unsigned char uc = static_cast<unsigned char>(c);
            if (uc != '\t' && isControlByte(uc)) {
                return {HeadOutcome::Malformed, {}};
            }
        }

        std::string lower_name = toLower(name);
        if (lower_name == "transfer-encoding") {
            return {HeadOutcome::Malformed, {}};
        }
        if (lower_name == "content-length") {
            if (seen_content_length) {
                return {HeadOutcome::Malformed, {}};
            }
            seen_content_length = true;
            // Any value other than the exact string "0" is rejected --
            // this single equality covers nonzero, malformed-decimal,
            // and overflowing-decimal alike, so no numeric parsing (and
            // its overflow-safety burden) is needed at all.
            if (value != "0") {
                return {HeadOutcome::Malformed, {}};
            }
        }
    }

    HttpRequest request;
    request.method = std::string(method);
    request.target = std::string(target);
    request.version = std::string(version);
    return {HeadOutcome::Complete, std::move(request)};
}

} // namespace

HttpParseResult parseHttpRequest(std::span<const std::byte> buffer) {
    std::string_view view = asView(buffer);

    auto terminator = view.find("\r\n\r\n");
    auto first_crlf = view.find("\r\n");

    if (terminator == std::string_view::npos) {
        if (first_crlf != std::string_view::npos &&
            first_crlf + 2 > kMaxHttpRequestLineLength) {
            return {HttpParseStatus::TooLarge, std::nullopt};
        }
        if (view.size() >= kMaxHttpHeaderBlockLength) {
            return {HttpParseStatus::TooLarge, std::nullopt};
        }
        return {HttpParseStatus::Incomplete, std::nullopt};
    }

    if (first_crlf + 2 > kMaxHttpRequestLineLength) {
        return {HttpParseStatus::TooLarge, std::nullopt};
    }
    if (terminator + 4 > kMaxHttpHeaderBlockLength) {
        return {HttpParseStatus::TooLarge, std::nullopt};
    }

    std::string_view head_block = view.substr(0, terminator + 4);
    std::string_view extra = view.substr(terminator + 4);

    if (head_block.find('\0') != std::string_view::npos) {
        return {HttpParseStatus::Malformed, std::nullopt};
    }

    auto parsed = parseHead(head_block);
    switch (parsed.outcome) {
        case HeadOutcome::Malformed:
            return {HttpParseStatus::Malformed, std::nullopt};
        case HeadOutcome::UnsupportedMethod:
            return {HttpParseStatus::UnsupportedMethod, std::nullopt};
        case HeadOutcome::UnsupportedVersion:
            return {HttpParseStatus::UnsupportedVersion, std::nullopt};
        case HeadOutcome::Complete:
            if (!extra.empty()) {
                return {HttpParseStatus::Malformed, std::nullopt}; // pipelining/extra bytes
            }
            return {HttpParseStatus::Complete, std::move(parsed.request)};
    }
    return {HttpParseStatus::Malformed, std::nullopt};
}

void appendHttpBytes(HttpConnectionState& state, std::span<const std::byte> bytes) {
    if (state.buffer.size() >= kMaxHttpHeaderBlockLength) {
        return;
    }
    std::size_t room = kMaxHttpHeaderBlockLength - state.buffer.size();
    std::size_t take = std::min(room, bytes.size());
    state.buffer.insert(state.buffer.end(), bytes.begin(), bytes.begin() + take);
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

constexpr std::string_view kPlainTextContentType = "text/plain; charset=utf-8";

} // namespace

HttpResponse makeOkResponse() {
    return HttpResponse{HttpStatus::Ok200, std::string(kPlainTextContentType),
                         toBytes("Hello from Wirestack\n"), false};
}

HttpResponse makeBadRequestResponse() {
    return HttpResponse{HttpStatus::BadRequest400, std::string(kPlainTextContentType),
                         toBytes("Bad Request\n"), false};
}

HttpResponse makeNotFoundResponse() {
    return HttpResponse{HttpStatus::NotFound404, std::string(kPlainTextContentType),
                         toBytes("Not Found\n"), false};
}

HttpResponse makeMethodNotAllowedResponse() {
    return HttpResponse{HttpStatus::MethodNotAllowed405, std::string(kPlainTextContentType),
                         toBytes("Method Not Allowed\n"), true};
}

HttpResponse makeVersionNotSupportedResponse() {
    return HttpResponse{HttpStatus::VersionNotSupported505, std::string(kPlainTextContentType),
                         toBytes("HTTP Version Not Supported\n"), false};
}

HttpResponse selectResponse(const HttpRequest& request) {
    if (request.target == "/") {
        return makeOkResponse();
    }
    return makeNotFoundResponse();
}

namespace {

std::string_view statusLine(HttpStatus status) {
    switch (status) {
        case HttpStatus::Ok200:
            return "200 OK";
        case HttpStatus::BadRequest400:
            return "400 Bad Request";
        case HttpStatus::NotFound404:
            return "404 Not Found";
        case HttpStatus::MethodNotAllowed405:
            return "405 Method Not Allowed";
        case HttpStatus::VersionNotSupported505:
            return "505 HTTP Version Not Supported";
    }
    return "500 Internal Server Error";
}

} // namespace

std::vector<std::byte> serializeHttpResponse(const HttpResponse& response) {
    std::string head;
    head += "HTTP/1.0 ";
    head += statusLine(response.status);
    head += "\r\n";
    head += "Content-Type: ";
    head += response.content_type;
    head += "\r\n";
    head += "Content-Length: ";
    head += std::to_string(response.body.size());
    head += "\r\n";
    if (response.include_allow_get) {
        head += "Allow: GET\r\n";
    }
    head += "Connection: close\r\n";
    head += "\r\n";

    std::vector<std::byte> out = toBytes(head);
    out.insert(out.end(), response.body.begin(), response.body.end());
    return out;
}

} // namespace wirestack
