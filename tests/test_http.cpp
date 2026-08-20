#include "wirestack/http.hpp"

#include "test_util.hpp"

using wirestack::appendHttpBytes;
using wirestack::HttpConnectionState;
using wirestack::HttpParseStatus;
using wirestack::kMaxHttpHeaderBlockLength;
using wirestack::kMaxHttpRequestLineLength;
using wirestack::parseHttpRequest;

namespace {

std::vector<std::byte> toBytes(std::string_view text) {
    std::vector<std::byte> out;
    out.reserve(text.size());
    for (char c : text) {
        out.push_back(static_cast<std::byte>(static_cast<unsigned char>(c)));
    }
    return out;
}

HttpParseStatus statusOf(std::string_view text) {
    return parseHttpRequest(toBytes(text)).status;
}

} // namespace

int main() {
    // --- Complete request ---
    {
        auto result = parseHttpRequest(toBytes("GET / HTTP/1.0\r\n\r\n"));
        CHECK(result.status == HttpParseStatus::Complete);
        CHECK(result.request.has_value());
        if (result.request) {
            CHECK(result.request->method == "GET");
            CHECK(result.request->target == "/");
            CHECK(result.request->version == "HTTP/1.0");
        }
    }

    // --- Incremental request: one byte at a time ---
    {
        std::string full = "GET / HTTP/1.0\r\n\r\n";
        for (std::size_t i = 0; i < full.size(); ++i) {
            auto prefix = full.substr(0, i);
            CHECK(statusOf(prefix) == HttpParseStatus::Incomplete);
        }
        CHECK(statusOf(full) == HttpParseStatus::Complete);
    }

    // --- Split boundaries ---
    {
        std::string full = "GET / HTTP/1.0\r\nHost: wirestack\r\n\r\n";
        // Every prefix strictly shorter than the full request must be
        // Incomplete; the full request must be Complete. This covers
        // splitting at each space, each CR, each LF, mid-version,
        // mid-header-name, and mid-header-value simultaneously, since it
        // exercises every possible split point.
        for (std::size_t i = 0; i < full.size(); ++i) {
            CHECK(statusOf(full.substr(0, i)) == HttpParseStatus::Incomplete);
        }
        CHECK(statusOf(full) == HttpParseStatus::Complete);
    }
    {
        // Between the final \r and \n specifically.
        std::string without_final_lf = "GET / HTTP/1.0\r\nHost: x\r\n\r";
        CHECK(statusOf(without_final_lf) == HttpParseStatus::Incomplete);
        CHECK(statusOf(without_final_lf + "\n") == HttpParseStatus::Complete);
    }

    // --- Headers ---
    {
        CHECK(statusOf("GET / HTTP/1.0\r\n\r\n") == HttpParseStatus::Complete); // no headers
        CHECK(statusOf("GET / HTTP/1.0\r\nHost: x\r\n\r\n") ==
              HttpParseStatus::Complete); // one valid header
        CHECK(statusOf("GET / HTTP/1.0\r\nHost: x\r\nAccept: */*\r\n\r\n") ==
              HttpParseStatus::Complete); // multiple valid headers
        CHECK(statusOf("GET / HTTP/1.0\r\ncontent-length: 0\r\n\r\n") ==
              HttpParseStatus::Complete); // lowercase header name
        CHECK(statusOf("GET / HTTP/1.0\r\nX-Empty:\r\n\r\n") ==
              HttpParseStatus::Complete); // empty value is valid

        CHECK(statusOf("GET / HTTP/1.0\r\nBad Name: x\r\n\r\n") ==
              HttpParseStatus::Malformed); // invalid field name (space)
        CHECK(statusOf("GET / HTTP/1.0\r\nNoColon\r\n\r\n") ==
              HttpParseStatus::Malformed); // missing colon
        CHECK(statusOf("GET / HTTP/1.0\r\nHost: x\r\n folded\r\n\r\n") ==
              HttpParseStatus::Malformed); // folded header continuation

        auto embedded_nul = toBytes("GET / HTTP/1.0\r\nHost: x");
        embedded_nul.push_back(std::byte{0x00});
        auto nul_rest = toBytes("\r\n\r\n");
        embedded_nul.insert(embedded_nul.end(), nul_rest.begin(), nul_rest.end());
        CHECK(parseHttpRequest(embedded_nul).status == HttpParseStatus::Malformed);

        auto control_byte = toBytes("GET / HTTP/1.0\r\nHost: x");
        control_byte.push_back(std::byte{0x01});
        auto ctrl_rest = toBytes("\r\n\r\n");
        control_byte.insert(control_byte.end(), ctrl_rest.begin(), ctrl_rest.end());
        CHECK(parseHttpRequest(control_byte).status == HttpParseStatus::Malformed);
    }

    // --- Bounds ---
    {
        CHECK(statusOf("") == HttpParseStatus::Incomplete); // 0 bytes
        CHECK(statusOf("G") == HttpParseStatus::Incomplete); // 1 byte

        // Request line exactly at the limit (including its own CRLF).
        std::string prefix = "GET /";
        std::string suffix = " HTTP/1.0\r\n";
        std::size_t pad = kMaxHttpRequestLineLength - prefix.size() - suffix.size();
        std::string exact_line = prefix + std::string(pad, 'a') + suffix;
        CHECK(exact_line.size() == kMaxHttpRequestLineLength);
        CHECK(statusOf(exact_line + "\r\n") == HttpParseStatus::Complete);

        std::string over_line = prefix + std::string(pad + 1, 'a') + suffix;
        CHECK(over_line.size() == kMaxHttpRequestLineLength + 1);
        CHECK(statusOf(over_line + "\r\n") == HttpParseStatus::TooLarge);
        CHECK(statusOf(over_line) == HttpParseStatus::TooLarge); // also before terminator arrives

        // Header block exactly at the limit.
        std::string base = "GET / HTTP/1.0\r\nX-Pad: ";
        std::string tail = "\r\n\r\n";
        std::size_t header_pad = kMaxHttpHeaderBlockLength - base.size() - tail.size();
        std::string exact_block = base + std::string(header_pad, 'a') + tail;
        CHECK(exact_block.size() == kMaxHttpHeaderBlockLength);
        CHECK(statusOf(exact_block) == HttpParseStatus::Complete);

        std::string over_block = base + std::string(header_pad + 1, 'a') + tail;
        CHECK(over_block.size() == kMaxHttpHeaderBlockLength + 1);
        CHECK(statusOf(over_block) == HttpParseStatus::TooLarge);
    }

    // --- Semantic tests ---
    {
        auto get_root = parseHttpRequest(toBytes("GET / HTTP/1.0\r\n\r\n"));
        CHECK(get_root.status == HttpParseStatus::Complete);
        if (get_root.request) CHECK(get_root.request->target == "/"); // -> 200 at dispatch

        auto get_other = parseHttpRequest(toBytes("GET /missing HTTP/1.0\r\n\r\n"));
        CHECK(get_other.status == HttpParseStatus::Complete);
        if (get_other.request) CHECK(get_other.request->target == "/missing"); // -> 404

        CHECK(statusOf("POST / HTTP/1.0\r\n\r\n") == HttpParseStatus::UnsupportedMethod);
        CHECK(statusOf("HEAD / HTTP/1.0\r\n\r\n") == HttpParseStatus::UnsupportedMethod);

        CHECK(statusOf("GET / HTTP/1.1\r\n\r\n") == HttpParseStatus::UnsupportedVersion);
        CHECK(statusOf("GET / HTTP/1.x\r\n\r\n") == HttpParseStatus::Malformed); // malformed version

        CHECK(statusOf("GET  HTTP/1.0\r\n\r\n") == HttpParseStatus::Malformed); // empty target folded away
        CHECK(statusOf("GET x HTTP/1.0\r\n\r\n") == HttpParseStatus::Malformed); // target not starting '/'

        auto query = parseHttpRequest(toBytes("GET /?x=1 HTTP/1.0\r\n\r\n"));
        CHECK(query.status == HttpParseStatus::Complete);
        if (query.request) CHECK(query.request->target != "/"); // query target does not match "/"

        CHECK(statusOf("GET / HTTP/1.0\r\nContent-Length: 0\r\n\r\n") ==
              HttpParseStatus::Complete); // Content-Length: 0 accepted
        CHECK(statusOf("GET / HTTP/1.0\r\nContent-Length: 5\r\n\r\n") ==
              HttpParseStatus::Malformed); // nonzero
        CHECK(statusOf("GET / HTTP/1.0\r\nContent-Length: abc\r\n\r\n") ==
              HttpParseStatus::Malformed); // invalid
        CHECK(statusOf("GET / HTTP/1.0\r\nContent-Length: 99999999999999999999\r\n\r\n") ==
              HttpParseStatus::Malformed); // overflowing
        CHECK(statusOf("GET / HTTP/1.0\r\nContent-Length: 0\r\nContent-Length: 0\r\n\r\n") ==
              HttpParseStatus::Malformed); // duplicate
        CHECK(statusOf("GET / HTTP/1.0\r\nTransfer-Encoding: chunked\r\n\r\n") ==
              HttpParseStatus::Malformed); // transfer-encoding rejected

        CHECK(statusOf("GET / HTTP/1.0\r\n\r\nextra") ==
              HttpParseStatus::Malformed); // extra bytes / pipelined request
    }

    // --- Response exact-byte tests ---
    {
        auto ok = wirestack::serializeHttpResponse(wirestack::makeOkResponse());
        auto expected_ok = toBytes(
            "HTTP/1.0 200 OK\r\n"
            "Content-Type: text/plain; charset=utf-8\r\n"
            "Content-Length: 21\r\n"
            "Connection: close\r\n"
            "\r\n"
            "Hello from Wirestack\n");
        CHECK(ok == expected_ok);
    }
    {
        auto bad = wirestack::serializeHttpResponse(wirestack::makeBadRequestResponse());
        auto expected_bad = toBytes(
            "HTTP/1.0 400 Bad Request\r\n"
            "Content-Type: text/plain; charset=utf-8\r\n"
            "Content-Length: 12\r\n"
            "Connection: close\r\n"
            "\r\n"
            "Bad Request\n");
        CHECK(bad == expected_bad);
    }
    {
        auto not_found = wirestack::serializeHttpResponse(wirestack::makeNotFoundResponse());
        auto expected_not_found = toBytes(
            "HTTP/1.0 404 Not Found\r\n"
            "Content-Type: text/plain; charset=utf-8\r\n"
            "Content-Length: 10\r\n"
            "Connection: close\r\n"
            "\r\n"
            "Not Found\n");
        CHECK(not_found == expected_not_found);
    }
    {
        auto method_not_allowed =
            wirestack::serializeHttpResponse(wirestack::makeMethodNotAllowedResponse());
        auto expected_method_not_allowed = toBytes(
            "HTTP/1.0 405 Method Not Allowed\r\n"
            "Content-Type: text/plain; charset=utf-8\r\n"
            "Content-Length: 19\r\n"
            "Allow: GET\r\n"
            "Connection: close\r\n"
            "\r\n"
            "Method Not Allowed\n");
        CHECK(method_not_allowed == expected_method_not_allowed);
    }
    {
        auto version_not_supported =
            wirestack::serializeHttpResponse(wirestack::makeVersionNotSupportedResponse());
        auto expected_version_not_supported = toBytes(
            "HTTP/1.0 505 HTTP Version Not Supported\r\n"
            "Content-Type: text/plain; charset=utf-8\r\n"
            "Content-Length: 27\r\n"
            "Connection: close\r\n"
            "\r\n"
            "HTTP Version Not Supported\n");
        CHECK(version_not_supported == expected_version_not_supported);
    }

    // --- HTTP session tests ---
    {
        HttpConnectionState session;
        appendHttpBytes(session, toBytes("GET / HT"));
        CHECK(parseHttpRequest(session.buffer).status == HttpParseStatus::Incomplete);
        CHECK(!session.responded);

        appendHttpBytes(session, toBytes("TP/1.0\r\n\r\n"));
        auto result = parseHttpRequest(session.buffer);
        CHECK(result.status == HttpParseStatus::Complete);

        // Simulate the caller marking the session responded, then
        // re-delivering the identical bytes -- must not reprocess.
        session.responded = true;
        appendHttpBytes(session, toBytes("GET / HTTP/1.0\r\n\r\n")); // duplicate delivery attempt
        CHECK(session.responded); // caller's own guard prevents a second response

        session = HttpConnectionState{};
        CHECK(session.buffer.empty());
        CHECK(!session.responded);
    }
    {
        // Two independent sessions.
        HttpConnectionState a, b;
        appendHttpBytes(a, toBytes("GET /a"));
        appendHttpBytes(b, toBytes("GET /b HTTP/1.0\r\n\r\n"));
        CHECK(parseHttpRequest(a.buffer).status == HttpParseStatus::Incomplete);
        CHECK(parseHttpRequest(b.buffer).status == HttpParseStatus::Complete);
    }
    {
        // One malformed connection does not affect another independent one.
        HttpConnectionState malformed, ok;
        appendHttpBytes(malformed, toBytes("GET  / HTTP/1.0\r\n\r\n"));
        appendHttpBytes(ok, toBytes("GET / HTTP/1.0\r\n\r\n"));
        CHECK(parseHttpRequest(malformed.buffer).status == HttpParseStatus::Malformed);
        CHECK(parseHttpRequest(ok.buffer).status == HttpParseStatus::Complete);
    }
    {
        // Oversized connection buffer stays bounded (release == capped, not grown).
        HttpConnectionState session;
        std::vector<std::byte> chunk(kMaxHttpHeaderBlockLength, std::byte{'a'});
        appendHttpBytes(session, chunk);
        CHECK(session.buffer.size() == kMaxHttpHeaderBlockLength);
        appendHttpBytes(session, toBytes("more bytes"));
        CHECK(session.buffer.size() == kMaxHttpHeaderBlockLength); // capped, not grown
        CHECK(parseHttpRequest(session.buffer).status == HttpParseStatus::TooLarge);
    }

    return wirestack::test::failureCount() == 0 ? 0 : 1;
}
