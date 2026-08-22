// Deterministic unit tests for the outbound HTTP/1.0 client: the exact
// GET request serializer, target validation, and the bounded incremental
// response parser -- all independent of TCP/TAP.

#include "wirestack/http_client.hpp"
#include "wirestack/ipv4_address.hpp"

#include "test_util.hpp"

#include <array>
#include <string>

using namespace wirestack;

namespace {

std::vector<std::byte> toBytes(std::string_view text) {
    std::vector<std::byte> out;
    out.reserve(text.size());
    for (char c : text) {
        out.push_back(static_cast<std::byte>(static_cast<unsigned char>(c)));
    }
    return out;
}

Ipv4Address remoteIp() {
    return *Ipv4Address::parse("10.0.0.1");
}

constexpr std::array<std::uint8_t, 6> kBinaryBytes = {0x00, 0x01, 0x7f, 0x80, 0xff, 0x0a};

// --- Section 27: exact request bytes and rejection ----------------------

void testExactRequestRoot() {
    auto request = buildHttpGetRequest(remoteIp(), 9090, "/");
    CHECK(request.has_value());
    if (!request) return;
    std::string expected = "GET / HTTP/1.0\r\nHost: 10.0.0.1:9090\r\nConnection: close\r\n\r\n";
    CHECK(*request == toBytes(expected));
}

void testExactRequestHealth() {
    auto request = buildHttpGetRequest(remoteIp(), 9090, "/health");
    CHECK(request.has_value());
    if (!request) return;
    std::string expected =
        "GET /health HTTP/1.0\r\nHost: 10.0.0.1:9090\r\nConnection: close\r\n\r\n";
    CHECK(*request == toBytes(expected));
}

void testExactRequestNonDefaultPort() {
    auto request = buildHttpGetRequest(remoteIp(), 80, "/");
    CHECK(request.has_value());
    if (!request) return;
    std::string expected = "GET / HTTP/1.0\r\nHost: 10.0.0.1:80\r\nConnection: close\r\n\r\n";
    CHECK(*request == toBytes(expected));
}

void testRequestRejectsEmptyTarget() {
    CHECK(validateHttpClientTarget("") == HttpClientTargetError::Empty);
    CHECK(!buildHttpGetRequest(remoteIp(), 80, "").has_value());
}

void testRequestRejectsMissingLeadingSlash() {
    CHECK(validateHttpClientTarget("health") == HttpClientTargetError::MissingLeadingSlash);
    CHECK(!buildHttpGetRequest(remoteIp(), 80, "health").has_value());
}

void testRequestRejectsSpace() {
    CHECK(validateHttpClientTarget("/a b") == HttpClientTargetError::InvalidByte);
    CHECK(!buildHttpGetRequest(remoteIp(), 80, "/a b").has_value());
}

void testRequestRejectsCrInjection() {
    CHECK(validateHttpClientTarget("/a\r\nEvil: header") == HttpClientTargetError::InvalidByte);
    CHECK(!buildHttpGetRequest(remoteIp(), 80, "/a\r\nEvil: header").has_value());
}

void testRequestRejectsLfOnly() {
    CHECK(validateHttpClientTarget("/a\nb") == HttpClientTargetError::InvalidByte);
}

// --- Section 26: status line and headers ---------------------------------

HttpResponseParseResult parseWhole(std::string_view text, bool peer_closed = true) {
    return parseHttpResponse(toBytes(text), peer_closed);
}

void testStatus200() {
    auto r = parseWhole("HTTP/1.0 200 OK\r\nContent-Length: 5\r\n\r\nhello", false);
    CHECK(r.status == HttpResponseParseStatus::Complete);
    CHECK(r.status_code == 200);
    CHECK(r.body == toBytes("hello"));
    CHECK(r.content_length_present);
}

void testStatus204() {
    auto r = parseWhole("HTTP/1.0 204 No Content\r\nContent-Length: 0\r\n\r\n", false);
    CHECK(r.status == HttpResponseParseStatus::Complete);
    CHECK(r.status_code == 204);
    CHECK(r.body.empty());
}

void testStatus301() {
    auto r = parseWhole("HTTP/1.0 301 Moved Permanently\r\nContent-Length: 0\r\n\r\n", false);
    CHECK(r.status == HttpResponseParseStatus::Complete);
    CHECK(r.status_code == 301); // parsed, never followed -- no redirect support
}

void testStatus404() {
    auto r = parseWhole("HTTP/1.0 404 Not Found\r\nContent-Length: 0\r\n\r\n", false);
    CHECK(r.status == HttpResponseParseStatus::Complete);
    CHECK(r.status_code == 404);
}

void testStatus500() {
    auto r = parseWhole("HTTP/1.0 500 Internal Server Error\r\nContent-Length: 0\r\n\r\n", false);
    CHECK(r.status == HttpResponseParseStatus::Complete);
    CHECK(r.status_code == 500);
}

void testHttp11Rejected() {
    auto r = parseWhole("HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n", false);
    CHECK(r.status == HttpResponseParseStatus::UnsupportedVersion);
}

void test1xxRejected() {
    auto r = parseWhole("HTTP/1.0 100 Continue\r\n\r\n", false);
    CHECK(r.status == HttpResponseParseStatus::Malformed);
}

void testMalformedStatusCode() {
    auto r = parseWhole("HTTP/1.0 abc OK\r\n\r\n", false);
    CHECK(r.status == HttpResponseParseStatus::Malformed);
}

void testMissingReasonSeparator() {
    // No second space -- no separator before a (possibly empty) reason phrase.
    auto r = parseWhole("HTTP/1.0 200\r\n\r\n", false);
    CHECK(r.status == HttpResponseParseStatus::Malformed);
}

void testBareLfNeverCompletes() {
    // No CRLF sequence anywhere -- must never reach Complete, even with more
    // data and even after the peer closes.
    auto r = parseWhole("HTTP/1.0 200 OK\n\n", false);
    CHECK(r.status != HttpResponseParseStatus::Complete);
    auto r2 = parseWhole("HTTP/1.0 200 OK\n\n", true);
    CHECK(r2.status != HttpResponseParseStatus::Complete);
}

void testInvalidControlByteInReason() {
    std::string text = "HTTP/1.0 200 O";
    text += '\x01';
    text += "K\r\n\r\n";
    auto r = parseWhole(text, false);
    CHECK(r.status == HttpResponseParseStatus::Malformed);
}

void testNoHeaders() {
    auto r = parseWhole("HTTP/1.0 200 OK\r\n\r\n", true);
    CHECK(r.status == HttpResponseParseStatus::Complete);
    CHECK(r.body.empty());
    CHECK(!r.content_length_present);
}

void testUnknownHeadersIgnored() {
    auto r = parseWhole("HTTP/1.0 200 OK\r\nX-Custom: whatever\r\nContent-Length: 2\r\n\r\nhi", false);
    CHECK(r.status == HttpResponseParseStatus::Complete);
    CHECK(r.body == toBytes("hi"));
}

void testLowercaseContentLength() {
    auto r = parseWhole("HTTP/1.0 200 OK\r\ncontent-length: 2\r\n\r\nhi", false);
    CHECK(r.status == HttpResponseParseStatus::Complete);
    CHECK(r.content_length_present);
}

void testEmptyUnknownHeaderValue() {
    auto r = parseWhole("HTTP/1.0 200 OK\r\nX-Empty:\r\nContent-Length: 0\r\n\r\n", false);
    CHECK(r.status == HttpResponseParseStatus::Complete);
}

void testMissingColon() {
    auto r = parseWhole("HTTP/1.0 200 OK\r\nBroken Header\r\n\r\n", false);
    CHECK(r.status == HttpResponseParseStatus::Malformed);
}

void testInvalidFieldName() {
    auto r = parseWhole("HTTP/1.0 200 OK\r\nBad Name: v\r\n\r\n", false);
    CHECK(r.status == HttpResponseParseStatus::Malformed);
}

void testFoldedHeaderRejected() {
    auto r = parseWhole("HTTP/1.0 200 OK\r\nX-A: 1\r\n continuation\r\n\r\n", false);
    CHECK(r.status == HttpResponseParseStatus::Malformed);
}

void testNulRejected() {
    std::string text = "HTTP/1.0 200 OK\r\nContent-Length: 1\r\n\r\n";
    text += '\0';
    auto r = parseHttpResponse(toBytes(text), false);
    CHECK(r.status == HttpResponseParseStatus::Complete); // NUL is a valid body byte
    // But a NUL inside the header block itself must be rejected.
    std::string bad_head = "HTTP/1.0 200 OK\r\nX-A:";
    bad_head += '\0';
    bad_head += "\r\n\r\n";
    auto r2 = parseHttpResponse(toBytes(bad_head), false);
    CHECK(r2.status == HttpResponseParseStatus::Malformed);
}

void testOversizedStatusLine() {
    std::string line = "HTTP/1.0 200 ";
    line.append(kMaxHttpResponseStatusLineLength, 'a');
    line += "\r\n\r\n";
    auto r = parseWhole(line, false);
    CHECK(r.status == HttpResponseParseStatus::TooLarge);
}

void testStatusLineExactlyAtLimit() {
    // Build a status line whose length, including CRLF, is exactly the
    // limit, followed by a complete zero-length-body response.
    std::string reason(kMaxHttpResponseStatusLineLength - std::string("HTTP/1.0 200 \r\n").size(),
                        'a');
    std::string text = "HTTP/1.0 200 " + reason + "\r\nContent-Length: 0\r\n\r\n";
    CHECK(text.find("\r\n") + 2 == kMaxHttpResponseStatusLineLength);
    auto r = parseWhole(text, false);
    CHECK(r.status == HttpResponseParseStatus::Complete);
}

void testOversizedHeaderBlock() {
    std::string text = "HTTP/1.0 200 OK\r\n";
    while (text.size() < kMaxHttpResponseHeaderBlockLength) {
        text += "X-Pad: aaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\r\n";
    }
    text += "\r\n";
    auto r = parseWhole(text, false);
    CHECK(r.status == HttpResponseParseStatus::TooLarge);
}

// --- Section 24: Content-Length --------------------------------------

void testContentLengthZero() {
    auto r = parseWhole("HTTP/1.0 200 OK\r\nContent-Length: 0\r\n\r\n", false);
    CHECK(r.status == HttpResponseParseStatus::Complete);
    CHECK(r.body.empty());
}

void testContentLengthOne() {
    auto r = parseWhole("HTTP/1.0 200 OK\r\nContent-Length: 1\r\n\r\nx", false);
    CHECK(r.status == HttpResponseParseStatus::Complete);
    CHECK(r.body == toBytes("x"));
}

void testContentLengthBinaryBody() {
    std::string head = "HTTP/1.0 200 OK\r\nContent-Length: 6\r\n\r\n";
    std::vector<std::byte> buffer = toBytes(head);
    for (std::uint8_t b : kBinaryBytes) {
        buffer.push_back(static_cast<std::byte>(b));
    }
    auto r = parseHttpResponse(buffer, false);
    CHECK(r.status == HttpResponseParseStatus::Complete);
    CHECK(r.body.size() == 6);
    std::vector<std::byte> expected;
    for (std::uint8_t b : kBinaryBytes) {
        expected.push_back(static_cast<std::byte>(b));
    }
    CHECK(r.body == expected);
}

void testContentLengthExactlyMax() {
    std::string body(kMaxHttpResponseBodyLength, 'z');
    std::string head =
        "HTTP/1.0 200 OK\r\nContent-Length: " + std::to_string(body.size()) + "\r\n\r\n";
    std::vector<std::byte> buffer = toBytes(head);
    auto body_bytes = toBytes(body);
    buffer.insert(buffer.end(), body_bytes.begin(), body_bytes.end());
    auto r = parseHttpResponse(buffer, false);
    CHECK(r.status == HttpResponseParseStatus::Complete);
    CHECK(r.body.size() == kMaxHttpResponseBodyLength);
}

void testContentLengthOneOverMax() {
    auto r = parseWhole("HTTP/1.0 200 OK\r\nContent-Length: " +
                             std::to_string(kMaxHttpResponseBodyLength + 1) + "\r\n\r\n",
                         false);
    CHECK(r.status == HttpResponseParseStatus::TooLarge);
}

void testContentLengthShorterThanDeclaredPlusFin() {
    auto r = parseWhole("HTTP/1.0 200 OK\r\nContent-Length: 5\r\n\r\nhi", true);
    CHECK(r.status == HttpResponseParseStatus::Truncated);
}

void testContentLengthShorterNoFinYetIncomplete() {
    auto r = parseWhole("HTTP/1.0 200 OK\r\nContent-Length: 5\r\n\r\nhi", false);
    CHECK(r.status == HttpResponseParseStatus::Incomplete);
}

void testContentLengthLongerThanDeclared() {
    auto r = parseWhole("HTTP/1.0 200 OK\r\nContent-Length: 2\r\n\r\nhello", false);
    CHECK(r.status == HttpResponseParseStatus::Malformed);
}

void testContentLengthDuplicateHeader() {
    auto r = parseWhole(
        "HTTP/1.0 200 OK\r\nContent-Length: 2\r\nContent-Length: 2\r\n\r\nhi", false);
    CHECK(r.status == HttpResponseParseStatus::Malformed);
}

void testContentLengthLeadingZeroes() {
    auto r = parseWhole("HTTP/1.0 200 OK\r\nContent-Length: 002\r\n\r\nhi", false);
    CHECK(r.status == HttpResponseParseStatus::Complete);
    CHECK(r.body == toBytes("hi"));
}

void testContentLengthNonDecimal() {
    auto r = parseWhole("HTTP/1.0 200 OK\r\nContent-Length: 0x2\r\n\r\n", false);
    CHECK(r.status == HttpResponseParseStatus::Malformed);
}

void testContentLengthNegative() {
    auto r = parseWhole("HTTP/1.0 200 OK\r\nContent-Length: -1\r\n\r\n", false);
    CHECK(r.status == HttpResponseParseStatus::Malformed);
}

void testContentLengthPlusSign() {
    auto r = parseWhole("HTTP/1.0 200 OK\r\nContent-Length: +1\r\n\r\n", false);
    CHECK(r.status == HttpResponseParseStatus::Malformed);
}

void testContentLengthOverflow() {
    auto r = parseWhole("HTTP/1.0 200 OK\r\nContent-Length: 99999999999999999999999\r\n\r\n", false);
    CHECK(r.status == HttpResponseParseStatus::TooLarge);
}

void testContentLengthEmptyValue() {
    auto r = parseWhole("HTTP/1.0 200 OK\r\nContent-Length:\r\n\r\n", false);
    CHECK(r.status == HttpResponseParseStatus::Malformed);
}

void testContentLengthCommaSeparated() {
    auto r = parseWhole("HTTP/1.0 200 OK\r\nContent-Length: 1,1\r\n\r\n", false);
    CHECK(r.status == HttpResponseParseStatus::Malformed);
}

void testContentLengthWithTransferEncoding() {
    auto r = parseWhole(
        "HTTP/1.0 200 OK\r\nContent-Length: 2\r\nTransfer-Encoding: chunked\r\n\r\nhi", false);
    CHECK(r.status == HttpResponseParseStatus::UnsupportedTransferEncoding);
}

// --- Section 25: close-delimited body ---------------------------------

void testCloseDelimitedEmptyBody() {
    auto r = parseWhole("HTTP/1.0 200 OK\r\n\r\n", true);
    CHECK(r.status == HttpResponseParseStatus::Complete);
    CHECK(r.body.empty());
    CHECK(!r.content_length_present);
}

void testCloseDelimitedOneSegment() {
    auto r = parseWhole("HTTP/1.0 200 OK\r\n\r\nhello world", true);
    CHECK(r.status == HttpResponseParseStatus::Complete);
    CHECK(r.body == toBytes("hello world"));
}

void testCloseDelimitedIncompleteBeforeFin() {
    auto r = parseWhole("HTTP/1.0 200 OK\r\n\r\nhello world", false);
    CHECK(r.status == HttpResponseParseStatus::Incomplete);
}

void testCloseDelimitedBinaryBody() {
    std::string head = "HTTP/1.0 200 OK\r\n\r\n";
    std::vector<std::byte> buffer = toBytes(head);
    for (std::uint8_t b : kBinaryBytes) {
        buffer.push_back(static_cast<std::byte>(b));
    }
    auto r = parseHttpResponse(buffer, true);
    CHECK(r.status == HttpResponseParseStatus::Complete);
    CHECK(r.body.size() == 6);
}

// --- Section 30: server/client policy separation (parser-level) --------

void testTransferEncodingUnsupportedEvenWithoutContentLength() {
    auto r = parseWhole("HTTP/1.0 200 OK\r\nTransfer-Encoding: gzip\r\n\r\nbody", true);
    CHECK(r.status == HttpResponseParseStatus::UnsupportedTransferEncoding);
}

// --- Section 23: split-boundary parsing ---------------------------------

// One hardcoded response vector (hand-written, not derived from any
// serializer) with a binary body, fed at every possible split boundary.
// Every valid split must reach the same complete result.
void testSplitBoundaries() {
    std::string head = "HTTP/1.0 200 OK\r\nContent-Length: 6\r\n\r\n";
    std::vector<std::byte> full = toBytes(head);
    for (std::uint8_t b : kBinaryBytes) {
        full.push_back(static_cast<std::byte>(b));
    }

    // All at once.
    {
        auto r = parseHttpResponse(full, false);
        CHECK(r.status == HttpResponseParseStatus::Complete);
        CHECK(r.body.size() == 6);
    }

    // One byte at a time: accumulate a growing prefix, re-parsing (mirrors
    // how main.cpp re-parses the whole buffer-so-far on each TCP delivery).
    for (std::size_t i = 1; i <= full.size(); ++i) {
        std::span<const std::byte> prefix(full.data(), i);
        auto r = parseHttpResponse(prefix, false);
        if (i < full.size()) {
            CHECK(r.status == HttpResponseParseStatus::Incomplete);
        } else {
            CHECK(r.status == HttpResponseParseStatus::Complete);
            CHECK(r.body.size() == 6);
        }
    }

    // Split at every single boundary into exactly two pieces, delivered as
    // two parseHttpResponse calls against the concatenated buffer-so-far
    // (the only sequence main.cpp ever actually re-parses).
    for (std::size_t cut = 1; cut < full.size(); ++cut) {
        std::span<const std::byte> first_part(full.data(), cut);
        auto first_result = parseHttpResponse(first_part, false);
        CHECK(first_result.status == HttpResponseParseStatus::Incomplete);

        auto second_result = parseHttpResponse(full, false);
        CHECK(second_result.status == HttpResponseParseStatus::Complete);
        CHECK(second_result.body.size() == 6);
        std::vector<std::byte> expected;
        for (std::uint8_t b : kBinaryBytes) {
            expected.push_back(static_cast<std::byte>(b));
        }
        CHECK(second_result.body == expected);
    }
}

} // namespace

int main() {
    testExactRequestRoot();
    testExactRequestHealth();
    testExactRequestNonDefaultPort();
    testRequestRejectsEmptyTarget();
    testRequestRejectsMissingLeadingSlash();
    testRequestRejectsSpace();
    testRequestRejectsCrInjection();
    testRequestRejectsLfOnly();

    testStatus200();
    testStatus204();
    testStatus301();
    testStatus404();
    testStatus500();
    testHttp11Rejected();
    test1xxRejected();
    testMalformedStatusCode();
    testMissingReasonSeparator();
    testBareLfNeverCompletes();
    testInvalidControlByteInReason();
    testNoHeaders();
    testUnknownHeadersIgnored();
    testLowercaseContentLength();
    testEmptyUnknownHeaderValue();
    testMissingColon();
    testInvalidFieldName();
    testFoldedHeaderRejected();
    testNulRejected();
    testOversizedStatusLine();
    testStatusLineExactlyAtLimit();
    testOversizedHeaderBlock();

    testContentLengthZero();
    testContentLengthOne();
    testContentLengthBinaryBody();
    testContentLengthExactlyMax();
    testContentLengthOneOverMax();
    testContentLengthShorterThanDeclaredPlusFin();
    testContentLengthShorterNoFinYetIncomplete();
    testContentLengthLongerThanDeclared();
    testContentLengthDuplicateHeader();
    testContentLengthLeadingZeroes();
    testContentLengthNonDecimal();
    testContentLengthNegative();
    testContentLengthPlusSign();
    testContentLengthOverflow();
    testContentLengthEmptyValue();
    testContentLengthCommaSeparated();
    testContentLengthWithTransferEncoding();

    testCloseDelimitedEmptyBody();
    testCloseDelimitedOneSegment();
    testCloseDelimitedIncompleteBeforeFin();
    testCloseDelimitedBinaryBody();

    testTransferEncodingUnsupportedEvenWithoutContentLength();

    testSplitBoundaries();

    return wirestack::test::failureCount() == 0 ? 0 : 1;
}
