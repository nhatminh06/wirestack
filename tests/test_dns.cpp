// Deterministic unit tests for DNS A-record query serialization and
// response parsing -- independent of UDP/IPv4/TAP. Two byte-exact vectors
// (Section 10 and Section 14 of the milestone spec) are verified against
// hand-computed bytes, not against anything Wirestack itself produced.

#include "wirestack/dns.hpp"

#include "test_util.hpp"

#include <string>
#include <vector>

using namespace wirestack;

namespace {

std::vector<std::byte> toBytes(std::initializer_list<int> values) {
    std::vector<std::byte> out;
    out.reserve(values.size());
    for (int v : values) {
        out.push_back(static_cast<std::byte>(static_cast<unsigned char>(v)));
    }
    return out;
}

// --- hostname validation ---------------------------------------------------

void testHostnameNormalizesCase() {
    auto r = normalizeHostname("Example.TEST");
    CHECK(r.normalized.has_value());
    if (r.normalized) CHECK(*r.normalized == "example.test");
}

void testHostnameSingleLabel() {
    auto r = normalizeHostname("localhost");
    CHECK(r.normalized.has_value());
}

void testHostnameEmpty() {
    auto r = normalizeHostname("");
    CHECK(!r.normalized.has_value());
    CHECK(r.error == HostnameError::Empty);
}

void testHostnameEmptyLabel() {
    auto r = normalizeHostname("example..test");
    CHECK(!r.normalized.has_value());
    CHECK(r.error == HostnameError::EmptyLabel);
}

void testHostnameTrailingDotIsEmptyLabel() {
    auto r = normalizeHostname("example.test.");
    CHECK(!r.normalized.has_value());
    CHECK(r.error == HostnameError::EmptyLabel);
}

void testHostnameLabel63Accepted() {
    std::string label(63, 'a');
    auto r = normalizeHostname(label + ".test");
    CHECK(r.normalized.has_value());
}

void testHostnameLabel64Rejected() {
    std::string label(64, 'a');
    auto r = normalizeHostname(label + ".test");
    CHECK(!r.normalized.has_value());
    CHECK(r.error == HostnameError::LabelTooLong);
}

void testHostnameLeadingHyphenRejected() {
    auto r = normalizeHostname("-example.test");
    CHECK(!r.normalized.has_value());
    CHECK(r.error == HostnameError::LeadingOrTrailingHyphen);
}

void testHostnameTrailingHyphenRejected() {
    auto r = normalizeHostname("example-.test");
    CHECK(!r.normalized.has_value());
    CHECK(r.error == HostnameError::LeadingOrTrailingHyphen);
}

void testHostnameOver253Rejected() {
    std::string label(63, 'a');
    std::string hostname = label + "." + label + "." + label + "." + std::string(61, 'b');
    CHECK(hostname.size() == 253); // baseline: exactly at the limit is accepted
    auto ok = normalizeHostname(hostname);
    CHECK(ok.normalized.has_value());
    hostname += "x";
    auto r = normalizeHostname(hostname);
    CHECK(!r.normalized.has_value());
    CHECK(r.error == HostnameError::TooLong);
}

void testHostnameControlByteRejected() {
    std::string hostname = "exa";
    hostname += '\x01';
    hostname += "mple.test";
    auto r = normalizeHostname(hostname);
    CHECK(!r.normalized.has_value());
    CHECK(r.error == HostnameError::InvalidChar);
}

void testHostnameUnderscoreRejected() {
    auto r = normalizeHostname("exa_mple.test");
    CHECK(!r.normalized.has_value());
    CHECK(r.error == HostnameError::InvalidChar);
}

// --- Section 10: exact independent query vector ----------------------------

void testExactQueryVector() {
    DnsQuery query;
    query.transaction_id = 0x1234;
    query.hostname = "example.test";
    auto bytes = serializeDnsQuery(query);
    CHECK(bytes.has_value());
    if (!bytes) return;

    std::vector<std::byte> expected = toBytes({
        0x12, 0x34, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x07, 0x65, 0x78, 0x61, 0x6d, 0x70, 0x6c, 0x65,
        0x04, 0x74, 0x65, 0x73, 0x74,
        0x00,
        0x00, 0x01,
        0x00, 0x01,
    });
    CHECK(*bytes == expected);
}

void testQueryRejectsUnnormalizedHostname() {
    DnsQuery query;
    query.transaction_id = 1;
    query.hostname = "Example.TEST"; // caller must pre-normalize
    CHECK(!serializeDnsQuery(query).has_value());
}

void testQueryMultiLabel() {
    DnsQuery query;
    query.transaction_id = 7;
    query.hostname = "a.b.c.test";
    auto bytes = serializeDnsQuery(query);
    CHECK(bytes.has_value());
}

// --- Section 14: exact independent response vector -------------------------

std::vector<std::byte> exampleTestResponse() {
    return toBytes({
        0x12, 0x34, 0x81, 0x80, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00,
        0x07, 0x65, 0x78, 0x61, 0x6d, 0x70, 0x6c, 0x65,
        0x04, 0x74, 0x65, 0x73, 0x74,
        0x00,
        0x00, 0x01,
        0x00, 0x01,
        0xc0, 0x0c,
        0x00, 0x01,
        0x00, 0x01,
        0x00, 0x00, 0x00, 0x3c,
        0x00, 0x04,
        0x0a, 0x00, 0x00, 0x01,
    });
}

void testExactResponseVectorResolves() {
    auto bytes = exampleTestResponse();
    auto result = parseDnsResponse(bytes, 0x1234, "example.test");
    CHECK(result.outcome == DnsResponseOutcome::Resolved);
    CHECK(result.address.has_value());
    if (result.address) CHECK(*result.address == *Ipv4Address::parse("10.0.0.1"));
}

void testResponseUncompressedOwnerName() {
    // Same answer, but with the owner name spelled out literally instead
    // of a compression pointer.
    std::vector<std::byte> bytes = toBytes({
        0x12, 0x34, 0x81, 0x80, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00,
        0x07, 0x65, 0x78, 0x61, 0x6d, 0x70, 0x6c, 0x65,
        0x04, 0x74, 0x65, 0x73, 0x74,
        0x00,
        0x00, 0x01,
        0x00, 0x01,
        // answer: literal owner name, not a pointer
        0x07, 0x65, 0x78, 0x61, 0x6d, 0x70, 0x6c, 0x65,
        0x04, 0x74, 0x65, 0x73, 0x74,
        0x00,
        0x00, 0x01,
        0x00, 0x01,
        0x00, 0x00, 0x00, 0x3c,
        0x00, 0x04,
        0x0a, 0x00, 0x00, 0x01,
    });
    auto result = parseDnsResponse(bytes, 0x1234, "example.test");
    CHECK(result.outcome == DnsResponseOutcome::Resolved);
    CHECK(*result.address == *Ipv4Address::parse("10.0.0.1"));
}

void testResponseLiteralPrefixThenPointer() {
    // Owner name: literal "www" label followed by a pointer back to the
    // question's "example.test" (offset 12).
    std::vector<std::byte> bytes = toBytes({
        0x12, 0x34, 0x81, 0x80, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00,
        0x07, 0x65, 0x78, 0x61, 0x6d, 0x70, 0x6c, 0x65,
        0x04, 0x74, 0x65, 0x73, 0x74,
        0x00,
        0x00, 0x01,
        0x00, 0x01,
        0x03, 'w', 'w', 'w', 0xc0, 0x0c,
        0x00, 0x01,
        0x00, 0x01,
        0x00, 0x00, 0x00, 0x3c,
        0x00, 0x04,
        0x0a, 0x00, 0x00, 0x01,
    });
    // Owner is www.example.test, which does not match the queried
    // hostname -- correctly ignored (see A-record selection: owner name
    // must equal the queried hostname).
    auto result = parseDnsResponse(bytes, 0x1234, "example.test");
    CHECK(result.outcome == DnsResponseOutcome::NoAnswer);
}

void testMultipleAnswersFirstMatchSelected() {
    std::vector<std::byte> bytes = toBytes({
        0x12, 0x34, 0x81, 0x80, 0x00, 0x01, 0x00, 0x02, 0x00, 0x00, 0x00, 0x00,
        0x07, 0x65, 0x78, 0x61, 0x6d, 0x70, 0x6c, 0x65,
        0x04, 0x74, 0x65, 0x73, 0x74,
        0x00,
        0x00, 0x01,
        0x00, 0x01,
        0xc0, 0x0c, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x3c, 0x00, 0x04, 0x0a, 0x00, 0x00, 0x01,
        0xc0, 0x0c, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x3c, 0x00, 0x04, 0x0a, 0x00, 0x00, 0x02,
    });
    auto result = parseDnsResponse(bytes, 0x1234, "example.test");
    CHECK(result.outcome == DnsResponseOutcome::Resolved);
    CHECK(*result.address == *Ipv4Address::parse("10.0.0.1"));
}

void testUnrelatedAIgnored() {
    // A single answer whose owner name is unrelated -- must not resolve.
    std::vector<std::byte> bytes = toBytes({
        0x12, 0x34, 0x81, 0x80, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00,
        0x07, 0x65, 0x78, 0x61, 0x6d, 0x70, 0x6c, 0x65,
        0x04, 0x74, 0x65, 0x73, 0x74,
        0x00,
        0x00, 0x01,
        0x00, 0x01,
        0x05, 'o', 't', 'h', 'e', 'r', 0x00,
        0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x3c, 0x00, 0x04, 0x0a, 0x00, 0x00, 0x09,
    });
    auto result = parseDnsResponse(bytes, 0x1234, "example.test");
    CHECK(result.outcome == DnsResponseOutcome::NoAnswer);
}

void testUnknownRecordTypeSkipped() {
    // An unknown-type (99) record of arbitrary length precedes a matching
    // A record; both must be parsed correctly and the A record selected.
    std::vector<std::byte> bytes = toBytes({
        0x12, 0x34, 0x81, 0x80, 0x00, 0x01, 0x00, 0x02, 0x00, 0x00, 0x00, 0x00,
        0x07, 0x65, 0x78, 0x61, 0x6d, 0x70, 0x6c, 0x65,
        0x04, 0x74, 0x65, 0x73, 0x74,
        0x00,
        0x00, 0x01,
        0x00, 0x01,
        0xc0, 0x0c, 0x00, 0x63, 0x00, 0x01, 0x00, 0x00, 0x00, 0x3c, 0x00, 0x03, 0xaa, 0xbb, 0xcc,
        0xc0, 0x0c, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x3c, 0x00, 0x04, 0x0a, 0x00, 0x00, 0x01,
    });
    auto result = parseDnsResponse(bytes, 0x1234, "example.test");
    CHECK(result.outcome == DnsResponseOutcome::Resolved);
    CHECK(*result.address == *Ipv4Address::parse("10.0.0.1"));
}

void testCnameOnlyProducesNoAnswer() {
    // CNAME (type 5) answer only, no A record -- must not resolve, and
    // must not be treated as an address (see Section 6: no CNAME
    // following).
    std::vector<std::byte> bytes = toBytes({
        0x12, 0x34, 0x81, 0x80, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00,
        0x07, 0x65, 0x78, 0x61, 0x6d, 0x70, 0x6c, 0x65,
        0x04, 0x74, 0x65, 0x73, 0x74,
        0x00,
        0x00, 0x01,
        0x00, 0x01,
        0xc0, 0x0c, 0x00, 0x05, 0x00, 0x01, 0x00, 0x00, 0x00, 0x3c,
        0x00, 0x02, 0xc0, 0x0c,
    });
    auto result = parseDnsResponse(bytes, 0x1234, "example.test");
    CHECK(result.outcome == DnsResponseOutcome::NoAnswer);
}

void testZeroAnswers() {
    std::vector<std::byte> bytes = toBytes({
        0x12, 0x34, 0x81, 0x80, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x07, 0x65, 0x78, 0x61, 0x6d, 0x70, 0x6c, 0x65,
        0x04, 0x74, 0x65, 0x73, 0x74,
        0x00,
        0x00, 0x01,
        0x00, 0x01,
    });
    auto result = parseDnsResponse(bytes, 0x1234, "example.test");
    CHECK(result.outcome == DnsResponseOutcome::NoAnswer);
}

std::vector<std::byte> questionOnlyWithRcode(std::uint8_t rcode) {
    std::vector<std::byte> bytes = toBytes({
        0x12, 0x34, 0x81, static_cast<int>(0x80 | rcode), 0x00, 0x01, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00,
        0x07, 0x65, 0x78, 0x61, 0x6d, 0x70, 0x6c, 0x65,
        0x04, 0x74, 0x65, 0x73, 0x74,
        0x00,
        0x00, 0x01,
        0x00, 0x01,
    });
    return bytes;
}

void testNxDomain() {
    auto bytes = questionOnlyWithRcode(3);
    auto result = parseDnsResponse(bytes, 0x1234, "example.test");
    CHECK(result.outcome == DnsResponseOutcome::NxDomain);
}

void testServerFailure() {
    auto bytes = questionOnlyWithRcode(2);
    auto result = parseDnsResponse(bytes, 0x1234, "example.test");
    CHECK(result.outcome == DnsResponseOutcome::ServerFailure);
}

void testRefused() {
    auto bytes = questionOnlyWithRcode(5);
    auto result = parseDnsResponse(bytes, 0x1234, "example.test");
    CHECK(result.outcome == DnsResponseOutcome::Refused);
}

void testWrongTransaction() {
    auto bytes = exampleTestResponse();
    auto result = parseDnsResponse(bytes, 0xffff, "example.test");
    CHECK(result.outcome == DnsResponseOutcome::WrongTransaction);
}

void testWrongQuestionHostname() {
    auto bytes = exampleTestResponse();
    auto result = parseDnsResponse(bytes, 0x1234, "other.test");
    CHECK(result.outcome == DnsResponseOutcome::WrongQuestion);
}

void testWrongQtype() {
    std::vector<std::byte> bytes = toBytes({
        0x12, 0x34, 0x81, 0x80, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x07, 0x65, 0x78, 0x61, 0x6d, 0x70, 0x6c, 0x65,
        0x04, 0x74, 0x65, 0x73, 0x74,
        0x00,
        0x00, 0x1c, // AAAA, not A
        0x00, 0x01,
    });
    auto result = parseDnsResponse(bytes, 0x1234, "example.test");
    CHECK(result.outcome == DnsResponseOutcome::WrongQuestion);
}

void testWrongQclass() {
    std::vector<std::byte> bytes = toBytes({
        0x12, 0x34, 0x81, 0x80, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x07, 0x65, 0x78, 0x61, 0x6d, 0x70, 0x6c, 0x65,
        0x04, 0x74, 0x65, 0x73, 0x74,
        0x00,
        0x00, 0x01,
        0x00, 0x03, // CH, not IN
    });
    auto result = parseDnsResponse(bytes, 0x1234, "example.test");
    CHECK(result.outcome == DnsResponseOutcome::WrongQuestion);
}

void testRequestPresentedAsResponseRejected() {
    // QR=0 -- this is a query, not a response.
    std::vector<std::byte> bytes = toBytes({
        0x12, 0x34, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x07, 0x65, 0x78, 0x61, 0x6d, 0x70, 0x6c, 0x65,
        0x04, 0x74, 0x65, 0x73, 0x74,
        0x00,
        0x00, 0x01,
        0x00, 0x01,
    });
    auto result = parseDnsResponse(bytes, 0x1234, "example.test");
    CHECK(result.outcome == DnsResponseOutcome::Malformed);
}

void testTcFlagTruncated() {
    std::vector<std::byte> bytes = exampleTestResponse();
    bytes[2] = static_cast<std::byte>(static_cast<unsigned char>(bytes[2]) | 0x02); // set TC
    auto result = parseDnsResponse(bytes, 0x1234, "example.test");
    CHECK(result.outcome == DnsResponseOutcome::Truncated);
}

void testInvalidOpcodeRejected() {
    std::vector<std::byte> bytes = exampleTestResponse();
    bytes[2] = static_cast<std::byte>(static_cast<unsigned char>(bytes[2]) | 0x08); // opcode=1
    auto result = parseDnsResponse(bytes, 0x1234, "example.test");
    CHECK(result.outcome == DnsResponseOutcome::Malformed);
}

// --- Malformed boundaries ----------------------------------------------

void testTooShortHeader() {
    for (std::size_t len = 0; len <= 11; ++len) {
        std::vector<std::byte> bytes(len, std::byte{0});
        auto result = parseDnsResponse(bytes, 0x1234, "example.test");
        CHECK(result.outcome == DnsResponseOutcome::Malformed);
    }
}

void testOversizedPacketRejected() {
    std::vector<std::byte> bytes(513, std::byte{0});
    auto result = parseDnsResponse(bytes, 0x1234, "example.test");
    CHECK(result.outcome == DnsResponseOutcome::Malformed);
}

void testTruncatedLabelRejected() {
    // Declares a 7-byte label but the packet ends after 3 bytes of it.
    std::vector<std::byte> bytes = toBytes({
        0x12, 0x34, 0x81, 0x80, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x07, 0x65, 0x78, 0x61,
    });
    auto result = parseDnsResponse(bytes, 0x1234, "example.test");
    CHECK(result.outcome == DnsResponseOutcome::Malformed);
}

void testLabelLongerThan63Rejected() {
    // 0xC0 top bits already mean "pointer"; a reserved single-label form
    // (top bits 01) is the only way to express ">63" structurally.
    std::vector<std::byte> bytes = toBytes({
        0x12, 0x34, 0x81, 0x80, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x40, 0x00, 0x00, 0x01, 0x00, 0x01,
    });
    auto result = parseDnsResponse(bytes, 0x1234, "example.test");
    CHECK(result.outcome == DnsResponseOutcome::Malformed);
}

void testIncompletePointerRejected() {
    std::vector<std::byte> bytes = toBytes({
        0x12, 0x34, 0x81, 0x80, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0xc0,
    });
    auto result = parseDnsResponse(bytes, 0x1234, "example.test");
    CHECK(result.outcome == DnsResponseOutcome::Malformed);
}

void testPointerOutOfRangeRejected() {
    std::vector<std::byte> bytes = toBytes({
        0x12, 0x34, 0x81, 0x80, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0xc0, 0xff, // points far past the packet
        0x00, 0x01, 0x00, 0x01,
    });
    auto result = parseDnsResponse(bytes, 0x1234, "example.test");
    CHECK(result.outcome == DnsResponseOutcome::Malformed);
}

void testSelfPointerRejected() {
    // The question name at offset 12 points to itself.
    std::vector<std::byte> bytes = toBytes({
        0x12, 0x34, 0x81, 0x80, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0xc0, 0x0c,
        0x00, 0x01, 0x00, 0x01,
    });
    auto result = parseDnsResponse(bytes, 0x1234, "example.test");
    CHECK(result.outcome == DnsResponseOutcome::Malformed);
}

void testPointerLoopRejected() {
    // Two pointers at offsets 12 and 14 that reference each other.
    std::vector<std::byte> bytes = toBytes({
        0x12, 0x34, 0x81, 0x80, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0xc0, 0x0e, // offset 12: pointer -> 14
        0xc0, 0x0c, // offset 14: pointer -> 12
        0x00, 0x01, 0x00, 0x01,
    });
    auto result = parseDnsResponse(bytes, 0x1234, "example.test");
    CHECK(result.outcome == DnsResponseOutcome::Malformed);
}

void pushU16(std::vector<std::byte>& bytes, std::uint16_t v) {
    bytes.push_back(static_cast<std::byte>((v >> 8) & 0xFF));
    bytes.push_back(static_cast<std::byte>(v & 0xFF));
}

void pushPointer(std::vector<std::byte>& bytes, std::size_t target) {
    pushU16(bytes, static_cast<std::uint16_t>(0xC000 | (target & 0x3FFF)));
}

// Builds a response with a genuine strictly-backward compression-pointer
// chain of exactly `total_hops` hops, terminating in the real labels
// "example.test", used as the owner name of the actual A answer.
//
// Layout: header, an ordinary uncompressed question, then an EARLIER
// "unknown" resource record (TYPE=16/TXT, ignored by A-selection) whose
// opaque RDATA holds the real label bytes followed by a chain of
// (total_hops - 1) two-byte pointers, each one referencing the
// immediately preceding, strictly earlier chain element (or the labels
// themselves for the first one) -- never a later resource-record parser
// interprets this RDATA as anything but opaque bytes, so it can safely
// carry pointer bytes without those bytes ever being independently
// decoded as a name in their own record's owner-name position. The
// LATER record -- the real answer -- has an owner name that is a single
// pointer aimed at the last (highest-offset) chain element, making the
// full traversal from that owner name exactly `total_hops` pointer
// hops: the owner's own pointer, plus each of the (total_hops - 1)
// chain elements, before finally reading the real labels.
std::vector<std::byte> buildPointerChainResponse(int total_hops) {
    CHECK(total_hops >= 1);
    int chain_count = total_hops - 1; // pointers stored inside the RDATA

    std::vector<std::byte> bytes = toBytes({
        0x12, 0x34, 0x81, 0x80, 0x00, 0x01, 0x00, 0x02, 0x00, 0x00, 0x00, 0x00,
    });
    // Question at offset 12: example.test A IN (18 bytes, ends at 30).
    bytes.push_back(std::byte{0x07});
    for (char c : std::string("example")) bytes.push_back(static_cast<std::byte>(c));
    bytes.push_back(std::byte{0x04});
    for (char c : std::string("test")) bytes.push_back(static_cast<std::byte>(c));
    bytes.push_back(std::byte{0x00});
    pushU16(bytes, 1); // QTYPE = A
    pushU16(bytes, 1); // QCLASS = IN
    CHECK(bytes.size() == 30);

    // Earlier record: owner = root, TYPE=16 (TXT, unrelated/ignored),
    // CLASS=IN, TTL=0, RDLENGTH=computed, RDATA = labels + chain.
    bytes.push_back(std::byte{0x00}); // owner: root
    pushU16(bytes, 16); // TYPE = TXT
    pushU16(bytes, 1); // CLASS = IN
    for (int i = 0; i < 4; ++i) bytes.push_back(std::byte{0x00}); // TTL
    std::size_t rdlength_offset = bytes.size();
    pushU16(bytes, 0); // RDLENGTH placeholder, patched below

    std::size_t rdata_offset = bytes.size();
    std::size_t labels_offset = bytes.size();
    bytes.push_back(std::byte{0x07});
    for (char c : std::string("example")) bytes.push_back(static_cast<std::byte>(c));
    bytes.push_back(std::byte{0x04});
    for (char c : std::string("test")) bytes.push_back(static_cast<std::byte>(c));
    bytes.push_back(std::byte{0x00});

    std::vector<std::size_t> chain_offsets;
    std::size_t prev_target = labels_offset;
    for (int i = 0; i < chain_count; ++i) {
        chain_offsets.push_back(bytes.size());
        pushPointer(bytes, prev_target); // strictly earlier than this entry
        prev_target = chain_offsets.back();
    }
    std::uint16_t rdlength = static_cast<std::uint16_t>(bytes.size() - rdata_offset);
    bytes[rdlength_offset] = static_cast<std::byte>((rdlength >> 8) & 0xFF);
    bytes[rdlength_offset + 1] = static_cast<std::byte>(rdlength & 0xFF);

    // Later record: the real answer. Owner name is a single pointer to
    // the last (deepest/highest-offset) chain element -- or straight to
    // the labels if there is no chain at all (total_hops == 1).
    std::size_t owner_target = chain_offsets.empty() ? labels_offset : chain_offsets.back();
    pushPointer(bytes, owner_target);
    pushU16(bytes, 1); // TYPE = A
    pushU16(bytes, 1); // CLASS = IN
    pushU16(bytes, 0); // TTL hi
    pushU16(bytes, 60); // TTL lo
    pushU16(bytes, 4); // RDLENGTH
    bytes.push_back(std::byte{10});
    bytes.push_back(std::byte{0});
    bytes.push_back(std::byte{0});
    bytes.push_back(std::byte{1});

    return bytes;
}

void testPointerChainExactlyAtHopLimitResolves() {
    auto bytes = buildPointerChainResponse(kMaxDnsPointerHops);
    auto result = parseDnsResponse(bytes, 0x1234, "example.test");
    // Exactly at the bound: traversal succeeds and the response resolves
    // normally -- the chain depth alone must not be treated as malformed.
    CHECK(result.outcome == DnsResponseOutcome::Resolved);
    CHECK(result.address.has_value());
    if (result.address) CHECK(*result.address == *Ipv4Address::parse("10.0.0.1"));
}

void testPointerChainOneOverHopLimitRejected() {
    auto bytes = buildPointerChainResponse(kMaxDnsPointerHops + 1);
    auto result = parseDnsResponse(bytes, 0x1234, "example.test");
    // One hop beyond the bound: the same otherwise-valid chain must now
    // be rejected specifically for exceeding kMaxDnsPointerHops, not for
    // any of the other malformed-input reasons this file covers
    // separately (forward pointer, self-pointer, truncation, bad
    // RDLENGTH, excessive record count, or decoded-name length).
    CHECK(result.outcome == DnsResponseOutcome::Malformed);
}

void testDecodedNameOver253Rejected() {
    // A single label chain whose total decoded length exceeds 253 bytes.
    std::vector<std::byte> bytes = toBytes({
        0x12, 0x34, 0x81, 0x80, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    });
    for (int i = 0; i < 5; ++i) {
        bytes.push_back(std::byte{63});
        for (int j = 0; j < 63; ++j) bytes.push_back(std::byte{'a'});
    }
    bytes.push_back(std::byte{0}); // terminator; total decoded ~= 5*63 + 4 dots > 253
    bytes.push_back(std::byte{0x00});
    bytes.push_back(std::byte{0x01});
    bytes.push_back(std::byte{0x00});
    bytes.push_back(std::byte{0x01});
    auto result = parseDnsResponse(bytes, 0x1234, "example.test");
    CHECK(result.outcome == DnsResponseOutcome::Malformed);
}

void testRdlengthBeyondPacketRejected() {
    std::vector<std::byte> bytes = toBytes({
        0x12, 0x34, 0x81, 0x80, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00,
        0x07, 0x65, 0x78, 0x61, 0x6d, 0x70, 0x6c, 0x65,
        0x04, 0x74, 0x65, 0x73, 0x74,
        0x00,
        0x00, 0x01,
        0x00, 0x01,
        0xc0, 0x0c, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x3c,
        0x00, 0xff, // RDLENGTH way beyond what's left
        0x0a, 0x00, 0x00, 0x01,
    });
    auto result = parseDnsResponse(bytes, 0x1234, "example.test");
    CHECK(result.outcome == DnsResponseOutcome::Malformed);
}

void testARdlengthNotFourIgnored() {
    // A structurally-valid A record with RDLENGTH=3 (not 4) must not be
    // accepted as an address.
    std::vector<std::byte> bytes = toBytes({
        0x12, 0x34, 0x81, 0x80, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00,
        0x07, 0x65, 0x78, 0x61, 0x6d, 0x70, 0x6c, 0x65,
        0x04, 0x74, 0x65, 0x73, 0x74,
        0x00,
        0x00, 0x01,
        0x00, 0x01,
        0xc0, 0x0c, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x3c,
        0x00, 0x03, 0x0a, 0x00, 0x00,
    });
    auto result = parseDnsResponse(bytes, 0x1234, "example.test");
    CHECK(result.outcome == DnsResponseOutcome::NoAnswer);
}

void testExcessiveRecordCountRejected() {
    std::vector<std::byte> bytes = toBytes({
        0x12, 0x34, 0x81, 0x80, 0x00, 0x01, 0xff, 0xff, 0x00, 0x00, 0x00, 0x00,
        0x07, 0x65, 0x78, 0x61, 0x6d, 0x70, 0x6c, 0x65,
        0x04, 0x74, 0x65, 0x73, 0x74,
        0x00,
        0x00, 0x01,
        0x00, 0x01,
    });
    auto result = parseDnsResponse(bytes, 0x1234, "example.test");
    CHECK(result.outcome == DnsResponseOutcome::Malformed);
}

void testMalformedAdditionalRecordRejected() {
    // Valid answer, but a truncated additional record afterward.
    std::vector<std::byte> bytes = exampleTestResponse();
    // Rewrite header: ARCOUNT=1, then append a truncated record.
    bytes[10] = std::byte{0x00};
    bytes[11] = std::byte{0x01};
    bytes.push_back(std::byte{0xc0});
    bytes.push_back(std::byte{0x0c});
    bytes.push_back(std::byte{0x00}); // truncated: type only partially present
    auto result = parseDnsResponse(bytes, 0x1234, "example.test");
    CHECK(result.outcome == DnsResponseOutcome::Malformed);
}

} // namespace

int main() {
    testHostnameNormalizesCase();
    testHostnameSingleLabel();
    testHostnameEmpty();
    testHostnameEmptyLabel();
    testHostnameTrailingDotIsEmptyLabel();
    testHostnameLabel63Accepted();
    testHostnameLabel64Rejected();
    testHostnameLeadingHyphenRejected();
    testHostnameTrailingHyphenRejected();
    testHostnameOver253Rejected();
    testHostnameControlByteRejected();
    testHostnameUnderscoreRejected();

    testExactQueryVector();
    testQueryRejectsUnnormalizedHostname();
    testQueryMultiLabel();

    testExactResponseVectorResolves();
    testResponseUncompressedOwnerName();
    testResponseLiteralPrefixThenPointer();
    testMultipleAnswersFirstMatchSelected();
    testUnrelatedAIgnored();
    testUnknownRecordTypeSkipped();
    testCnameOnlyProducesNoAnswer();
    testZeroAnswers();
    testNxDomain();
    testServerFailure();
    testRefused();
    testWrongTransaction();
    testWrongQuestionHostname();
    testWrongQtype();
    testWrongQclass();
    testRequestPresentedAsResponseRejected();
    testTcFlagTruncated();
    testInvalidOpcodeRejected();

    testTooShortHeader();
    testOversizedPacketRejected();
    testTruncatedLabelRejected();
    testLabelLongerThan63Rejected();
    testIncompletePointerRejected();
    testPointerOutOfRangeRejected();
    testSelfPointerRejected();
    testPointerLoopRejected();
    testPointerChainExactlyAtHopLimitResolves();
    testPointerChainOneOverHopLimitRejected();
    testDecodedNameOver253Rejected();
    testRdlengthBeyondPacketRejected();
    testARdlengthNotFourIgnored();
    testExcessiveRecordCountRejected();
    testMalformedAdditionalRecordRejected();

    return wirestack::test::failureCount() == 0 ? 0 : 1;
}
