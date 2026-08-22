// Deterministic unit tests for the runtime-option parser (--active-open /
// --http-get / --source-port / --target). No TAP device, no privileges: the
// parser is pure argv-in, RuntimeOptionsParseResult-out.

#include "wirestack/runtime_options.hpp"

#include "wirestack/ipv4_address.hpp"

#include "test_util.hpp"

#include <string>
#include <vector>

using namespace wirestack;

namespace {

// Builds argv as {"wirestack", "tap0", "10.0.0.2", "02:00:00:00:00:02",
// extra...} and calls parseRuntimeOptions on it -- mirrors exactly how
// main.cpp invokes it (extra options start at argv[4]).
RuntimeOptionsParseResult parse(const std::vector<std::string>& extra) {
    std::vector<std::string> args = {"wirestack", "tap0", "10.0.0.2", "02:00:00:00:00:02"};
    args.insert(args.end(), extra.begin(), extra.end());
    std::vector<char*> argv;
    argv.reserve(args.size());
    for (auto& a : args) argv.push_back(a.data());
    return parseRuntimeOptions(static_cast<int>(argv.size()), argv.data());
}

bool isValid(const RuntimeOptionsParseResult& r) {
    return r.options.has_value() && !r.error.has_value();
}
bool isInvalid(const RuntimeOptionsParseResult& r) {
    return !r.options.has_value() && r.error.has_value();
}

// --- valid cases ---------------------------------------------------------

void testPassiveMode() {
    auto r = parse({});
    CHECK(isValid(r));
    CHECK(r.options->mode == RuntimeMode::Passive);
}

void testActiveOpenMode() {
    auto r = parse({"--active-open", "10.0.0.1:9090", "--source-port", "49200"});
    CHECK(isValid(r));
    CHECK(r.options->mode == RuntimeMode::ActiveOpen);
    CHECK(r.options->remote_port == 9090);
    CHECK(r.options->source_port == 49200);
}

void testHttpGetMode() {
    auto r = parse(
        {"--http-get", "10.0.0.1:9090", "--source-port", "49200", "--target", "/health"});
    CHECK(isValid(r));
    CHECK(r.options->mode == RuntimeMode::HttpGet);
    CHECK(r.options->target == "/health");
}

void testHttpGetTargetRoot() {
    auto r = parse({"--http-get", "10.0.0.1:9090", "--source-port", "1", "--target", "/"});
    CHECK(isValid(r));
    CHECK(r.options->target == "/");
}

void testPortOne() {
    auto r = parse({"--active-open", "10.0.0.1:1", "--source-port", "1"});
    CHECK(isValid(r));
    CHECK(r.options->remote_port == 1);
    CHECK(r.options->source_port == 1);
}

void testPortMax() {
    auto r = parse({"--active-open", "10.0.0.1:65535", "--source-port", "65535"});
    CHECK(isValid(r));
    CHECK(r.options->remote_port == 65535);
    CHECK(r.options->source_port == 65535);
}

// --- invalid: absent vs invalid must never be confused --------------------

void testInvalidNeverLooksLikePassive() {
    auto r = parse({"--active-open", "not-an-ip:9090", "--source-port", "1"});
    CHECK(isInvalid(r));
    CHECK(!(r.options.has_value() && r.options->mode == RuntimeMode::Passive));
}

// --- invalid: missing value / missing companion ---------------------------

void testActiveOpenMissingValue() {
    auto r = parse({"--active-open"});
    CHECK(isInvalid(r));
}

void testActiveOpenMissingSourcePort() {
    auto r = parse({"--active-open", "10.0.0.1:9090"});
    CHECK(isInvalid(r));
}

void testSourcePortWithoutMode() {
    auto r = parse({"--source-port", "9090"});
    CHECK(isInvalid(r));
}

void testHttpGetMissingSourcePort() {
    auto r = parse({"--http-get", "10.0.0.1:9090", "--target", "/"});
    CHECK(isInvalid(r));
}

void testHttpGetMissingTarget() {
    auto r = parse({"--http-get", "10.0.0.1:9090", "--source-port", "1"});
    CHECK(isInvalid(r));
}

void testTargetWithoutHttpGet() {
    auto r = parse({"--active-open", "10.0.0.1:9090", "--source-port", "1", "--target", "/"});
    CHECK(isInvalid(r));
}

void testTargetAloneWithoutHttpGet() {
    auto r = parse({"--target", "/"});
    CHECK(isInvalid(r));
}

// --- invalid: mutual exclusion, either order ------------------------------

void testActiveOpenAndHttpGetTogether() {
    auto r = parse({"--active-open", "10.0.0.1:9090", "--http-get", "10.0.0.1:9091",
                     "--source-port", "1", "--target", "/"});
    CHECK(isInvalid(r));
}

void testHttpGetAndActiveOpenReversedOrder() {
    auto r = parse({"--http-get", "10.0.0.1:9091", "--active-open", "10.0.0.1:9090",
                     "--source-port", "1", "--target", "/"});
    CHECK(isInvalid(r));
}

// --- invalid: duplicated options -------------------------------------------

void testDuplicateActiveOpen() {
    auto r = parse({"--active-open", "10.0.0.1:9090", "--active-open", "10.0.0.1:9091",
                     "--source-port", "1"});
    CHECK(isInvalid(r));
}

void testDuplicateHttpGet() {
    auto r = parse({"--http-get", "10.0.0.1:9090", "--http-get", "10.0.0.1:9091", "--source-port",
                     "1", "--target", "/"});
    CHECK(isInvalid(r));
}

void testDuplicateSourcePort() {
    auto r = parse(
        {"--active-open", "10.0.0.1:9090", "--source-port", "1", "--source-port", "2"});
    CHECK(isInvalid(r));
}

void testDuplicateTarget() {
    auto r = parse({"--http-get", "10.0.0.1:9090", "--source-port", "1", "--target", "/a",
                     "--target", "/b"});
    CHECK(isInvalid(r));
}

// --- invalid: unknown option ------------------------------------------------

void testUnknownOption() {
    auto r = parse({"--bogus", "value"});
    CHECK(isInvalid(r));
}

void testUnknownOptionAmongValidOnes() {
    auto r = parse(
        {"--active-open", "10.0.0.1:9090", "--source-port", "1", "--frobnicate"});
    CHECK(isInvalid(r));
}

// --- invalid: destination syntax -------------------------------------------

void testMissingColon() {
    auto r = parse({"--active-open", "10.0.0.1", "--source-port", "1"});
    CHECK(isInvalid(r));
}

void testEmptyDestinationIp() {
    auto r = parse({"--active-open", ":9090", "--source-port", "1"});
    CHECK(isInvalid(r));
}

void testEmptyDestinationPort() {
    auto r = parse({"--active-open", "10.0.0.1:", "--source-port", "1"});
    CHECK(isInvalid(r));
}

void testMalformedIp() {
    auto r = parse({"--active-open", "10.0.0.256:9090", "--source-port", "1"});
    CHECK(isInvalid(r));
}

void testMalformedIpTooFewOctets() {
    auto r = parse({"--active-open", "10.0.0:9090", "--source-port", "1"});
    CHECK(isInvalid(r));
}

// --- invalid: port range and strict decimal syntax -------------------------

void testPortZero() {
    auto r = parse({"--active-open", "10.0.0.1:0", "--source-port", "1"});
    CHECK(isInvalid(r));
}

void testPortAboveMax() {
    auto r = parse({"--active-open", "10.0.0.1:65536", "--source-port", "1"});
    CHECK(isInvalid(r));
}

void testPortNegative() {
    auto r = parse({"--active-open", "10.0.0.1:-1", "--source-port", "1"});
    CHECK(isInvalid(r));
}

void testPortPlusPrefixed() {
    auto r = parse({"--active-open", "10.0.0.1:+9090", "--source-port", "1"});
    CHECK(isInvalid(r));
}

void testPortLeadingWhitespace() {
    auto r = parse({"--active-open", "10.0.0.1: 9090", "--source-port", "1"});
    CHECK(isInvalid(r));
}

void testPortTrailingWhitespace() {
    auto r = parse({"--active-open", "10.0.0.1:9090 ", "--source-port", "1"});
    CHECK(isInvalid(r));
}

void testPortTrailingJunk() {
    auto r = parse({"--active-open", "10.0.0.1:9090junk", "--source-port", "1"});
    CHECK(isInvalid(r));
}

void testPortLeadingJunk() {
    auto r = parse({"--active-open", "10.0.0.1:123abc", "--source-port", "1"});
    CHECK(isInvalid(r));
}

void testPortHex() {
    auto r = parse({"--active-open", "10.0.0.1:0x2382", "--source-port", "1"});
    CHECK(isInvalid(r));
}

void testSourcePortTrailingJunk() {
    auto r = parse({"--active-open", "10.0.0.1:9090", "--source-port", "9090junk"});
    CHECK(isInvalid(r));
}

void testSourcePortZero() {
    auto r = parse({"--active-open", "10.0.0.1:9090", "--source-port", "0"});
    CHECK(isInvalid(r));
}

// --- invalid: target syntax -------------------------------------------------

void testEmptyTarget() {
    auto r = parse({"--http-get", "10.0.0.1:9090", "--source-port", "1", "--target", ""});
    CHECK(isInvalid(r));
}

void testTargetMissingLeadingSlash() {
    auto r =
        parse({"--http-get", "10.0.0.1:9090", "--source-port", "1", "--target", "health"});
    CHECK(isInvalid(r));
}

void testTargetContainsSpace() {
    auto r =
        parse({"--http-get", "10.0.0.1:9090", "--source-port", "1", "--target", "/a b"});
    CHECK(isInvalid(r));
}

void testTargetContainsCr() {
    auto r = parse(
        {"--http-get", "10.0.0.1:9090", "--source-port", "1", "--target", "/a\rEvil"});
    CHECK(isInvalid(r));
}

void testTargetContainsLf() {
    auto r =
        parse({"--http-get", "10.0.0.1:9090", "--source-port", "1", "--target", "/a\nEvil"});
    CHECK(isInvalid(r));
}

// A NUL byte cannot be tested through argv here: argv entries are
// NUL-terminated C strings, so a real command line can never carry a NUL
// inside an option value in the first place. validateHttpClientTarget's
// rejection of NUL (and other control bytes) is exercised directly on a
// std::string in tests/test_http_client.cpp.

// --- DNS/hostname destination (Milestone 18) ------------------------------

void testHostnameHttpGetRequiresDnsServer() {
    auto r = parse({"--http-get", "wirestack.test:9094", "--source-port", "49300", "--target",
                     "/"});
    CHECK(isInvalid(r));
}

void testHostnameHttpGetWithDnsServerValid() {
    auto r = parse({"--http-get", "wirestack.test:9094", "--dns-server", "10.0.0.1:5353",
                     "--source-port", "49300", "--target", "/"});
    CHECK(isValid(r));
    if (!isValid(r)) return;
    CHECK(r.options->mode == RuntimeMode::HttpGet);
    CHECK(r.options->destination_is_hostname);
    CHECK(r.options->hostname == "wirestack.test");
    CHECK(r.options->remote_port == 9094);
    CHECK(r.options->dns_server_ip == *Ipv4Address::parse("10.0.0.1"));
    CHECK(r.options->dns_server_port == 5353);
}

void testHostnameNormalizedToLowercase() {
    auto r = parse({"--http-get", "Wirestack.TEST:9094", "--dns-server", "10.0.0.1:5353",
                     "--source-port", "49300", "--target", "/"});
    CHECK(isValid(r));
    if (isValid(r)) CHECK(r.options->hostname == "wirestack.test");
}

void testLiteralIpv4WithDnsServerRejected() {
    auto r = parse({"--http-get", "10.0.0.1:9094", "--dns-server", "10.0.0.1:5353",
                     "--source-port", "49300", "--target", "/"});
    CHECK(isInvalid(r));
}

void testDnsServerInPassiveModeRejected() {
    auto r = parse({"--dns-server", "10.0.0.1:5353"});
    CHECK(isInvalid(r));
}

void testDnsServerWithActiveOpenRejected() {
    auto r = parse({"--active-open", "10.0.0.1:9090", "--dns-server", "10.0.0.1:5353",
                     "--source-port", "49200"});
    CHECK(isInvalid(r));
}

void testDuplicateDnsServerRejected() {
    auto r = parse({"--http-get", "wirestack.test:9094", "--dns-server", "10.0.0.1:5353",
                     "--dns-server", "10.0.0.1:5353", "--source-port", "49300", "--target", "/"});
    CHECK(isInvalid(r));
}

void testDnsServerMissingValueRejected() {
    auto r = parse({"--http-get", "wirestack.test:9094", "--dns-server"});
    CHECK(isInvalid(r));
}

void testMalformedDnsServerIpRejected() {
    auto r = parse({"--http-get", "wirestack.test:9094", "--dns-server", "999.0.0.1:5353",
                     "--source-port", "49300", "--target", "/"});
    CHECK(isInvalid(r));
}

void testMalformedDnsServerPortRejected() {
    auto r = parse({"--http-get", "wirestack.test:9094", "--dns-server", "10.0.0.1:0",
                     "--source-port", "49300", "--target", "/"});
    CHECK(isInvalid(r));
}

void testInvalidHostnameDestinationRejected() {
    auto r = parse({"--http-get", "-bad.test:9094", "--dns-server", "10.0.0.1:5353",
                     "--source-port", "49300", "--target", "/"});
    CHECK(isInvalid(r));
}

void testActiveOpenHostnameDestinationRejected() {
    // --active-open never accepts a hostname destination, DNS server or
    // not -- only --http-get supports DNS resolution (see docs/dns.md).
    auto r = parse({"--active-open", "wirestack.test:9090", "--source-port", "49200"});
    CHECK(isInvalid(r));
}

// Invalid DNS input must exit before the TAP device is opened and must
// never fall back to passive mode -- this is guaranteed structurally by
// RuntimeOptionsParseResult's contract (see runtime_options.hpp): every
// isInvalid() case above sets `error` and leaves `options` unset, which
// main.cpp checks before calling TapDevice::open at all.

} // namespace

int main() {
    testPassiveMode();
    testActiveOpenMode();
    testHttpGetMode();
    testHttpGetTargetRoot();
    testPortOne();
    testPortMax();

    testInvalidNeverLooksLikePassive();

    testActiveOpenMissingValue();
    testActiveOpenMissingSourcePort();
    testSourcePortWithoutMode();
    testHttpGetMissingSourcePort();
    testHttpGetMissingTarget();
    testTargetWithoutHttpGet();
    testTargetAloneWithoutHttpGet();

    testActiveOpenAndHttpGetTogether();
    testHttpGetAndActiveOpenReversedOrder();

    testDuplicateActiveOpen();
    testDuplicateHttpGet();
    testDuplicateSourcePort();
    testDuplicateTarget();

    testUnknownOption();
    testUnknownOptionAmongValidOnes();

    testMissingColon();
    testEmptyDestinationIp();
    testEmptyDestinationPort();
    testMalformedIp();
    testMalformedIpTooFewOctets();

    testPortZero();
    testPortAboveMax();
    testPortNegative();
    testPortPlusPrefixed();
    testPortLeadingWhitespace();
    testPortTrailingWhitespace();
    testPortTrailingJunk();
    testPortLeadingJunk();
    testPortHex();
    testSourcePortTrailingJunk();
    testSourcePortZero();

    testEmptyTarget();
    testTargetMissingLeadingSlash();
    testTargetContainsSpace();
    testTargetContainsCr();
    testTargetContainsLf();

    testHostnameHttpGetRequiresDnsServer();
    testHostnameHttpGetWithDnsServerValid();
    testHostnameNormalizedToLowercase();
    testLiteralIpv4WithDnsServerRejected();
    testDnsServerInPassiveModeRejected();
    testDnsServerWithActiveOpenRejected();
    testDuplicateDnsServerRejected();
    testDnsServerMissingValueRejected();
    testMalformedDnsServerIpRejected();
    testMalformedDnsServerPortRejected();
    testInvalidHostnameDestinationRejected();
    testActiveOpenHostnameDestinationRejected();

    return wirestack::test::failureCount() == 0 ? 0 : 1;
}
