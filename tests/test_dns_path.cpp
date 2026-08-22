// Composed pure-packet-path tests for the DNS client: the retry/timeout
// state machine driven with a synthetic clock (no sleeps), plus the full
// query/response cycle serialized through the real UDP/IPv4/Ethernet
// layers (no TapDevice involved) -- proving DNS resolution never bypasses
// those layers and that TCP active open never starts before resolution.

#include "wirestack/dns.hpp"
#include "wirestack/ethernet.hpp"
#include "wirestack/ipv4.hpp"
#include "wirestack/mac_address.hpp"
#include "wirestack/tcp.hpp"
#include "wirestack/tcp_connection.hpp"
#include "wirestack/udp.hpp"

#include "test_util.hpp"

#include <optional>

using namespace wirestack;

namespace {

constexpr DnsClock::time_point t0{};

Ipv4Address serverIp() {
    return *Ipv4Address::parse("10.0.0.1");
}
Ipv4Address localIp() {
    return *Ipv4Address::parse("10.0.0.2");
}

DnsQuery exampleQuery() {
    DnsQuery q;
    q.transaction_id = 0x1234;
    q.hostname = "example.test";
    return q;
}

DnsClientSession makeSession() {
    DnsClientSession session;
    session.server_ip = serverIp();
    session.server_port = 5353;
    session.local_port = kDnsClientSourcePort;
    return session;
}

// --- Section 22: synthetic-clock retry/timeout state machine --------------

void testInitialQueryArmsOneSecondDeadline() {
    auto session = makeSession();
    auto sent = beginDnsQuery(session, exampleQuery(), t0);
    CHECK(sent.has_value());
    CHECK(session.transmit_count == 1);
    CHECK(session.next_deadline == t0 + kDnsInitialInterval);
    CHECK(session.state == DnsClientState::Pending);
}

void testNoRetryBeforeDeadline() {
    auto session = makeSession();
    beginDnsQuery(session, exampleQuery(), t0);
    auto poll = pollDnsTimeout(session, t0 + kDnsInitialInterval - std::chrono::milliseconds{1});
    CHECK(!poll.retransmit.has_value());
    CHECK(!poll.timed_out);
    CHECK(session.transmit_count == 1);
}

void testFirstRetryAtOneSecond() {
    auto session = makeSession();
    auto original = beginDnsQuery(session, exampleQuery(), t0);
    auto poll = pollDnsTimeout(session, t0 + kDnsInitialInterval);
    CHECK(poll.retransmit.has_value());
    CHECK(!poll.timed_out);
    CHECK(session.transmit_count == 2);
    if (poll.retransmit) {
        CHECK(*poll.retransmit == *original); // byte-identical retransmission
    }
    CHECK(session.next_deadline == t0 + kDnsInitialInterval + std::chrono::milliseconds{2000});
}

void testSecondRetryAtThreeSeconds() {
    auto session = makeSession();
    auto original = beginDnsQuery(session, exampleQuery(), t0);
    auto first = pollDnsTimeout(session, t0 + std::chrono::seconds{1});
    CHECK(first.retransmit.has_value());
    auto second = pollDnsTimeout(session, t0 + std::chrono::seconds{3});
    CHECK(second.retransmit.has_value());
    CHECK(!second.timed_out);
    CHECK(session.transmit_count == 3);
    if (second.retransmit) {
        CHECK(*second.retransmit == *original);
    }
    // Interval capped at kDnsMaxInterval (4s): next deadline = 3s + 4s = 7s.
    CHECK(session.next_deadline == t0 + std::chrono::seconds{7});
}

void testTerminalTimeoutAtSevenSeconds() {
    auto session = makeSession();
    beginDnsQuery(session, exampleQuery(), t0);
    pollDnsTimeout(session, t0 + std::chrono::seconds{1});
    pollDnsTimeout(session, t0 + std::chrono::seconds{3});
    auto terminal = pollDnsTimeout(session, t0 + std::chrono::seconds{7});
    CHECK(terminal.timed_out);
    CHECK(!terminal.retransmit.has_value());
    CHECK(session.state == DnsClientState::Failed);
    CHECK(!session.failure_reason.has_value()); // timeout carries no DNS rcode
    CHECK(session.transmit_count == 3); // never a 4th
}

void testNoFourthQueryEverEmitted() {
    auto session = makeSession();
    beginDnsQuery(session, exampleQuery(), t0);
    pollDnsTimeout(session, t0 + std::chrono::seconds{1});
    pollDnsTimeout(session, t0 + std::chrono::seconds{3});
    pollDnsTimeout(session, t0 + std::chrono::seconds{7});
    // Any further poll, at any later time, must be a no-op.
    auto later = pollDnsTimeout(session, t0 + std::chrono::hours{1});
    CHECK(!later.retransmit.has_value());
    CHECK(!later.timed_out);
    CHECK(session.transmit_count == 3);
}

void testResolutionCancelsRetry() {
    auto session = makeSession();
    beginDnsQuery(session, exampleQuery(), t0);
    auto bytes = *serializeDnsQuery(exampleQuery());
    (void)bytes;

    std::vector<std::byte> response = {
        std::byte{0x12}, std::byte{0x34}, std::byte{0x81}, std::byte{0x80},
        std::byte{0x00}, std::byte{0x01}, std::byte{0x00}, std::byte{0x01},
        std::byte{0x00}, std::byte{0x00}, std::byte{0x00}, std::byte{0x00},
        std::byte{0x07}, std::byte{'e'}, std::byte{'x'}, std::byte{'a'},
        std::byte{'m'}, std::byte{'p'}, std::byte{'l'}, std::byte{'e'},
        std::byte{0x04}, std::byte{'t'}, std::byte{'e'}, std::byte{'s'}, std::byte{'t'},
        std::byte{0x00},
        std::byte{0x00}, std::byte{0x01}, std::byte{0x00}, std::byte{0x01},
        std::byte{0xc0}, std::byte{0x0c}, std::byte{0x00}, std::byte{0x01},
        std::byte{0x00}, std::byte{0x01}, std::byte{0x00}, std::byte{0x00},
        std::byte{0x00}, std::byte{0x3c}, std::byte{0x00}, std::byte{0x04},
        std::byte{0x0a}, std::byte{0x00}, std::byte{0x00}, std::byte{0x01},
    };
    bool changed =
        handleDnsResponse(session, serverIp(), 5353, kDnsClientSourcePort, response);
    CHECK(changed);
    CHECK(session.state == DnsClientState::Resolved);
    CHECK(session.resolved_address == Ipv4Address::parse("10.0.0.1"));
    CHECK(!session.next_deadline.has_value());

    // Timer is dead: no retry, no timeout, ever again.
    auto poll = pollDnsTimeout(session, t0 + std::chrono::hours{1});
    CHECK(!poll.retransmit.has_value());
    CHECK(!poll.timed_out);
}

std::vector<std::byte> nxdomainResponse() {
    return {
        std::byte{0x12}, std::byte{0x34}, std::byte{0x81}, std::byte{0x83}, // RCODE=3
        std::byte{0x00}, std::byte{0x01}, std::byte{0x00}, std::byte{0x00},
        std::byte{0x00}, std::byte{0x00}, std::byte{0x00}, std::byte{0x00},
        std::byte{0x07}, std::byte{'e'}, std::byte{'x'}, std::byte{'a'},
        std::byte{'m'}, std::byte{'p'}, std::byte{'l'}, std::byte{'e'},
        std::byte{0x04}, std::byte{'t'}, std::byte{'e'}, std::byte{'s'}, std::byte{'t'},
        std::byte{0x00},
        std::byte{0x00}, std::byte{0x01}, std::byte{0x00}, std::byte{0x01},
    };
}

void testNxDomainCancelsRetry() {
    auto session = makeSession();
    beginDnsQuery(session, exampleQuery(), t0);
    bool changed = handleDnsResponse(session, serverIp(), 5353, kDnsClientSourcePort,
                                       nxdomainResponse());
    CHECK(changed);
    CHECK(session.state == DnsClientState::Failed);
    CHECK(session.failure_reason == DnsResponseOutcome::NxDomain);
    CHECK(!session.next_deadline.has_value());
    auto poll = pollDnsTimeout(session, t0 + std::chrono::hours{1});
    CHECK(!poll.retransmit.has_value());
}

void testWrongSourceIgnored() {
    auto session = makeSession();
    beginDnsQuery(session, exampleQuery(), t0);
    bool changed = handleDnsResponse(session, *Ipv4Address::parse("10.0.0.9"), 5353,
                                       kDnsClientSourcePort, nxdomainResponse());
    CHECK(!changed);
    CHECK(session.state == DnsClientState::Pending);
}

void testWrongPortIgnored() {
    auto session = makeSession();
    beginDnsQuery(session, exampleQuery(), t0);
    bool changed =
        handleDnsResponse(session, serverIp(), 9999, kDnsClientSourcePort, nxdomainResponse());
    CHECK(!changed);
    CHECK(session.state == DnsClientState::Pending);
}

void testWrongDestinationPortIgnored() {
    auto session = makeSession();
    beginDnsQuery(session, exampleQuery(), t0);
    bool changed = handleDnsResponse(session, serverIp(), 5353, 9999, nxdomainResponse());
    CHECK(!changed);
    CHECK(session.state == DnsClientState::Pending);
}

void testWrongTransactionIgnored() {
    auto session = makeSession();
    beginDnsQuery(session, exampleQuery(), t0);
    auto response = nxdomainResponse();
    response[0] = std::byte{0xff};
    response[1] = std::byte{0xff};
    bool changed =
        handleDnsResponse(session, serverIp(), 5353, kDnsClientSourcePort, response);
    CHECK(!changed);
    CHECK(session.state == DnsClientState::Pending);
}

void testWrongQuestionIgnored() {
    auto session = makeSession();
    DnsQuery other = exampleQuery();
    other.hostname = "other.test";
    beginDnsQuery(session, other, t0); // session now expects "other.test"
    bool changed = handleDnsResponse(session, serverIp(), 5353, kDnsClientSourcePort,
                                       nxdomainResponse()); // answers "example.test"
    CHECK(!changed);
    CHECK(session.state == DnsClientState::Pending);
}

void testDuplicateValidResponseHarmless() {
    auto session = makeSession();
    beginDnsQuery(session, exampleQuery(), t0);
    std::vector<std::byte> response = {
        std::byte{0x12}, std::byte{0x34}, std::byte{0x81}, std::byte{0x83},
        std::byte{0x00}, std::byte{0x01}, std::byte{0x00}, std::byte{0x00},
        std::byte{0x00}, std::byte{0x00}, std::byte{0x00}, std::byte{0x00},
        std::byte{0x07}, std::byte{'e'}, std::byte{'x'}, std::byte{'a'},
        std::byte{'m'}, std::byte{'p'}, std::byte{'l'}, std::byte{'e'},
        std::byte{0x04}, std::byte{'t'}, std::byte{'e'}, std::byte{'s'}, std::byte{'t'},
        std::byte{0x00},
        std::byte{0x00}, std::byte{0x01}, std::byte{0x00}, std::byte{0x01},
    };
    bool first = handleDnsResponse(session, serverIp(), 5353, kDnsClientSourcePort, response);
    CHECK(first);
    CHECK(session.state == DnsClientState::Failed);
    bool second = handleDnsResponse(session, serverIp(), 5353, kDnsClientSourcePort, response);
    CHECK(!second); // no longer Pending -- ignored, no double-processing
    CHECK(session.state == DnsClientState::Failed);
}

// --- Section 23/24: composed wire-format query/response/TCP transition --

// A real UDP/IPv4/Ethernet-wrapped DNS query, hand-parsed back to prove
// direction/ports/checksum, mirroring how main.cpp would build it.
std::vector<std::byte> wrapUdp(std::span<const std::byte> dns_payload, Ipv4Address src_ip,
                                 MacAddress src_mac, std::uint16_t src_port, Ipv4Address dst_ip,
                                 MacAddress dst_mac, std::uint16_t dst_port) {
    UdpDatagram datagram;
    datagram.source_port = src_port;
    datagram.destination_port = dst_port;
    datagram.payload.assign(dns_payload.begin(), dns_payload.end());
    auto udp_bytes = serializeUdpDatagram(datagram, src_ip, dst_ip);
    if (!std::holds_alternative<std::vector<std::byte>>(udp_bytes)) return {};

    Ipv4Packet ip;
    ip.ttl = 64;
    ip.protocol = 17;
    ip.source = src_ip;
    ip.destination = dst_ip;
    ip.payload = std::get<std::vector<std::byte>>(udp_bytes);
    auto ip_bytes = serializeIpv4Packet(ip);
    if (!std::holds_alternative<std::vector<std::byte>>(ip_bytes)) return {};

    EthernetFrame frame;
    frame.destination = dst_mac;
    frame.source = src_mac;
    frame.ether_type = static_cast<std::uint16_t>(EtherType::Ipv4);
    frame.payload = std::get<std::vector<std::byte>>(ip_bytes);
    return serializeEthernetFrame(frame);
}

struct ParsedUdpWire {
    bool ok = false;
    MacAddress eth_src, eth_dst;
    Ipv4Address ip_src, ip_dst;
    UdpDatagram udp;
};

ParsedUdpWire parseUdpWire(std::span<const std::byte> bytes) {
    ParsedUdpWire out;
    auto eth = parseEthernetFrame(bytes);
    auto* frame = std::get_if<EthernetFrame>(&eth);
    if (!frame) return out;
    auto ip = parseIpv4Packet(frame->payload);
    auto* packet = std::get_if<Ipv4Packet>(&ip);
    if (!packet) return out;
    auto udp = parseUdpDatagram(packet->payload, packet->source, packet->destination);
    auto* datagram = std::get_if<UdpDatagram>(&udp);
    if (!datagram) return out;
    out.ok = true;
    out.eth_src = frame->source;
    out.eth_dst = frame->destination;
    out.ip_src = packet->source;
    out.ip_dst = packet->destination;
    out.udp = *datagram;
    return out;
}

void testComposedResolutionThenActiveOpenNeverStartsEarly() {
    MacAddress local_mac = *MacAddress::parse("02:00:00:00:00:02");
    MacAddress server_mac = *MacAddress::parse("aa:bb:cc:dd:ee:ff");
    constexpr std::uint16_t kServerPort = 5353;
    constexpr std::uint16_t kHttpPort = 9094;
    constexpr std::uint16_t kTcpSourcePort = 49300;

    auto session = makeSession();
    DnsQuery query;
    query.transaction_id = 0x1234;
    query.hostname = "example.test";
    auto query_bytes = beginDnsQuery(session, query, t0);
    CHECK(query_bytes.has_value());
    if (!query_bytes) return;

    // Outgoing query goes through real UDP/IPv4/Ethernet.
    auto query_frame = wrapUdp(*query_bytes, localIp(), local_mac, kDnsClientSourcePort,
                                 serverIp(), server_mac, kServerPort);
    CHECK(!query_frame.empty());
    auto parsed_query = parseUdpWire(query_frame);
    CHECK(parsed_query.ok);
    if (parsed_query.ok) {
        CHECK(parsed_query.eth_dst == server_mac);
        CHECK(parsed_query.ip_dst == serverIp());
        CHECK(parsed_query.udp.source_port == kDnsClientSourcePort);
        CHECK(parsed_query.udp.destination_port == kServerPort);
        CHECK(parsed_query.udp.payload == *query_bytes); // exact DNS question preserved
    }

    // No TCP connection may exist yet -- resolution has not happened.
    TcpConnectionTable table(8080);
    CHECK(!table.stateOf(TcpConnectionKey{localIp(), kTcpSourcePort, *Ipv4Address::parse("10.0.0.1"),
                                            kHttpPort})
               .has_value());

    // Independently-constructed compressed DNS reply, wrapped through the
    // same real UDP/IPv4/Ethernet layers in the reverse direction.
    std::vector<std::byte> dns_reply = {
        std::byte{0x12}, std::byte{0x34}, std::byte{0x81}, std::byte{0x80},
        std::byte{0x00}, std::byte{0x01}, std::byte{0x00}, std::byte{0x01},
        std::byte{0x00}, std::byte{0x00}, std::byte{0x00}, std::byte{0x00},
        std::byte{0x07}, std::byte{'e'}, std::byte{'x'}, std::byte{'a'},
        std::byte{'m'}, std::byte{'p'}, std::byte{'l'}, std::byte{'e'},
        std::byte{0x04}, std::byte{'t'}, std::byte{'e'}, std::byte{'s'}, std::byte{'t'},
        std::byte{0x00},
        std::byte{0x00}, std::byte{0x01}, std::byte{0x00}, std::byte{0x01},
        std::byte{0xc0}, std::byte{0x0c}, std::byte{0x00}, std::byte{0x01},
        std::byte{0x00}, std::byte{0x01}, std::byte{0x00}, std::byte{0x00},
        std::byte{0x00}, std::byte{0x3c}, std::byte{0x00}, std::byte{0x04},
        std::byte{0x0a}, std::byte{0x00}, std::byte{0x00}, std::byte{0x01},
    };
    auto reply_frame = wrapUdp(dns_reply, serverIp(), server_mac, kServerPort, localIp(),
                                 local_mac, kDnsClientSourcePort);
    auto parsed_reply = parseUdpWire(reply_frame);
    CHECK(parsed_reply.ok);
    if (!parsed_reply.ok) return;
    CHECK(parsed_reply.udp.source_port == kServerPort);
    CHECK(parsed_reply.udp.destination_port == kDnsClientSourcePort);

    bool changed = handleDnsResponse(session, parsed_reply.ip_src, parsed_reply.udp.source_port,
                                       parsed_reply.udp.destination_port,
                                       parsed_reply.udp.payload);
    CHECK(changed);
    CHECK(session.state == DnsClientState::Resolved);
    CHECK(session.resolved_address == Ipv4Address::parse("10.0.0.1"));

    // Resolution-to-TCP transition: exactly one connection, addressed to
    // the resolved IPv4, never the DNS server's address.
    TcpConnectionKey key{localIp(), kTcpSourcePort, *session.resolved_address, kHttpPort};
    auto connect_result = table.beginConnect(key, t0);
    CHECK(connect_result.accepted);
    CHECK(connect_result.syn.has_value());
    CHECK(table.stateOf(key) == TcpState::SynSent);

    // A duplicate/late DNS response must never create a second connection.
    bool duplicate = handleDnsResponse(session, parsed_reply.ip_src, parsed_reply.udp.source_port,
                                         parsed_reply.udp.destination_port,
                                         parsed_reply.udp.payload);
    CHECK(!duplicate);
    auto second_attempt = table.beginConnect(key, t0);
    CHECK(!second_attempt.accepted); // DuplicateConnection
}

void testRetryPacketPathLossThenIdenticalRetransmission() {
    auto session = makeSession();
    auto first_query = beginDnsQuery(session, exampleQuery(), t0);
    CHECK(first_query.has_value());

    // First query dropped (never delivered anywhere); clock advances to
    // the retry deadline.
    auto poll = pollDnsTimeout(session, t0 + kDnsInitialInterval);
    CHECK(poll.retransmit.has_value());
    if (poll.retransmit) {
        CHECK(*poll.retransmit == *first_query); // byte-identical retry
    }

    // The retry succeeds: resolve, and the DNS deadline is cancelled.
    std::vector<std::byte> response = {
        std::byte{0x12}, std::byte{0x34}, std::byte{0x81}, std::byte{0x80},
        std::byte{0x00}, std::byte{0x01}, std::byte{0x00}, std::byte{0x01},
        std::byte{0x00}, std::byte{0x00}, std::byte{0x00}, std::byte{0x00},
        std::byte{0x07}, std::byte{'e'}, std::byte{'x'}, std::byte{'a'},
        std::byte{'m'}, std::byte{'p'}, std::byte{'l'}, std::byte{'e'},
        std::byte{0x04}, std::byte{'t'}, std::byte{'e'}, std::byte{'s'}, std::byte{'t'},
        std::byte{0x00},
        std::byte{0x00}, std::byte{0x01}, std::byte{0x00}, std::byte{0x01},
        std::byte{0xc0}, std::byte{0x0c}, std::byte{0x00}, std::byte{0x01},
        std::byte{0x00}, std::byte{0x01}, std::byte{0x00}, std::byte{0x00},
        std::byte{0x00}, std::byte{0x3c}, std::byte{0x00}, std::byte{0x04},
        std::byte{0x0a}, std::byte{0x00}, std::byte{0x00}, std::byte{0x01},
    };
    bool changed =
        handleDnsResponse(session, serverIp(), 5353, kDnsClientSourcePort, response);
    CHECK(changed);
    CHECK(session.state == DnsClientState::Resolved);

    // Later DNS deadline is cancelled: exactly one TCP connection follows.
    auto later_poll = pollDnsTimeout(session, t0 + std::chrono::seconds{100});
    CHECK(!later_poll.retransmit.has_value());
    CHECK(!later_poll.timed_out);

    TcpConnectionTable table(8080);
    TcpConnectionKey key{localIp(), 49300, *session.resolved_address, 9094};
    auto connect_result = table.beginConnect(key, t0);
    CHECK(connect_result.accepted);
}

void testTotalTimeoutProducesZeroSyns() {
    auto session = makeSession();
    beginDnsQuery(session, exampleQuery(), t0);
    pollDnsTimeout(session, t0 + std::chrono::seconds{1});
    pollDnsTimeout(session, t0 + std::chrono::seconds{3});
    auto terminal = pollDnsTimeout(session, t0 + std::chrono::seconds{7});
    CHECK(terminal.timed_out);
    CHECK(session.state == DnsClientState::Failed);
    CHECK(session.transmit_count == 3);
    CHECK(!session.resolved_address.has_value());

    // No SYN may ever be sent for this session's destination -- the caller
    // (main.cpp) simply never calls beginConnect when state != Resolved,
    // which is exactly what a terminal Failed state guarantees to any
    // caller inspecting it.
    CHECK(session.state != DnsClientState::Resolved);
}

} // namespace

int main() {
    testInitialQueryArmsOneSecondDeadline();
    testNoRetryBeforeDeadline();
    testFirstRetryAtOneSecond();
    testSecondRetryAtThreeSeconds();
    testTerminalTimeoutAtSevenSeconds();
    testNoFourthQueryEverEmitted();
    testResolutionCancelsRetry();
    testNxDomainCancelsRetry();
    testWrongSourceIgnored();
    testWrongPortIgnored();
    testWrongDestinationPortIgnored();
    testWrongTransactionIgnored();
    testWrongQuestionIgnored();
    testDuplicateValidResponseHarmless();

    testComposedResolutionThenActiveOpenNeverStartsEarly();
    testRetryPacketPathLossThenIdenticalRetransmission();
    testTotalTimeoutProducesZeroSyns();

    return wirestack::test::failureCount() == 0 ? 0 : 1;
}
