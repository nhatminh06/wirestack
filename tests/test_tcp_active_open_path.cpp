// Composed pure-packet-path tests for TCP active open: beginConnect's SYN
// and the handshake-completing final ACK both go through the full
// serialize -> parse chain (real Ethernet/IPv4/TCP bytes, real
// checksums), with no TapDevice involved. Also covers the timeout
// retransmission, RST-refusal, and retry-exhaustion paths using the same
// deterministic-clock technique as test_tcp_retransmission_path.cpp.

#include "wirestack/ethernet.hpp"
#include "wirestack/ipv4.hpp"
#include "wirestack/mac_address.hpp"
#include "wirestack/tcp.hpp"
#include "wirestack/tcp_connection.hpp"

#include "test_util.hpp"

using namespace wirestack;

namespace {

constexpr TcpClock::time_point t0{};

Ipv4Address localIp() {
    return *Ipv4Address::parse("10.0.0.2");
}
Ipv4Address remoteIp() {
    return *Ipv4Address::parse("10.0.0.1");
}
MacAddress localMac() {
    return *MacAddress::parse("02:00:00:00:00:02");
}
MacAddress remoteMac() {
    return *MacAddress::parse("aa:bb:cc:dd:ee:ff");
}

// Wraps `segment` in IPv4/Ethernet and hands it back as wire bytes,
// addressed from (src_ip, src_mac) to (dst_ip, dst_mac). Used for both
// directions -- Wirestack's own outgoing segments and the hand-assembled
// peer replies -- so both sides of the exchange go through the identical
// real serialize path.
std::vector<std::byte> wrap(const TcpSegment& segment, Ipv4Address src_ip,
                             MacAddress src_mac, Ipv4Address dst_ip, MacAddress dst_mac) {
    auto tcp_bytes = serializeTcpSegment(segment, src_ip, dst_ip);
    if (!std::holds_alternative<std::vector<std::byte>>(tcp_bytes)) {
        return {};
    }
    Ipv4Packet ip;
    ip.ttl = 64;
    ip.protocol = 6;
    ip.source = src_ip;
    ip.destination = dst_ip;
    ip.payload = std::get<std::vector<std::byte>>(tcp_bytes);
    auto ip_bytes = serializeIpv4Packet(ip);
    if (!std::holds_alternative<std::vector<std::byte>>(ip_bytes)) {
        return {};
    }
    EthernetFrame frame;
    frame.destination = dst_mac;
    frame.source = src_mac;
    frame.ether_type = static_cast<std::uint16_t>(EtherType::Ipv4);
    frame.payload = std::get<std::vector<std::byte>>(ip_bytes);
    return serializeEthernetFrame(frame);
}

// Re-parses wire bytes through Ethernet -> IPv4 -> TCP, validating both
// checksums independently (the parser recomputes them, it does not trust
// the header field) and returns the TCP segment plus the addressing it
// carried at each layer.
struct ParsedWire {
    bool ok = false;
    MacAddress eth_src, eth_dst;
    Ipv4Address ip_src, ip_dst;
    TcpSegment tcp;
};

ParsedWire parseWire(std::span<const std::byte> bytes) {
    ParsedWire out;
    auto eth = parseEthernetFrame(bytes);
    auto* frame = std::get_if<EthernetFrame>(&eth);
    if (!frame) return out;
    auto ip = parseIpv4Packet(frame->payload);
    auto* packet = std::get_if<Ipv4Packet>(&ip);
    if (!packet) return out;
    auto tcp = parseTcpSegment(packet->payload, packet->source, packet->destination);
    auto* segment = std::get_if<TcpSegment>(&tcp);
    if (!segment) return out;
    out.ok = true;
    out.eth_src = frame->source;
    out.eth_dst = frame->destination;
    out.ip_src = packet->source;
    out.ip_dst = packet->destination;
    out.tcp = *segment;
    return out;
}

// Hand-assembles a peer SYN-ACK segment as a real TcpSegment (options
// encoded exactly per RFC 1323/793 layout), with peer_isn, peer MSS,
// peer window scale, and SACK-Permitted all independently chosen here --
// none of these values come from Wirestack.
TcpSegment makePeerSynAck(std::uint16_t peer_port, std::uint16_t local_port,
                           std::uint32_t peer_isn, std::uint32_t ack, std::uint16_t window,
                           std::uint16_t peer_mss, std::uint8_t peer_ws) {
    TcpSegment seg;
    seg.source_port = peer_port;
    seg.destination_port = local_port;
    seg.sequence_number = peer_isn;
    seg.acknowledgment_number = ack;
    seg.flags.syn = true;
    seg.flags.ack = true;
    seg.window_size = window;
    seg.urgent_pointer = 0;
    seg.options = {
        std::byte{2}, std::byte{4}, static_cast<std::byte>((peer_mss >> 8) & 0xff),
        static_cast<std::byte>(peer_mss & 0xff),
        std::byte{4}, std::byte{2}, // SACK-Permitted
        std::byte{1},               // NOP
        std::byte{3}, std::byte{3}, static_cast<std::byte>(peer_ws),
    };
    while (seg.options.size() % 4 != 0) {
        seg.options.push_back(std::byte{0});
    }
    return seg;
}

// --- Section 19: full active handshake through real wire bytes --------

void testFullHandshakeWireFormat() {
    TcpConnectionTable table(8080); // listen port is irrelevant here
    constexpr std::uint16_t kSourcePort = 49152;
    constexpr std::uint16_t kRemotePort = 9090;
    TcpConnectionKey key{localIp(), kSourcePort, remoteIp(), kRemotePort};

    auto connect_result = table.beginConnect(key, t0);
    CHECK(connect_result.accepted);
    CHECK(connect_result.syn.has_value());
    if (!connect_result.syn) return;

    std::uint32_t local_isn = connect_result.syn->sequence_number;
    CHECK(!connect_result.syn->flags.ack);
    CHECK(connect_result.syn->flags.syn);
    CHECK(connect_result.syn->acknowledgment_number == 0);
    CHECK(connect_result.syn->payload.empty());

    // Independently-derived expected option bytes: MSS(1460), SACK-
    // Permitted, NOP+WindowScale(2) -- 10 bytes padded to 12.
    std::vector<std::byte> expected_syn_options = {
        std::byte{2}, std::byte{4}, std::byte{0x05}, std::byte{0xb4},
        std::byte{4}, std::byte{2},
        std::byte{1}, std::byte{3}, std::byte{3}, std::byte{2},
        std::byte{0}, std::byte{0},
    };
    CHECK(connect_result.syn->options == expected_syn_options);

    auto syn_bytes = wrap(*connect_result.syn, localIp(), localMac(), remoteIp(), remoteMac());
    CHECK(!syn_bytes.empty());

    auto parsed_syn = parseWire(syn_bytes); // validates IPv4 + TCP checksums
    CHECK(parsed_syn.ok);
    if (parsed_syn.ok) {
        CHECK(parsed_syn.eth_dst == remoteMac());
        CHECK(parsed_syn.eth_src == localMac());
        CHECK(parsed_syn.ip_src == localIp());
        CHECK(parsed_syn.ip_dst == remoteIp());
        CHECK(parsed_syn.tcp.source_port == kSourcePort);
        CHECK(parsed_syn.tcp.destination_port == kRemotePort);
        CHECK(parsed_syn.tcp.flags.syn);
        CHECK(!parsed_syn.tcp.flags.ack);
        CHECK(parsed_syn.tcp.sequence_number == local_isn);
        CHECK(parsed_syn.tcp.acknowledgment_number == 0);
        CHECK(parsed_syn.tcp.payload.empty());
        // 20-byte base header + 12 bytes of options == 32 bytes == 8
        // 32-bit words -- Data Offset itself isn't re-exposed on
        // TcpSegment, but a successful parse at this exact options size
        // proves it was encoded/decoded consistently.
        CHECK(parsed_syn.tcp.options == expected_syn_options);
    }

    // Peer SYN-ACK: independently chosen ISN, MSS, and window scale.
    constexpr std::uint32_t kPeerIsn = 5000000;
    constexpr std::uint16_t kPeerMss = 1460;
    constexpr std::uint8_t kPeerWs = 7;
    constexpr std::uint16_t kSynAckWindow = 4096;
    auto peer_syn_ack = makePeerSynAck(kRemotePort, kSourcePort, kPeerIsn, local_isn + 1,
                                        kSynAckWindow, kPeerMss, kPeerWs);
    auto syn_ack_bytes = wrap(peer_syn_ack, remoteIp(), remoteMac(), localIp(), localMac());
    auto parsed_syn_ack = parseWire(syn_ack_bytes);
    CHECK(parsed_syn_ack.ok);
    if (!parsed_syn_ack.ok) return;

    auto result = table.handle(key, parsed_syn_ack.tcp, t0);
    CHECK(result.connection_established);
    CHECK(table.stateOf(key) == TcpState::Established);
    CHECK(result.reply.has_value());
    if (!result.reply) return;

    auto snapshot = table.snapshotOf(key);
    CHECK(snapshot.has_value());
    if (snapshot) {
        CHECK(snapshot->rcv_nxt == kPeerIsn + 1);
        CHECK(snapshot->snd_una == local_isn + 1);
        CHECK(snapshot->snd_nxt == local_isn + 1);
        CHECK(snapshot->pending_count == 0); // SYN retired
        CHECK(snapshot->snd_wnd == kSynAckWindow); // unscaled, per docs/tcp.md
        CHECK(snapshot->effective_send_mss == std::min<std::uint16_t>(kTcpMss, kPeerMss));
        CHECK(snapshot->window_scaling_enabled);
        CHECK(snapshot->peer_window_scale == kPeerWs);
        CHECK(snapshot->sack_permitted);
        CHECK(snapshot->has_rtt_sample); // clean handshake, never retransmitted
    }

    auto ack_bytes = wrap(*result.reply, localIp(), localMac(), remoteIp(), remoteMac());
    auto parsed_ack = parseWire(ack_bytes);
    CHECK(parsed_ack.ok);
    if (parsed_ack.ok) {
        CHECK(parsed_ack.eth_dst == remoteMac());
        CHECK(parsed_ack.ip_dst == remoteIp());
        CHECK(parsed_ack.tcp.source_port == kSourcePort);
        CHECK(parsed_ack.tcp.destination_port == kRemotePort);
        CHECK(parsed_ack.tcp.flags.ack);
        CHECK(!parsed_ack.tcp.flags.syn);
        CHECK(parsed_ack.tcp.sequence_number == local_isn + 1); // no sequence space consumed
        CHECK(parsed_ack.tcp.acknowledgment_number == kPeerIsn + 1);
        CHECK(parsed_ack.tcp.payload.empty());
    }
}

// --- Section 20: active-SYN timeout retransmission ---------------------

void testActiveSynRetransmissionWireFormat() {
    TcpConnectionTable table(8080);
    TcpConnectionKey key{localIp(), 49153, remoteIp(), 9090};

    auto connect_result = table.beginConnect(key, t0);
    CHECK(connect_result.accepted);
    if (!connect_result.accepted) return;
    std::uint32_t local_isn = connect_result.syn->sequence_number;
    auto original_options = connect_result.syn->options;

    auto before = table.snapshotOf(key);
    CHECK(before.has_value());
    if (before) CHECK(before->snd_nxt == local_isn + 1);

    // Peer response withheld; advance to the initial RTO and poll.
    auto due = table.pollRetransmissions(t0 + kInitialRto);
    CHECK(due.retransmissions.size() == 1);
    CHECK(due.timed_out.empty());
    if (due.retransmissions.size() != 1) return;

    const TcpSegment& retransmitted = due.retransmissions.front().segment;
    CHECK(retransmitted.flags.syn);
    CHECK(!retransmitted.flags.ack);
    CHECK(retransmitted.sequence_number == local_isn);
    CHECK(retransmitted.acknowledgment_number == 0);
    CHECK(retransmitted.payload.empty());
    CHECK(retransmitted.options == original_options);

    auto bytes = wrap(retransmitted, localIp(), localMac(), remoteIp(), remoteMac());
    auto parsed = parseWire(bytes);
    CHECK(parsed.ok);
    if (parsed.ok) {
        CHECK(parsed.tcp.sequence_number == local_isn);
        CHECK(!parsed.tcp.flags.ack);
        CHECK(parsed.tcp.options == original_options);
    }

    auto after = table.snapshotOf(key);
    CHECK(after.has_value());
    if (after) {
        CHECK(after->snd_nxt == local_isn + 1); // never advanced by a retransmission
        CHECK(after->snd_una == local_isn);
        CHECK(after->pending_count == 1);
        CHECK(!after->in_fast_recovery);
        CHECK(!after->persist_armed);
        CHECK(after->ssthresh == kInitialSsthresh); // no congestion collapse for a SYN timeout
    }

    // Now the peer's SYN-ACK arrives -- Karn's rule: no RTT sample.
    auto peer_syn_ack =
        makePeerSynAck(9090, 49153, 7000000, local_isn + 1, 65535, 1460, 0);
    auto establish = table.handle(key, peer_syn_ack, t0 + kInitialRto);
    CHECK(establish.connection_established);
    auto final_snapshot = table.snapshotOf(key);
    CHECK(final_snapshot.has_value());
    if (final_snapshot) {
        CHECK(!final_snapshot->has_rtt_sample); // Karn: retransmitted SYN excluded
        CHECK(final_snapshot->pending_count == 0);
    }
}

// --- Section 21: refusal and timeout-exhaustion composed paths ---------

void testRstRefusalRemovesOnlyAffectedConnection() {
    TcpConnectionTable table(8080);
    TcpConnectionKey refused_key{localIp(), 49154, remoteIp(), 9090};
    TcpConnectionKey survivor_key{localIp(), 49155, remoteIp(), 9091};

    auto refused = table.beginConnect(refused_key, t0);
    auto survivor = table.beginConnect(survivor_key, t0);
    CHECK(refused.accepted && survivor.accepted);
    std::uint32_t refused_isn = refused.syn->sequence_number;

    TcpSegment rst_ack;
    rst_ack.source_port = 9090;
    rst_ack.destination_port = 49154;
    rst_ack.sequence_number = 0;
    rst_ack.acknowledgment_number = refused_isn + 1;
    rst_ack.flags.rst = true;
    rst_ack.flags.ack = true;
    rst_ack.window_size = 0;
    rst_ack.urgent_pointer = 0;

    auto result = table.handle(refused_key, rst_ack, t0);
    CHECK(result.connection_reset);
    CHECK(!result.reply.has_value()); // never respond to RST
    CHECK(!table.stateOf(refused_key).has_value()); // removed

    // Unrelated connection untouched.
    CHECK(table.stateOf(survivor_key) == TcpState::SynSent);

    // Tuple can be reused immediately.
    auto reconnect = table.beginConnect(refused_key, t0);
    CHECK(reconnect.accepted);

    // A wrong-ack RST must not remove a connection.
    TcpSegment wrong_rst = rst_ack;
    wrong_rst.acknowledgment_number = 1; // does not match the outstanding SYN
    auto wrong_result = table.handle(survivor_key, wrong_rst, t0);
    CHECK(!wrong_result.connection_reset);
    CHECK(table.stateOf(survivor_key) == TcpState::SynSent);

    // A bare RST (no ACK) must also be ignored.
    TcpSegment bare_rst;
    bare_rst.source_port = 9091;
    bare_rst.destination_port = 49155;
    bare_rst.flags.rst = true;
    auto bare_result = table.handle(survivor_key, bare_rst, t0);
    CHECK(!bare_result.connection_reset);
    CHECK(table.stateOf(survivor_key) == TcpState::SynSent);
}

void testActiveOpenTimeoutExhaustion() {
    TcpConnectionTable table(8080);
    TcpConnectionKey timing_out_key{localIp(), 49156, remoteIp(), 9090};
    TcpConnectionKey survivor_key{localIp(), 49157, remoteIp(), 9091};

    CHECK(table.beginConnect(timing_out_key, t0).accepted);
    auto survivor_connect = table.beginConnect(survivor_key, t0);
    CHECK(survivor_connect.accepted);
    // The survivor connection actually establishes (unlike timing_out_key,
    // whose peer never responds) -- proves an unrelated connection isn't
    // just spared by accident of timing, but genuinely unaffected by
    // another connection's retry/removal machinery.
    std::uint32_t survivor_isn = survivor_connect.syn->sequence_number;
    auto survivor_syn_ack = makePeerSynAck(9091, 49157, 8000000, survivor_isn + 1, 65535, 1460, 0);
    auto survivor_established = table.handle(survivor_key, survivor_syn_ack, t0);
    CHECK(survivor_established.connection_established);
    CHECK(table.stateOf(survivor_key) == TcpState::Established);

    TcpClock::time_point now = t0;
    TcpClock::duration interval = kInitialRto;
    bool timed_out = false;
    for (int i = 0; i < kMaxRetransmits + 1 && !timed_out; ++i) {
        now += interval;
        auto due = table.pollRetransmissions(now);
        interval *= 2;
        for (const auto& key : due.timed_out) {
            if (key == timing_out_key) {
                timed_out = true;
            }
        }
    }
    CHECK(timed_out);
    CHECK(!table.stateOf(timing_out_key).has_value()); // removed
    CHECK(table.stateOf(survivor_key) == TcpState::Established); // untouched

    // No further segment is produced for the exhausted connection.
    auto due = table.pollRetransmissions(now + std::chrono::hours{1});
    for (const auto& retransmission : due.retransmissions) {
        CHECK(!(retransmission.key == timing_out_key));
    }

    // Four-tuple reusable.
    auto reconnect = table.beginConnect(timing_out_key, t0);
    CHECK(reconnect.accepted);
}

} // namespace

int main() {
    testFullHandshakeWireFormat();
    testActiveSynRetransmissionWireFormat();
    testRstRefusalRemovesOnlyAffectedConnection();
    testActiveOpenTimeoutExhaustion();
    return wirestack::test::failureCount() == 0 ? 0 : 1;
}
