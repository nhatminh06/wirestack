// Composed pure-packet-path test for NewReno-style partial-ACK recovery
// with SACK NOT negotiated: a real handshake, six real serialized data
// segments, two simulated consecutive losses (segments 2 and 3), three
// real duplicate ACKs (immediate fast retransmission of segment 2), a
// real partial cumulative ACK that only covers segment 2 (NewReno partial
// ACK -- remains in recovery, retransmits segment 3), and a real final
// cumulative ACK reaching recovery_point (full ACK -- exits recovery).
// No TapDevice, no root, no sleeping.
//
// Wirestack has no active-open/client role, so the "receiver" side is
// simulated the same way every other composed test in this suite
// simulates the peer: by hand-constructing the exact TcpSegments a real
// receiving TCP would emit in this scenario.

#include "wirestack/ethernet.hpp"
#include "wirestack/ipv4.hpp"
#include "wirestack/mac_address.hpp"
#include "wirestack/tcp.hpp"
#include "wirestack/tcp_connection.hpp"

#include "test_util.hpp"

using namespace wirestack;

namespace {

MacAddress clientMac() {
    return *MacAddress::parse("aa:bb:cc:dd:ee:ff");
}
Ipv4Address clientIp() {
    return *Ipv4Address::parse("10.0.0.1");
}

std::vector<std::byte> toBytes(std::string_view text) {
    std::vector<std::byte> out;
    out.reserve(text.size());
    for (char c : text) {
        out.push_back(static_cast<std::byte>(static_cast<unsigned char>(c)));
    }
    return out;
}

std::vector<std::byte> buildFrame(const TcpSegment& segment, Ipv4Address source_ip,
                                   Ipv4Address dest_ip, MacAddress source_mac,
                                   MacAddress dest_mac) {
    auto tcp_bytes = serializeTcpSegment(segment, source_ip, dest_ip);
    Ipv4Packet ip_packet;
    ip_packet.ttl = 64;
    ip_packet.protocol = 6;
    ip_packet.source = source_ip;
    ip_packet.destination = dest_ip;
    ip_packet.payload = std::get<std::vector<std::byte>>(tcp_bytes);

    auto ip_bytes = serializeIpv4Packet(ip_packet);
    EthernetFrame frame;
    frame.destination = dest_mac;
    frame.source = source_mac;
    frame.ether_type = static_cast<std::uint16_t>(EtherType::Ipv4);
    frame.payload = std::get<std::vector<std::byte>>(ip_bytes);

    return serializeEthernetFrame(frame);
}

struct ParsedFrame {
    EthernetFrame eth;
    Ipv4Packet ip;
    TcpSegment tcp;
};

std::optional<ParsedFrame> parseFrame(std::span<const std::byte> bytes) {
    auto eth_result = parseEthernetFrame(bytes);
    auto* frame = std::get_if<EthernetFrame>(&eth_result);
    CHECK(frame != nullptr);
    if (frame == nullptr) return std::nullopt;

    auto ip_result = parseIpv4Packet(frame->payload);
    auto* ip_packet = std::get_if<Ipv4Packet>(&ip_result);
    CHECK(ip_packet != nullptr);
    if (ip_packet == nullptr) return std::nullopt;

    auto tcp_result =
        parseTcpSegment(ip_packet->payload, ip_packet->source, ip_packet->destination);
    auto* segment = std::get_if<TcpSegment>(&tcp_result);
    CHECK(segment != nullptr);
    if (segment == nullptr) return std::nullopt;

    return ParsedFrame{*frame, *ip_packet, *segment};
}

} // namespace

int main() {
    auto local_ip = *Ipv4Address::parse("10.0.0.2");
    auto local_mac = *MacAddress::parse("02:00:00:00:00:02");
    constexpr TcpClock::time_point t0{};

    TcpConnectionTable connections(8080);
    TcpConnectionKey key{local_ip, 8080, clientIp(), 54321};

    // --- Handshake: real SYN with MSS only (no SACK-Permitted). ---

    TcpSegment syn;
    syn.source_port = 54321;
    syn.destination_port = 8080;
    syn.sequence_number = 1000;
    syn.acknowledgment_number = 0;
    syn.flags.syn = true;
    syn.window_size = 65535;
    syn.urgent_pointer = 0;
    syn.options = {std::byte{2}, std::byte{4}, std::byte{0x05}, std::byte{0xb4}};

    auto syn_frame = buildFrame(syn, clientIp(), local_ip, clientMac(), local_mac);
    auto parsed_syn = parseFrame(syn_frame);
    CHECK(parsed_syn.has_value());
    if (!parsed_syn) return wirestack::test::failureCount() == 0 ? 0 : 1;

    auto syn_ack = connections.handle(key, parsed_syn->tcp, t0).reply;
    CHECK(syn_ack.has_value());
    if (!syn_ack) return wirestack::test::failureCount() == 0 ? 0 : 1;
    CHECK(syn_ack->options == std::vector<std::byte>({std::byte{2}, std::byte{4}, std::byte{0x05},
                                                        std::byte{0xb4}}));
    std::uint32_t server_isn = syn_ack->sequence_number;

    TcpSegment final_ack;
    final_ack.source_port = 54321;
    final_ack.destination_port = 8080;
    final_ack.sequence_number = 1001;
    final_ack.acknowledgment_number = server_isn + 1;
    final_ack.flags.ack = true;
    final_ack.window_size = 65535;

    auto final_ack_frame = buildFrame(final_ack, clientIp(), local_ip, clientMac(), local_mac);
    auto parsed_final_ack = parseFrame(final_ack_frame);
    CHECK(parsed_final_ack.has_value());
    if (parsed_final_ack) connections.handle(key, parsed_final_ack->tcp, t0);
    CHECK(connections.stateOf(key) == TcpState::Established);

    auto snap0 = connections.snapshotOf(key);
    CHECK(snap0.has_value());
    if (snap0) CHECK(!snap0->sack_permitted);

    // --- Six real, wire-serialized data segments. ---

    std::vector<TcpSegment> data_segments;
    for (int i = 0; i < 6; ++i) {
        auto sent = connections.makeOutgoingData(key, toBytes("newreno-recovery-segmnt"), t0);
        CHECK(sent.segments.size() == 1);
        if (sent.segments.size() != 1) return wirestack::test::failureCount() == 0 ? 0 : 1;
        data_segments.push_back(sent.segments.front());

        auto frame_bytes =
            buildFrame(data_segments.back(), local_ip, clientIp(), local_mac, clientMac());
        auto parsed = parseFrame(frame_bytes);
        CHECK(parsed.has_value());
        if (parsed) {
            CHECK(parsed->tcp.payload == data_segments.back().payload);
            CHECK(parsed->tcp.sequence_number == data_segments.back().sequence_number);
        }
    }
    CHECK(data_segments.size() == 6);
    if (data_segments.size() != 6) return wirestack::test::failureCount() == 0 ? 0 : 1;

    std::uint32_t seg2_seq = data_segments[1].sequence_number;
    std::uint32_t seg3_seq = data_segments[2].sequence_number;
    auto seg2_payload = data_segments[1].payload;
    auto seg3_payload = data_segments[2].payload;

    // --- Receiver accepts segment 1; segments 2 and 3 are dropped (never
    //     fed to the sender's connection state); segments 4, 5, 6 arrive
    //     out of order behind them. ---

    TcpSegment ack_seg1;
    ack_seg1.source_port = 54321;
    ack_seg1.destination_port = 8080;
    ack_seg1.sequence_number = 1001;
    ack_seg1.acknowledgment_number = seg2_seq; // pinned at the first gap
    ack_seg1.flags.ack = true;
    ack_seg1.window_size = 65535;
    auto ack_seg1_frame = buildFrame(ack_seg1, clientIp(), local_ip, clientMac(), local_mac);
    auto parsed_ack_seg1 = parseFrame(ack_seg1_frame);
    CHECK(parsed_ack_seg1.has_value());
    if (parsed_ack_seg1) {
        auto result = connections.handle(key, parsed_ack_seg1->tcp, t0);
        CHECK(!result.fast_retransmit.has_value());
    }

    // --- Three duplicate ACKs for the missing segment 2. The third must
    //     produce an immediate fast retransmission, well before any RTO. ---

    TcpSegment dup_ack = ack_seg1;
    std::optional<TcpSegment> fast_retransmit;
    for (int i = 0; i < 3; ++i) {
        auto dup_frame = buildFrame(dup_ack, clientIp(), local_ip, clientMac(), local_mac);
        auto parsed_dup = parseFrame(dup_frame);
        CHECK(parsed_dup.has_value());
        if (!parsed_dup) continue;
        auto result = connections.handle(key, parsed_dup->tcp, t0);
        if (i < 2) {
            CHECK(!result.fast_retransmit.has_value());
        } else {
            CHECK(result.fast_retransmit.has_value());
            fast_retransmit = result.fast_retransmit;
        }
    }
    CHECK(fast_retransmit.has_value());
    if (!fast_retransmit) return wirestack::test::failureCount() == 0 ? 0 : 1;
    CHECK(fast_retransmit->sequence_number == seg2_seq);
    CHECK(fast_retransmit->payload == seg2_payload);

    auto after_entry = connections.snapshotOf(key);
    CHECK(after_entry.has_value());
    if (after_entry) {
        CHECK(after_entry->in_fast_recovery);
        CHECK(after_entry->recovery_point == after_entry->snd_nxt);

        // No timeout occurred: the fast retransmission happened well
        // before any RTO deadline.
        auto too_early = connections.pollRetransmissions(
            t0 + after_entry->current_rto - std::chrono::milliseconds(1));
        CHECK(too_early.retransmissions.empty());
    }

    // --- Verify the fast-retransmitted segment 2 through real wire
    //     bytes: direction, ports, sequence/ack, payload, flags, both
    //     checksums. ---

    auto fr_frame = buildFrame(*fast_retransmit, local_ip, clientIp(), local_mac, clientMac());
    auto parsed_fr = parseFrame(fr_frame); // validates both checksums
    CHECK(parsed_fr.has_value());
    if (parsed_fr) {
        CHECK(parsed_fr->eth.source == local_mac);
        CHECK(parsed_fr->eth.destination == clientMac());
        CHECK(parsed_fr->ip.source == local_ip);
        CHECK(parsed_fr->ip.destination == clientIp());
        CHECK(parsed_fr->tcp.source_port == 8080);
        CHECK(parsed_fr->tcp.destination_port == 54321);
        CHECK(parsed_fr->tcp.sequence_number == seg2_seq);
        CHECK(parsed_fr->tcp.payload == seg2_payload);
        CHECK(parsed_fr->tcp.flags.ack);
    }

    // --- Receiver's partial cumulative ACK: covers segment 2 (now
    //     retransmitted and received) but segment 3 is still missing, so
    //     the ACK stops there -- a NewReno partial ACK, strictly below
    //     recovery_point. ---

    TcpSegment partial_ack;
    partial_ack.source_port = 54321;
    partial_ack.destination_port = 8080;
    partial_ack.sequence_number = 1001;
    partial_ack.acknowledgment_number = seg3_seq;
    partial_ack.flags.ack = true;
    partial_ack.window_size = 65535;
    auto partial_frame = buildFrame(partial_ack, clientIp(), local_ip, clientMac(), local_mac);
    auto parsed_partial = parseFrame(partial_frame);
    CHECK(parsed_partial.has_value());
    std::optional<TcpSegment> second_retransmit;
    if (parsed_partial) {
        auto result = connections.handle(key, parsed_partial->tcp, t0);
        CHECK(result.fast_retransmit.has_value()); // one immediate retransmission of segment 3
        second_retransmit = result.fast_retransmit;
    }
    CHECK(second_retransmit.has_value());
    if (!second_retransmit) return wirestack::test::failureCount() == 0 ? 0 : 1;
    CHECK(second_retransmit->sequence_number == seg3_seq);
    CHECK(second_retransmit->payload == seg3_payload);

    auto after_partial = connections.snapshotOf(key);
    CHECK(after_partial.has_value());
    if (after_partial) {
        CHECK(after_partial->in_fast_recovery); // still below recovery_point
        CHECK(after_partial->snd_una == seg3_seq);

        // No timeout-count increment: this is Karn ambiguity, not a
        // timeout retry.
        auto too_early = connections.pollRetransmissions(
            t0 + after_partial->current_rto - std::chrono::milliseconds(1));
        CHECK(too_early.retransmissions.empty());
    }

    // --- Verify the second retransmission (segment 3) through real wire
    //     bytes too. ---

    auto second_frame =
        buildFrame(*second_retransmit, local_ip, clientIp(), local_mac, clientMac());
    auto parsed_second = parseFrame(second_frame);
    CHECK(parsed_second.has_value());
    if (parsed_second) {
        CHECK(parsed_second->tcp.sequence_number == seg3_seq);
        CHECK(parsed_second->tcp.payload == seg3_payload);
        CHECK(parsed_second->tcp.flags.ack);
    }

    // --- Final cumulative ACK reaches recovery_point (segments 4, 5, 6
    //     already released by the receiver's reassembly, now cumulative):
    //     a full ACK, exits recovery, cwnd == ssthresh. ---

    TcpSegment final_cumulative;
    final_cumulative.source_port = 54321;
    final_cumulative.destination_port = 8080;
    final_cumulative.sequence_number = 1001;
    final_cumulative.acknowledgment_number =
        data_segments.back().sequence_number +
        static_cast<std::uint32_t>(data_segments.back().payload.size());
    final_cumulative.flags.ack = true;
    final_cumulative.window_size = 65535;

    auto final_cumulative_frame =
        buildFrame(final_cumulative, clientIp(), local_ip, clientMac(), local_mac);
    auto parsed_final_cumulative = parseFrame(final_cumulative_frame);
    CHECK(parsed_final_cumulative.has_value());
    if (parsed_final_cumulative) {
        auto result = connections.handle(key, parsed_final_cumulative->tcp, t0);
        CHECK(!result.fast_retransmit.has_value());
    }

    auto after_exit = connections.snapshotOf(key);
    CHECK(after_exit.has_value());
    if (after_exit && after_entry) {
        CHECK(!after_exit->in_fast_recovery);
        CHECK(after_exit->cwnd == after_entry->ssthresh);
        CHECK(after_exit->duplicate_ack_count == 0);
        CHECK(after_exit->pending_count == 0);
        CHECK(after_exit->snd_una == after_exit->snd_nxt);
    }

    return wirestack::test::failureCount() == 0 ? 0 : 1;
}
