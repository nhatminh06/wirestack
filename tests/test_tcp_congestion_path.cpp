// Composed pure-packet-path test for Reno-style duplicate-ACK loss
// recovery: a real negotiated handshake, five real serialized data
// segments, a simulated single-segment loss, three real duplicate ACKs
// (as a real receiver would send after getting segments 3-5 out of
// order), the resulting immediate fast retransmission serialized and
// re-parsed through the real wire format, and a real cumulative ACK
// that exits fast recovery. No TapDevice, no root, no sleeping.
//
// Wirestack has no active-open/client role, so the "receiver" side is
// simulated the same way every other composed test in this suite
// simulates the peer: by hand-constructing the exact TcpSegments a real
// receiving TCP would emit in this scenario (duplicate ACKs referencing
// the last contiguous byte, then a cumulative ACK once the gap is
// filled), not by running a second TcpConnectionTable.

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

    // --- Handshake: real SYN with MSS + Window Scale, real SYN-ACK, real
    //     scaled final ACK. ---

    TcpSegment syn;
    syn.source_port = 54321;
    syn.destination_port = 8080;
    syn.sequence_number = 1000;
    syn.acknowledgment_number = 0;
    syn.flags.syn = true;
    syn.window_size = 65535;
    syn.urgent_pointer = 0;
    syn.options = {std::byte{2}, std::byte{4}, std::byte{0x05}, std::byte{0xb4},
                   std::byte{1}, std::byte{3}, std::byte{3},    std::byte{2}};

    auto syn_frame = buildFrame(syn, clientIp(), local_ip, clientMac(), local_mac);
    auto parsed_syn = parseFrame(syn_frame);
    CHECK(parsed_syn.has_value());
    if (!parsed_syn) return wirestack::test::failureCount() == 0 ? 0 : 1;

    auto syn_ack = connections.handle(key, parsed_syn->tcp, t0).reply;
    CHECK(syn_ack.has_value());
    if (!syn_ack) return wirestack::test::failureCount() == 0 ? 0 : 1;
    CHECK(syn_ack->options == std::vector<std::byte>({std::byte{2}, std::byte{4}, std::byte{0x05},
                                                        std::byte{0xb4}, std::byte{1}, std::byte{3},
                                                        std::byte{3}, std::byte{2}}));
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

    // --- Five real, wire-serialized data segments. ---

    std::vector<TcpSegment> data_segments;
    for (int i = 0; i < 5; ++i) {
        auto sent = connections.makeOutgoingData(key, toBytes("loss-recovery-segment"), t0);
        CHECK(sent.segments.size() == 1);
        if (sent.segments.size() != 1) return wirestack::test::failureCount() == 0 ? 0 : 1;
        data_segments.push_back(sent.segments.front());

        // Prove every segment actually serializes/parses/checksums
        // correctly over real Ethernet/IPv4, same as any other composed
        // test in this suite.
        auto frame_bytes =
            buildFrame(data_segments.back(), local_ip, clientIp(), local_mac, clientMac());
        auto parsed = parseFrame(frame_bytes);
        CHECK(parsed.has_value());
        if (parsed) {
            CHECK(parsed->tcp.payload == data_segments.back().payload);
            CHECK(parsed->tcp.sequence_number == data_segments.back().sequence_number);
        }
    }
    CHECK(data_segments.size() == 5);
    if (data_segments.size() != 5) return wirestack::test::failureCount() == 0 ? 0 : 1;

    std::uint32_t seg2_seq = data_segments[1].sequence_number;
    auto seg2_payload = data_segments[1].payload;

    // --- Receiver accepts segment 1; segment 2 is dropped (never fed to
    //     the sender's connection state at all); segments 3, 4, 5 arrive
    //     out of order behind it. ---

    TcpSegment ack_seg1;
    ack_seg1.source_port = 54321;
    ack_seg1.destination_port = 8080;
    ack_seg1.sequence_number = 1001;
    ack_seg1.acknowledgment_number = seg2_seq;
    ack_seg1.flags.ack = true;
    ack_seg1.window_size = 65535;
    auto ack_seg1_frame = buildFrame(ack_seg1, clientIp(), local_ip, clientMac(), local_mac);
    auto parsed_ack_seg1 = parseFrame(ack_seg1_frame);
    CHECK(parsed_ack_seg1.has_value());
    if (parsed_ack_seg1) {
        auto result = connections.handle(key, parsed_ack_seg1->tcp, t0);
        CHECK(!result.fast_retransmit.has_value());
    }

    // --- Three duplicate ACKs for the missing segment 2 (what a real
    //     receiver sends upon getting 3, 4, 5 out of order). The third
    //     must produce an immediate fast retransmission. ---

    TcpSegment dup_ack = ack_seg1; // same ack number: still pointing at seg2_seq
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

    auto after_recovery_entry = connections.snapshotOf(key);
    CHECK(after_recovery_entry.has_value());
    if (after_recovery_entry) {
        CHECK(after_recovery_entry->in_fast_recovery);
        // flight at the 3rd duplicate = segments 2,3,4,5 = 4 * 22 bytes.
        std::uint32_t flight =
            4 * static_cast<std::uint32_t>(toBytes("loss-recovery-segment").size());
        std::uint32_t smss = after_recovery_entry->effective_send_mss;
        CHECK(after_recovery_entry->ssthresh == std::max(flight / 2, 2 * smss));
        CHECK(after_recovery_entry->cwnd == after_recovery_entry->ssthresh + 3 * smss);
        CHECK(after_recovery_entry->recovery_point == after_recovery_entry->snd_nxt);
    }

    // No timeout occurred: the fast retransmission happened well before
    // any RTO deadline (still at t0, using the connection's own
    // current_rto, unmodified by the fast retransmission).
    if (after_recovery_entry) {
        auto too_early =
            connections.pollRetransmissions(t0 + after_recovery_entry->current_rto -
                                             std::chrono::milliseconds(1));
        CHECK(too_early.retransmissions.empty());
    }

    // --- Serialize and re-parse the fast-retransmitted segment: exact
    //     lost segment, valid checksum, unchanged sequence numbers. ---

    CHECK(fast_retransmit->sequence_number == seg2_seq);
    CHECK(fast_retransmit->payload == seg2_payload);
    auto fr_frame = buildFrame(*fast_retransmit, local_ip, clientIp(), local_mac, clientMac());
    auto parsed_fr = parseFrame(fr_frame); // validates both checksums
    CHECK(parsed_fr.has_value());
    if (parsed_fr) {
        CHECK(parsed_fr->tcp.sequence_number == seg2_seq);
        CHECK(parsed_fr->tcp.payload == seg2_payload);
        CHECK(parsed_fr->tcp.flags.ack);
    }

    // --- The receiver's reassembly buffer now has 2 (from the
    //     retransmission), 3, 4, 5 contiguous: it releases everything and
    //     emits one cumulative ACK covering all five segments. No
    //     application data is ever delivered twice on Wirestack's own
    //     receive side (Wirestack is the sender here; the "no duplicate
    //     delivery" property is proven by the earlier composed reassembly
    //     test, test_tcp_reassembly_path.cpp, using the identical
    //     first-arrival-wins buffer this connection also uses on its own
    //     receive side). ---

    TcpSegment cumulative_ack;
    cumulative_ack.source_port = 54321;
    cumulative_ack.destination_port = 8080;
    cumulative_ack.sequence_number = 1001;
    cumulative_ack.acknowledgment_number = data_segments.back().sequence_number +
                                            static_cast<std::uint32_t>(
                                                data_segments.back().payload.size());
    cumulative_ack.flags.ack = true;
    cumulative_ack.window_size = 65535;

    auto cumulative_frame =
        buildFrame(cumulative_ack, clientIp(), local_ip, clientMac(), local_mac);
    auto parsed_cumulative = parseFrame(cumulative_frame);
    CHECK(parsed_cumulative.has_value());
    if (parsed_cumulative) {
        auto result = connections.handle(key, parsed_cumulative->tcp, t0);
        CHECK(!result.reply.has_value());
        CHECK(!result.fast_retransmit.has_value());
    }

    // --- Sender exits fast recovery; every pending entry retires. ---

    auto after_exit = connections.snapshotOf(key);
    CHECK(after_exit.has_value());
    if (after_exit && after_recovery_entry) {
        CHECK(!after_exit->in_fast_recovery);
        CHECK(after_exit->cwnd == after_recovery_entry->ssthresh);
        CHECK(after_exit->duplicate_ack_count == 0);
        CHECK(after_exit->congestion_avoidance_acked_bytes == 0);
        CHECK(after_exit->pending_count == 0);
        CHECK(after_exit->snd_una == after_exit->snd_nxt);
    }

    return wirestack::test::failureCount() == 0 ? 0 : 1;
}
