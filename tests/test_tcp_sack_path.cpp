// Composed pure-packet-path test for selective-acknowledgment loss
// recovery: a real handshake negotiating SACK-Permitted, seven real
// serialized data segments, two non-adjacent simulated losses (segments 2
// and 4), real duplicate ACKs carrying real SACK option bytes reporting
// the receiver's actual out-of-order ranges, the resulting selective
// retransmissions (segment 2 on duplicate ACK 3, segment 4 on a further
// SACK-bearing duplicate ACK, skipping the already-SACKed segments 3,
// 5, 6, 7), and a final cumulative ACK that retires everything and exits
// recovery. Also exercises the receiver side: Wirestack's own pure ACK
// generated while holding out-of-order data is re-parsed and its SACK
// blocks verified byte-exact. No TapDevice, no root, no sleeping.
//
// Wirestack has no active-open/client role, so the "receiver" side of
// the sender-loss scenario is simulated the same way every other
// composed test in this suite simulates the peer: by hand-constructing
// the exact TcpSegments (including real SACK option bytes) a real
// receiving TCP would emit.

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

void appendUint32(std::vector<std::byte>& out, std::uint32_t value) {
    out.push_back(static_cast<std::byte>((value >> 24) & 0xff));
    out.push_back(static_cast<std::byte>((value >> 16) & 0xff));
    out.push_back(static_cast<std::byte>((value >> 8) & 0xff));
    out.push_back(static_cast<std::byte>(value & 0xff));
}

// Builds a real, aligned kind-5 SACK option from (left, right) sequence
// pairs -- computed by hand from the block list, never derived by calling
// into Wirestack's own encoder.
std::vector<std::byte> buildSackOption(
    const std::vector<std::pair<std::uint32_t, std::uint32_t>>& blocks) {
    std::vector<std::byte> out;
    out.push_back(std::byte{5});
    out.push_back(static_cast<std::byte>(2 + 8 * blocks.size()));
    for (auto [left, right] : blocks) {
        appendUint32(out, left);
        appendUint32(out, right);
    }
    while (out.size() % 4 != 0) {
        out.push_back(std::byte{0});
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

    // --- Handshake: real SYN advertising MSS + SACK-Permitted. ---

    TcpSegment syn;
    syn.source_port = 54321;
    syn.destination_port = 8080;
    syn.sequence_number = 1000;
    syn.acknowledgment_number = 0;
    syn.flags.syn = true;
    syn.window_size = 65535;
    syn.urgent_pointer = 0;
    syn.options = {std::byte{2}, std::byte{4}, std::byte{0x05}, std::byte{0xb4},
                   std::byte{4}, std::byte{2}, std::byte{0}, std::byte{0}};

    auto syn_frame = buildFrame(syn, clientIp(), local_ip, clientMac(), local_mac);
    auto parsed_syn = parseFrame(syn_frame);
    CHECK(parsed_syn.has_value());
    if (!parsed_syn) return wirestack::test::failureCount() == 0 ? 0 : 1;

    auto syn_ack = connections.handle(key, parsed_syn->tcp, t0).reply;
    CHECK(syn_ack.has_value());
    if (!syn_ack) return wirestack::test::failureCount() == 0 ? 0 : 1;
    // Exact SYN-ACK bytes: MSS then SACK-Permitted then EOL padding.
    CHECK(syn_ack->options == std::vector<std::byte>({std::byte{0x02}, std::byte{0x04},
                                                        std::byte{0x05}, std::byte{0xb4},
                                                        std::byte{0x04}, std::byte{0x02},
                                                        std::byte{0x00}, std::byte{0x00}}));
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
    if (snap0) CHECK(snap0->sack_permitted);

    // --- Seven real, wire-serialized data segments. ---

    std::vector<TcpSegment> data_segments;
    for (int i = 0; i < 7; ++i) {
        auto sent = connections.makeOutgoingData(key, toBytes("sack-recovery-segmentx"), t0);
        CHECK(sent.segments.size() == 1);
        if (sent.segments.size() != 1) return wirestack::test::failureCount() == 0 ? 0 : 1;
        data_segments.push_back(sent.segments.front());

        auto frame_bytes =
            buildFrame(data_segments.back(), local_ip, clientIp(), local_mac, clientMac());
        auto parsed = parseFrame(frame_bytes);
        CHECK(parsed.has_value());
        if (parsed) {
            CHECK(parsed->tcp.payload == data_segments.back().payload);
        }
    }
    CHECK(data_segments.size() == 7);
    if (data_segments.size() != 7) return wirestack::test::failureCount() == 0 ? 0 : 1;

    std::size_t seg_len = data_segments[0].payload.size();
    std::uint32_t seg2_seq = data_segments[1].sequence_number;
    std::uint32_t seg3_seq = data_segments[2].sequence_number;
    std::uint32_t seg4_seq = data_segments[3].sequence_number;
    std::uint32_t seg5_seq = data_segments[4].sequence_number;
    std::uint32_t seg7_end = data_segments[6].sequence_number +
                              static_cast<std::uint32_t>(data_segments[6].payload.size());
    auto seg2_payload = data_segments[1].payload;
    auto seg4_payload = data_segments[3].payload;

    // --- Receiver: delivers segment 1, loses segment 2, delivers segment
    //     3, loses segment 4, delivers segments 5, 6, 7. Verify Wirestack
    //     itself, acting as a receiver holding out-of-order data, reports
    //     exact SACK blocks -- proven with the real receive-side path via
    //     a second connection table acting as the client's own receiver,
    //     for the sender-side loss scenario below the SACK reports are
    //     hand-built the same way every composed test's simulated peer
    //     is. ---

    // Segment 1 accepted; cumulative ACK pinned at seg2_seq (segment 2
    // missing). No SACK blocks yet -- nothing out of order at the sender.
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

    // Real duplicate ACKs, each pinned at seg2_seq, each carrying a real
    // SACK option reporting segment 3 and segments 5-7 received.
    std::vector<std::pair<std::uint32_t, std::uint32_t>> sack_blocks = {
        {seg3_seq, static_cast<std::uint32_t>(seg3_seq + seg_len)}, {seg5_seq, seg7_end}};
    auto sack_option = buildSackOption(sack_blocks);
    // Exact expected bytes: kind 5, length 18 (2 + 8*2), two 8-byte block
    // pairs, padded with 2 zero bytes to the 20-byte aligned total (see
    // docs/tcp.md). Computed by hand, not via Wirestack.
    CHECK(sack_option.size() == 20);
    CHECK(sack_option[0] == std::byte{5});
    CHECK(sack_option[1] == std::byte{18});

    TcpSegment dup_ack = ack_seg1;
    dup_ack.options = sack_option;
    std::optional<TcpSegment> first_retransmit;
    for (int i = 0; i < 3; ++i) {
        auto dup_frame = buildFrame(dup_ack, clientIp(), local_ip, clientMac(), local_mac);
        auto parsed_dup = parseFrame(dup_frame);
        CHECK(parsed_dup.has_value());
        if (!parsed_dup) continue;
        // Re-parse and verify the SACK blocks survive the real wire
        // format exactly.
        auto reparsed_options = parseTcpOptions(parsed_dup->tcp.options);
        CHECK(std::holds_alternative<TcpParsedOptions>(reparsed_options));
        if (auto* opts = std::get_if<TcpParsedOptions>(&reparsed_options)) {
            CHECK(opts->sack_blocks.size() == 2);
            if (opts->sack_blocks.size() == 2) {
                CHECK(opts->sack_blocks[0].left_edge == seg3_seq);
                CHECK(opts->sack_blocks[1].left_edge == seg5_seq);
            }
        }
        auto result = connections.handle(key, parsed_dup->tcp, t0);
        if (i < 2) {
            CHECK(!result.fast_retransmit.has_value());
        } else {
            CHECK(result.fast_retransmit.has_value());
            first_retransmit = result.fast_retransmit;
        }
    }
    CHECK(first_retransmit.has_value());
    if (!first_retransmit) return wirestack::test::failureCount() == 0 ? 0 : 1;
    CHECK(first_retransmit->sequence_number == seg2_seq);
    CHECK(first_retransmit->payload == seg2_payload);

    auto after_dup3 = connections.snapshotOf(key);
    CHECK(after_dup3.has_value());
    if (after_dup3) {
        CHECK(after_dup3->in_fast_recovery);
        CHECK(after_dup3->sacked_pending_count == 4); // segments 3, 5, 6, 7
        CHECK(after_dup3->recovery_retransmitted_count == 1);
        // No RTO expiry: well before the deadline.
        auto too_early = connections.pollRetransmissions(
            t0 + after_dup3->current_rto - std::chrono::milliseconds(1));
        CHECK(too_early.retransmissions.empty());
    }

    // Verify the first retransmission (segment 2) through real wire
    // bytes: direction, ports, sequence, payload, checksums.
    auto first_frame = buildFrame(*first_retransmit, local_ip, clientIp(), local_mac, clientMac());
    auto parsed_first = parseFrame(first_frame);
    CHECK(parsed_first.has_value());
    if (parsed_first) {
        CHECK(parsed_first->eth.source == local_mac);
        CHECK(parsed_first->ip.source == local_ip);
        CHECK(parsed_first->tcp.source_port == 8080);
        CHECK(parsed_first->tcp.sequence_number == seg2_seq);
        CHECK(parsed_first->tcp.payload == seg2_payload);
    }

    // --- An additional SACK-bearing duplicate ACK (still pinned at
    //     seg2_seq, same SACK report): skips the already-SACKed segment
    //     3, selectively retransmits segment 4. ---

    auto dup_frame = buildFrame(dup_ack, clientIp(), local_ip, clientMac(), local_mac);
    auto parsed_dup = parseFrame(dup_frame);
    CHECK(parsed_dup.has_value());
    std::optional<TcpSegment> second_retransmit;
    if (parsed_dup) {
        auto result = connections.handle(key, parsed_dup->tcp, t0);
        CHECK(result.fast_retransmit.has_value());
        second_retransmit = result.fast_retransmit;
    }
    CHECK(second_retransmit.has_value());
    if (!second_retransmit) return wirestack::test::failureCount() == 0 ? 0 : 1;
    CHECK(second_retransmit->sequence_number == seg4_seq); // not segment 3 -- already SACKed
    CHECK(second_retransmit->payload == seg4_payload);

    auto after_dup4 = connections.snapshotOf(key);
    CHECK(after_dup4.has_value());
    if (after_dup4) {
        CHECK(after_dup4->recovery_retransmitted_count == 2); // segments 2 and 4
        CHECK(after_dup4->sacked_pending_count == 4); // still exactly 3, 5, 6, 7
    }

    auto second_frame =
        buildFrame(*second_retransmit, local_ip, clientIp(), local_mac, clientMac());
    auto parsed_second = parseFrame(second_frame);
    CHECK(parsed_second.has_value());
    if (parsed_second) {
        CHECK(parsed_second->tcp.sequence_number == seg4_seq);
        CHECK(parsed_second->tcp.payload == seg4_payload);
    }

    // --- Cumulative ACK reaches recovery_point: full retirement, exits
    //     recovery. ---

    TcpSegment final_cumulative;
    final_cumulative.source_port = 54321;
    final_cumulative.destination_port = 8080;
    final_cumulative.sequence_number = 1001;
    final_cumulative.acknowledgment_number = seg7_end;
    final_cumulative.flags.ack = true;
    final_cumulative.window_size = 65535;

    auto final_frame = buildFrame(final_cumulative, clientIp(), local_ip, clientMac(), local_mac);
    auto parsed_final = parseFrame(final_frame);
    CHECK(parsed_final.has_value());
    if (parsed_final) {
        auto result = connections.handle(key, parsed_final->tcp, t0);
        CHECK(!result.fast_retransmit.has_value());
    }

    auto after_exit = connections.snapshotOf(key);
    CHECK(after_exit.has_value());
    if (after_exit && after_dup3) {
        CHECK(!after_exit->in_fast_recovery);
        CHECK(after_exit->cwnd == after_dup3->ssthresh);
        CHECK(after_exit->pending_count == 0);
        CHECK(after_exit->snd_una == after_exit->snd_nxt);
        CHECK(after_exit->snd_una == seg7_end);
        CHECK(after_exit->sacked_pending_count == 0);
    }

    // --- Receiver-side wire evidence: Wirestack itself, holding
    //     out-of-order data on its own receive side, emits exact SACK
    //     blocks on a pure ACK; re-parsed, the cumulative ACK stays
    //     pinned at the missing byte and blocks describe only the
    //     received out-of-order range; filling the gap releases the
    //     bytes exactly once and the block disappears. ---

    TcpConnectionTable receiver(9090);
    TcpConnectionKey rkey{local_ip, 9090, clientIp(), 44444};
    TcpSegment rsyn;
    rsyn.source_port = 44444;
    rsyn.destination_port = 9090;
    rsyn.sequence_number = 5000;
    rsyn.flags.syn = true;
    rsyn.window_size = 65535;
    rsyn.options = {std::byte{2}, std::byte{4}, std::byte{0x05}, std::byte{0xb4},
                     std::byte{4}, std::byte{2}, std::byte{0}, std::byte{0}};
    auto rsyn_frame = buildFrame(rsyn, clientIp(), local_ip, clientMac(), local_mac);
    auto rparsed_syn = parseFrame(rsyn_frame);
    CHECK(rparsed_syn.has_value());
    if (!rparsed_syn) return wirestack::test::failureCount() == 0 ? 0 : 1;
    auto rsyn_ack = receiver.handle(rkey, rparsed_syn->tcp, t0).reply;
    CHECK(rsyn_ack.has_value());
    if (!rsyn_ack) return wirestack::test::failureCount() == 0 ? 0 : 1;
    std::uint32_t rserver_isn = rsyn_ack->sequence_number;

    TcpSegment rfinal_ack;
    rfinal_ack.source_port = 44444;
    rfinal_ack.destination_port = 9090;
    rfinal_ack.sequence_number = 5001;
    rfinal_ack.acknowledgment_number = rserver_isn + 1;
    rfinal_ack.flags.ack = true;
    rfinal_ack.window_size = 65535;
    auto rfinal_frame = buildFrame(rfinal_ack, clientIp(), local_ip, clientMac(), local_mac);
    auto rparsed_final = parseFrame(rfinal_frame);
    CHECK(rparsed_final.has_value());
    if (rparsed_final) receiver.handle(rkey, rparsed_final->tcp, t0);
    CHECK(receiver.stateOf(rkey) == TcpState::Established);

    // Client sends bytes [5011, 5026) -- a 10-byte gap before them.
    TcpSegment gapped;
    gapped.source_port = 44444;
    gapped.destination_port = 9090;
    gapped.sequence_number = 5001 + 10;
    gapped.acknowledgment_number = rserver_isn + 1;
    gapped.flags.ack = true;
    gapped.window_size = 65535;
    gapped.payload = toBytes("out-of-order-bytes");
    auto gapped_frame = buildFrame(gapped, clientIp(), local_ip, clientMac(), local_mac);
    auto rparsed_gapped = parseFrame(gapped_frame);
    CHECK(rparsed_gapped.has_value());
    std::optional<TcpSegment> gap_ack;
    if (rparsed_gapped) {
        auto result = receiver.handle(rkey, rparsed_gapped->tcp, t0);
        CHECK(result.accepted_payload.empty()); // still gapped
        gap_ack = result.reply;
    }
    CHECK(gap_ack.has_value());
    if (!gap_ack) return wirestack::test::failureCount() == 0 ? 0 : 1;

    auto gap_ack_frame = buildFrame(*gap_ack, local_ip, clientIp(), local_mac, clientMac());
    auto reparsed_gap_ack = parseFrame(gap_ack_frame); // real serialize/parse round trip
    CHECK(reparsed_gap_ack.has_value());
    if (reparsed_gap_ack) {
        CHECK(reparsed_gap_ack->tcp.acknowledgment_number == 5001); // pinned at the gap
        auto opts = parseTcpOptions(reparsed_gap_ack->tcp.options);
        CHECK(std::holds_alternative<TcpParsedOptions>(opts));
        if (auto* parsed_opts = std::get_if<TcpParsedOptions>(&opts)) {
            CHECK(parsed_opts->sack_blocks.size() == 1);
            if (parsed_opts->sack_blocks.size() == 1) {
                CHECK(parsed_opts->sack_blocks[0].left_edge == 5011);
                CHECK(parsed_opts->sack_blocks[0].right_edge ==
                      5011 + static_cast<std::uint32_t>(toBytes("out-of-order-bytes").size()));
            }
        }
    }

    // Fill the gap: bytes released exactly once, byte-exact, and the SACK
    // block disappears from the next report.
    TcpSegment filler;
    filler.source_port = 44444;
    filler.destination_port = 9090;
    filler.sequence_number = 5001;
    filler.acknowledgment_number = rserver_isn + 1;
    filler.flags.ack = true;
    filler.window_size = 65535;
    filler.payload = toBytes("0123456789"); // exactly 10 bytes fills the gap
    auto filler_frame = buildFrame(filler, clientIp(), local_ip, clientMac(), local_mac);
    auto rparsed_filler = parseFrame(filler_frame);
    CHECK(rparsed_filler.has_value());
    if (rparsed_filler) {
        auto result = receiver.handle(rkey, rparsed_filler->tcp, t0);
        auto expected = toBytes("0123456789out-of-order-bytes");
        CHECK(result.accepted_payload == expected); // released once, byte-exact
        if (result.reply) {
            auto opts = parseTcpOptions(result.reply->options);
            if (auto* parsed_opts = std::get_if<TcpParsedOptions>(&opts)) {
                CHECK(parsed_opts->sack_blocks.empty()); // no out-of-order data remains
            }
        }
    }
    auto rsnap = receiver.snapshotOf(rkey);
    CHECK(rsnap.has_value());
    if (rsnap) CHECK(rsnap->rcv_nxt == 5001 + 10 + toBytes("out-of-order-bytes").size());

    return wirestack::test::failureCount() == 0 ? 0 : 1;
}
