// Composed pure-packet-path test for adaptive RTO estimation: a real
// negotiated connection is driven entirely by a synthetic monotonic
// clock (no sleep, no TAP, no root) through a first RTT sample, a
// second sample matching the task's own hand-verified vector, a
// simulated loss and retransmission proving Karn's rule withholds a
// sample, and a final clean exchange proving the estimator recovers
// away from the backed-off timeout. Follows the established
// composed-test shape.

#include "wirestack/ethernet.hpp"
#include "wirestack/ipv4.hpp"
#include "wirestack/mac_address.hpp"
#include "wirestack/tcp.hpp"
#include "wirestack/tcp_connection.hpp"

#include "test_util.hpp"

using namespace wirestack;
using namespace std::chrono_literals;

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

    // --- Handshake: SYN-ACK sent at t0, never retransmitted ---

    TcpSegment syn;
    syn.source_port = 54321;
    syn.destination_port = 8080;
    syn.sequence_number = 1000;
    syn.acknowledgment_number = 0;
    syn.flags.syn = true;
    syn.window_size = 65535;
    syn.urgent_pointer = 0;
    syn.options = {std::byte{2}, std::byte{4}, std::byte{0x05}, std::byte{0xb4}};

    auto syn_ack = connections.handle(key, syn, t0).reply;
    CHECK(syn_ack.has_value());
    if (!syn_ack) return wirestack::test::failureCount() == 0 ? 0 : 1;
    std::uint32_t server_isn = syn_ack->sequence_number;

    auto before_handshake = connections.snapshotOf(key);
    CHECK(before_handshake.has_value());
    if (before_handshake) CHECK(!before_handshake->has_rtt_sample);

    // Final ACK arrives 200ms later -- first RTT sample: R=200ms ->
    // SRTT=200ms, RTTVAR=100ms, raw RTO=600ms, clamped to the 1s floor.
    auto handshake_ack_time = t0 + 200ms;
    TcpSegment final_ack;
    final_ack.source_port = syn.source_port;
    final_ack.destination_port = syn.destination_port;
    final_ack.sequence_number = syn.sequence_number + 1;
    final_ack.acknowledgment_number = server_isn + 1;
    final_ack.flags.ack = true;
    final_ack.window_size = 65535;

    auto final_ack_frame = buildFrame(final_ack, clientIp(), local_ip, clientMac(), local_mac);
    auto parsed_final_ack = parseFrame(final_ack_frame);
    CHECK(parsed_final_ack.has_value());
    if (parsed_final_ack) connections.handle(key, parsed_final_ack->tcp, handshake_ack_time);
    CHECK(connections.stateOf(key) == TcpState::Established);

    auto after_first_sample = connections.snapshotOf(key);
    CHECK(after_first_sample.has_value());
    if (after_first_sample) {
        CHECK(after_first_sample->has_rtt_sample);
        CHECK(after_first_sample->srtt == 200ms);
        CHECK(after_first_sample->rttvar == 100ms);
        CHECK(after_first_sample->current_rto == 1000ms);
    }

    // --- Second sample: clean data sent right after the handshake, ACKed
    //     1000ms later. Using the OLD srtt/rttvar (200ms/100ms): diff=800ms,
    //     RTTVAR=(3*100+800)/4=275ms, SRTT=(7*200+1000)/8=300ms,
    //     RTO=300+4*275=1400ms -- matches the task's exact second-sample
    //     vector. ---

    auto data_sent_time = handshake_ack_time;
    auto payload_text = toBytes("adaptive rto");
    auto sent = connections.makeOutgoingData(key, payload_text, data_sent_time);
    CHECK(sent.segments.size() == 1);
    if (sent.segments.size() != 1) return wirestack::test::failureCount() == 0 ? 0 : 1;
    const auto& data_segment = sent.segments.front();

    auto data_ack_time = data_sent_time + 1000ms;
    TcpSegment ack_of_data;
    ack_of_data.source_port = syn.source_port;
    ack_of_data.destination_port = syn.destination_port;
    ack_of_data.sequence_number = syn.sequence_number + 1;
    ack_of_data.acknowledgment_number =
        data_segment.sequence_number + static_cast<std::uint32_t>(data_segment.payload.size());
    ack_of_data.flags.ack = true;
    ack_of_data.window_size = 65535;

    auto ack_of_data_frame = buildFrame(ack_of_data, clientIp(), local_ip, clientMac(), local_mac);
    auto parsed_ack_of_data = parseFrame(ack_of_data_frame);
    CHECK(parsed_ack_of_data.has_value());
    if (parsed_ack_of_data) connections.handle(key, parsed_ack_of_data->tcp, data_ack_time);

    auto after_second_sample = connections.snapshotOf(key);
    CHECK(after_second_sample.has_value());
    if (after_second_sample) {
        CHECK(after_second_sample->rttvar == 275ms);
        CHECK(after_second_sample->srtt == 300ms);
        CHECK(after_second_sample->current_rto == 1400ms);
    }

    // --- Loss and retransmission: send more data, never deliver the ACK
    //     until after the (current_rto=1400ms) deadline fires. The
    //     retransmission doubles the entry's timeout to 2800ms and the
    //     connection's current_rto reflects that backed-off value. ---

    auto second_send_time = data_ack_time;
    auto second_payload = toBytes("karn rule check");
    auto second_sent = connections.makeOutgoingData(key, second_payload, second_send_time);
    CHECK(second_sent.segments.size() == 1);
    if (second_sent.segments.size() != 1) return wirestack::test::failureCount() == 0 ? 0 : 1;
    const auto& lost_segment = second_sent.segments.front();

    auto retransmit_deadline = second_send_time + 1400ms;
    auto due = connections.pollRetransmissions(retransmit_deadline);
    CHECK(due.retransmissions.size() == 1);
    if (due.retransmissions.size() == 1) {
        CHECK(due.retransmissions[0].segment.sequence_number == lost_segment.sequence_number);
        CHECK(due.retransmissions[0].segment.payload == second_payload);
    }

    auto after_retransmit = connections.snapshotOf(key);
    CHECK(after_retransmit.has_value());
    if (after_retransmit) {
        CHECK(after_retransmit->current_rto == 2800ms);
        CHECK(after_retransmit->srtt == 300ms);   // unchanged -- no sample yet from this loss
        CHECK(after_retransmit->rttvar == 275ms); // unchanged
    }

    // ACK of the retransmitted segment must not produce a sample (Karn's
    // rule): current_rto stays at the backed-off 2800ms.
    auto ack_of_retransmit_time = retransmit_deadline + 300ms;
    TcpSegment ack_of_retransmit;
    ack_of_retransmit.source_port = syn.source_port;
    ack_of_retransmit.destination_port = syn.destination_port;
    ack_of_retransmit.sequence_number = syn.sequence_number + 1;
    ack_of_retransmit.acknowledgment_number =
        lost_segment.sequence_number + static_cast<std::uint32_t>(lost_segment.payload.size());
    ack_of_retransmit.flags.ack = true;
    ack_of_retransmit.window_size = 65535;

    auto ack_of_retransmit_frame =
        buildFrame(ack_of_retransmit, clientIp(), local_ip, clientMac(), local_mac);
    auto parsed_ack_of_retransmit = parseFrame(ack_of_retransmit_frame);
    CHECK(parsed_ack_of_retransmit.has_value());
    if (parsed_ack_of_retransmit) {
        connections.handle(key, parsed_ack_of_retransmit->tcp, ack_of_retransmit_time);
    }

    auto after_karn = connections.snapshotOf(key);
    CHECK(after_karn.has_value());
    if (after_karn) {
        CHECK(after_karn->current_rto == 2800ms); // untouched by Karn's rule
        CHECK(after_karn->srtt == 300ms);
        CHECK(after_karn->rttvar == 275ms);
    }

    // --- Recovery: a fresh, never-retransmitted send starts its own
    //     timeout at the backed-off current_rto (2800ms), but a clean ACK
    //     400ms later produces a real sample that pulls the estimate back
    //     down: RTTVAR=(3*275+100)/4=231.25ms, SRTT=(7*300+400)/8=312.5ms,
    //     RTO=312.5+4*231.25=1237.5ms. Integer duration arithmetic keeps
    //     the fractional millisecond exactly (nanosecond granularity). ---

    auto third_send_time = ack_of_retransmit_time;
    auto third_payload = toBytes("recovered");
    auto third_sent = connections.makeOutgoingData(key, third_payload, third_send_time);
    CHECK(third_sent.segments.size() == 1);
    if (third_sent.segments.size() != 1) return wirestack::test::failureCount() == 0 ? 0 : 1;
    const auto& fresh_segment = third_sent.segments.front();

    auto next_deadline = connections.snapshotOf(key);
    CHECK(next_deadline.has_value());
    if (next_deadline) {
        CHECK(next_deadline->current_rto == 2800ms); // new send starts from the backed-off value
    }

    auto third_ack_time = third_send_time + 400ms;
    TcpSegment ack_of_third;
    ack_of_third.source_port = syn.source_port;
    ack_of_third.destination_port = syn.destination_port;
    ack_of_third.sequence_number = syn.sequence_number + 1;
    ack_of_third.acknowledgment_number =
        fresh_segment.sequence_number + static_cast<std::uint32_t>(fresh_segment.payload.size());
    ack_of_third.flags.ack = true;
    ack_of_third.window_size = 65535;

    auto ack_of_third_frame = buildFrame(ack_of_third, clientIp(), local_ip, clientMac(), local_mac);
    auto parsed_ack_of_third = parseFrame(ack_of_third_frame);
    CHECK(parsed_ack_of_third.has_value());
    if (parsed_ack_of_third) connections.handle(key, parsed_ack_of_third->tcp, third_ack_time);

    auto final_snapshot = connections.snapshotOf(key);
    CHECK(final_snapshot.has_value());
    if (final_snapshot) {
        CHECK(final_snapshot->rttvar == std::chrono::microseconds(231250));
        CHECK(final_snapshot->srtt == std::chrono::microseconds(312500));
        CHECK(final_snapshot->current_rto == std::chrono::microseconds(1237500));
        CHECK(final_snapshot->current_rto < 2800ms); // estimator recovered from the backoff
        CHECK(final_snapshot->pending_count == 0);
        CHECK(final_snapshot->snd_una == final_snapshot->snd_nxt);
    }

    return wirestack::test::failureCount() == 0 ? 0 : 1;
}
