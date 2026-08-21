// Composed pure-packet-path test for zero-window persist: a real
// handshake, a real zero-window ACK with no outstanding sequence space,
// a queued binary payload, a synthetic-clock-driven persist probe
// serialized/re-parsed through the real wire format, exact backoff, and
// a real window-reopening ACK that cancels persist and sends normal
// data starting with the exact byte the probe used. No TapDevice, no
// root, no sleeping.

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

    // --- Real handshake, immediately advertising a zero window. ---

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
    std::uint32_t server_isn = syn_ack->sequence_number;

    TcpSegment final_ack;
    final_ack.source_port = 54321;
    final_ack.destination_port = 8080;
    final_ack.sequence_number = 1001;
    final_ack.acknowledgment_number = server_isn + 1;
    final_ack.flags.ack = true;
    final_ack.window_size = 0; // zero window from the very start

    auto final_ack_frame = buildFrame(final_ack, clientIp(), local_ip, clientMac(), local_mac);
    auto parsed_final_ack = parseFrame(final_ack_frame);
    CHECK(parsed_final_ack.has_value());
    if (parsed_final_ack) connections.handle(key, parsed_final_ack->tcp, t0);
    CHECK(connections.stateOf(key) == TcpState::Established);

    auto after_handshake = connections.snapshotOf(key);
    CHECK(after_handshake.has_value());
    if (after_handshake) {
        CHECK(after_handshake->snd_wnd == 0);
        CHECK(after_handshake->snd_una == after_handshake->snd_nxt); // nothing outstanding
    }

    // --- Enqueue binary application data: no normal data segment is
    //     emitted (zero window). ---

    std::vector<std::byte> data = {std::byte{0x00}, std::byte{0x01}, std::byte{0x7f},
                                     std::byte{0x80}, std::byte{0xff}, std::byte{0x0a}};
    auto sent = connections.makeOutgoingData(key, data, t0);
    CHECK(!sent.error);
    CHECK(sent.segments.empty());

    auto armed = connections.snapshotOf(key);
    CHECK(armed.has_value());
    if (armed) {
        CHECK(armed->persist_armed);
        CHECK(armed->persist_deadline.has_value());
        if (armed->persist_deadline) {
            CHECK(*armed->persist_deadline == t0 + kInitialPersistInterval);
        }
    }

    // --- No probe before the deadline; exactly one at the deadline. ---

    auto too_early = connections.pollPersistProbes(t0 + kInitialPersistInterval -
                                                     std::chrono::milliseconds(1));
    CHECK(too_early.probes.empty());

    auto due = connections.pollPersistProbes(t0 + kInitialPersistInterval);
    CHECK(due.probes.size() == 1);
    if (due.probes.size() != 1) return wirestack::test::failureCount() == 0 ? 0 : 1;

    const TcpSegment& probe = due.probes[0].segment;
    CHECK(probe.sequence_number == server_isn + 1 - 1); // snd_nxt - 1
    CHECK(probe.acknowledgment_number == 1001);
    CHECK(probe.flags.ack);
    CHECK(!probe.flags.syn && !probe.flags.fin && !probe.flags.rst);
    CHECK(probe.payload.size() == 1);
    CHECK(probe.payload.front() == data.front());
    CHECK(probe.options.empty());

    // Serialize and re-parse through the real wire format.
    auto probe_frame = buildFrame(probe, local_ip, clientIp(), local_mac, clientMac());
    auto parsed_probe = parseFrame(probe_frame); // validates both checksums
    CHECK(parsed_probe.has_value());
    if (parsed_probe) {
        CHECK(parsed_probe->tcp.sequence_number == probe.sequence_number);
        CHECK(parsed_probe->tcp.payload == probe.payload);
        CHECK(parsed_probe->eth.destination == clientMac());
        CHECK(parsed_probe->ip.destination == clientIp());
    }

    // TCP state and queue accounting are unchanged by the probe.
    auto after_probe = connections.snapshotOf(key);
    CHECK(after_probe.has_value() && armed.has_value());
    if (after_probe && armed) {
        CHECK(after_probe->snd_nxt == armed->snd_nxt);
        CHECK(after_probe->snd_una == armed->snd_una);
        CHECK(after_probe->unsent_bytes == armed->unsent_bytes);
        CHECK(after_probe->owned_bytes == armed->owned_bytes);
        CHECK(after_probe->pending_count == armed->pending_count);
        CHECK(after_probe->cwnd == armed->cwnd);
    }

    // --- Another zero-window ACK: next deadline follows backoff (2s). ---

    TcpSegment zero_ack_again;
    zero_ack_again.source_port = 54321;
    zero_ack_again.destination_port = 8080;
    zero_ack_again.sequence_number = 1001;
    zero_ack_again.acknowledgment_number = server_isn + 1;
    zero_ack_again.flags.ack = true;
    zero_ack_again.window_size = 0;
    auto zero_ack_frame =
        buildFrame(zero_ack_again, clientIp(), local_ip, clientMac(), local_mac);
    auto parsed_zero_ack = parseFrame(zero_ack_frame);
    CHECK(parsed_zero_ack.has_value());
    if (parsed_zero_ack) connections.handle(key, parsed_zero_ack->tcp, t0 + kInitialPersistInterval);

    // Next deadline is t0 + 1s + 2s (backoff doubles to 2s after the
    // first probe) = t0 + 3s, not t0 + 2s -- the zero-window ACK that
    // changed nothing must not reset the backoff back to 1s.
    auto second_deadline = t0 + kInitialPersistInterval + std::chrono::milliseconds(2000);
    auto still_early = connections.pollPersistProbes(second_deadline - std::chrono::milliseconds(1));
    CHECK(still_early.probes.empty());

    auto second_probe_due = connections.pollPersistProbes(second_deadline);
    CHECK(second_probe_due.probes.size() == 1);

    // --- A fresh nonzero-window update cancels persist and sends normal
    //     data immediately from the unchanged snd_nxt, starting with the
    //     exact byte the probe used. ---

    TcpSegment window_open;
    window_open.source_port = 54321;
    window_open.destination_port = 8080;
    window_open.sequence_number = 1001;
    window_open.acknowledgment_number = server_isn + 1;
    window_open.flags.ack = true;
    window_open.window_size = 65535;
    auto window_open_frame =
        buildFrame(window_open, clientIp(), local_ip, clientMac(), local_mac);
    auto parsed_window_open = parseFrame(window_open_frame);
    CHECK(parsed_window_open.has_value());
    if (!parsed_window_open) return wirestack::test::failureCount() == 0 ? 0 : 1;

    auto snapshot_before_open = connections.snapshotOf(key);
    CHECK(snapshot_before_open.has_value());

    auto reopen_result = connections.handle(key, parsed_window_open->tcp, t0);
    CHECK(reopen_result.scheduled.size() == 1);
    if (reopen_result.scheduled.size() == 1) {
        const TcpSegment& normal = reopen_result.scheduled.front();
        CHECK(normal.sequence_number ==
              (snapshot_before_open ? snapshot_before_open->snd_nxt : 0));
        CHECK(normal.payload.size() == data.size());
        CHECK(normal.payload == data);
        CHECK(normal.payload.front() == probe.payload.front()); // same first byte as the probe
        auto frame_bytes = buildFrame(normal, local_ip, clientIp(), local_mac, clientMac());
        auto parsed_normal = parseFrame(frame_bytes);
        CHECK(parsed_normal.has_value());
    }

    auto after_reopen = connections.snapshotOf(key);
    CHECK(after_reopen.has_value());
    if (after_reopen) {
        CHECK(!after_reopen->persist_armed); // cancelled
        CHECK(after_reopen->unsent_bytes == 0);
    }

    // --- ACK the data and prove normal retirement. ---

    if (reopen_result.scheduled.size() == 1) {
        TcpSegment ack_of_data;
        ack_of_data.source_port = 54321;
        ack_of_data.destination_port = 8080;
        ack_of_data.sequence_number = 1001;
        ack_of_data.acknowledgment_number =
            reopen_result.scheduled.front().sequence_number +
            static_cast<std::uint32_t>(reopen_result.scheduled.front().payload.size());
        ack_of_data.flags.ack = true;
        ack_of_data.window_size = 65535;
        auto ack_of_data_frame =
            buildFrame(ack_of_data, clientIp(), local_ip, clientMac(), local_mac);
        auto parsed_ack_of_data = parseFrame(ack_of_data_frame);
        CHECK(parsed_ack_of_data.has_value());
        if (parsed_ack_of_data) connections.handle(key, parsed_ack_of_data->tcp, t0);

        auto final_snapshot = connections.snapshotOf(key);
        CHECK(final_snapshot.has_value());
        if (final_snapshot) {
            CHECK(final_snapshot->snd_una == final_snapshot->snd_nxt);
            CHECK(final_snapshot->owned_bytes == 0);
            CHECK(final_snapshot->pending_count == 0);
        }
    }

    return wirestack::test::failureCount() == 0 ? 0 : 1;
}
