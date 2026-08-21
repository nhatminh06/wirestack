// Composed pure-packet-path test for the bounded send buffer and
// ACK-driven scheduler: a real handshake, a deliberately small peer
// receive window, a payload larger than both one MSS and the initial
// allowance, and a sequence of real cumulative ACKs that drain the
// queue entirely across several scheduling passes. No TapDevice, no
// root, no sleeping.

#include <algorithm>

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

std::vector<std::byte> makeFilledPayload(std::size_t length) {
    std::vector<std::byte> out(length);
    for (std::size_t i = 0; i < length; ++i) {
        out[i] = static_cast<std::byte>(i % 256);
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

// Serializes and re-parses each segment (proving MAC/IPv4/TCP direction,
// both checksums, and the MSS boundary), and returns the reconstructed
// payload bytes in order.
std::vector<std::byte> verifyAndReconstruct(const std::vector<TcpSegment>& segments,
                                              Ipv4Address local_ip, Ipv4Address remote_ip,
                                              MacAddress local_mac, MacAddress remote_mac,
                                              std::uint16_t mss) {
    std::vector<std::byte> reconstructed;
    for (const auto& segment : segments) {
        CHECK(segment.payload.size() <= mss);
        auto frame_bytes = buildFrame(segment, local_ip, remote_ip, local_mac, remote_mac);
        auto parsed = parseFrame(frame_bytes); // validates both checksums
        CHECK(parsed.has_value());
        if (!parsed) continue;
        CHECK(parsed->eth.source == local_mac);
        CHECK(parsed->eth.destination == remote_mac);
        CHECK(parsed->ip.source == local_ip);
        CHECK(parsed->ip.destination == remote_ip);
        CHECK(parsed->tcp.destination_port == 54321);
        CHECK(parsed->tcp.source_port == 8080);
        CHECK(parsed->tcp.sequence_number == segment.sequence_number);
        CHECK(parsed->tcp.payload == segment.payload);
        reconstructed.insert(reconstructed.end(), parsed->tcp.payload.begin(),
                              parsed->tcp.payload.end());
    }
    return reconstructed;
}

} // namespace

int main() {
    auto local_ip = *Ipv4Address::parse("10.0.0.2");
    auto local_mac = *MacAddress::parse("02:00:00:00:00:02");
    constexpr TcpClock::time_point t0{};
    constexpr std::uint16_t kSmallWindow = 300; // well under one MSS (1460)

    TcpConnectionTable connections(8080);
    TcpConnectionKey key{local_ip, 8080, clientIp(), 54321};

    // --- Real handshake. ---

    TcpSegment syn;
    syn.source_port = 54321;
    syn.destination_port = 8080;
    syn.sequence_number = 1000;
    syn.acknowledgment_number = 0;
    syn.flags.syn = true;
    syn.window_size = 65535;
    syn.urgent_pointer = 0;
    syn.options = {std::byte{2}, std::byte{4}, std::byte{0x05}, std::byte{0xb4}}; // MSS 1460

    auto syn_frame = buildFrame(syn, clientIp(), local_ip, clientMac(), local_mac);
    auto parsed_syn = parseFrame(syn_frame);
    CHECK(parsed_syn.has_value());
    if (!parsed_syn) return wirestack::test::failureCount() == 0 ? 0 : 1;

    auto syn_ack = connections.handle(key, parsed_syn->tcp, t0).reply;
    CHECK(syn_ack.has_value());
    if (!syn_ack) return wirestack::test::failureCount() == 0 ? 0 : 1;
    std::uint32_t server_isn = syn_ack->sequence_number;

    // Handshake-completing ACK, deliberately advertising a small window.
    TcpSegment final_ack;
    final_ack.source_port = 54321;
    final_ack.destination_port = 8080;
    final_ack.sequence_number = 1001;
    final_ack.acknowledgment_number = server_isn + 1;
    final_ack.flags.ack = true;
    final_ack.window_size = kSmallWindow;

    auto final_ack_frame = buildFrame(final_ack, clientIp(), local_ip, clientMac(), local_mac);
    auto parsed_final_ack = parseFrame(final_ack_frame);
    CHECK(parsed_final_ack.has_value());
    if (parsed_final_ack) connections.handle(key, parsed_final_ack->tcp, t0);
    CHECK(connections.stateOf(key) == TcpState::Established);

    // --- Enqueue a payload larger than one MSS and larger than the
    //     initial send allowance (kSmallWindow). ---

    constexpr std::size_t kTotalPayload = 5000; // > 3 * MSS, >> kSmallWindow
    auto payload = makeFilledPayload(kTotalPayload);

    auto initial_sent = connections.makeOutgoingData(key, payload, t0);
    CHECK(!initial_sent.error);
    CHECK(initial_sent.bytes_accepted == kTotalPayload);

    std::size_t initial_bytes = 0;
    for (const auto& seg : initial_sent.segments) initial_bytes += seg.payload.size();
    CHECK(initial_bytes == kSmallWindow); // stops at the exact allowance

    std::vector<std::byte> reconstructed =
        verifyAndReconstruct(initial_sent.segments, local_ip, clientIp(), local_mac, clientMac(),
                              kTcpMss);
    CHECK(reconstructed.size() == kSmallWindow);

    auto snapshot = connections.snapshotOf(key);
    CHECK(snapshot.has_value());
    if (snapshot) {
        CHECK(snapshot->unsent_bytes == kTotalPayload - kSmallWindow);
        CHECK(snapshot->owned_bytes == kTotalPayload);
    }

    // --- Repeatedly ACK the outstanding bytes and open the window a
    //     little further each time, verifying the scheduler produces new
    //     segments immediately from each real cumulative ACK, until the
    //     entire payload has entered sequence space. ---

    std::uint32_t client_seq = 1001;
    std::uint32_t payload_end = server_isn + 1 + static_cast<std::uint32_t>(kTotalPayload);
    std::size_t total_acked = kSmallWindow;
    int rounds = 0;
    while (total_acked < kTotalPayload) {
        auto current = connections.snapshotOf(key);
        CHECK(current.has_value());
        if (!current) break;

        // Small, non-wrapping values throughout this test -- plain
        // unsigned min is correct here.
        std::uint32_t ack_number = std::min(current->snd_una + kSmallWindow, payload_end);

        TcpSegment client_ack;
        client_ack.source_port = 54321;
        client_ack.destination_port = 8080;
        client_ack.sequence_number = client_seq;
        client_ack.acknowledgment_number = ack_number;
        client_ack.flags.ack = true;
        client_ack.window_size = kSmallWindow;

        auto ack_frame = buildFrame(client_ack, clientIp(), local_ip, clientMac(), local_mac);
        auto parsed_ack = parseFrame(ack_frame);
        CHECK(parsed_ack.has_value());
        if (!parsed_ack) break;

        auto ack_result = connections.handle(key, parsed_ack->tcp, t0);
        auto newly = verifyAndReconstruct(ack_result.scheduled, local_ip, clientIp(), local_mac,
                                           clientMac(), kTcpMss);
        reconstructed.insert(reconstructed.end(), newly.begin(), newly.end());

        auto after = connections.snapshotOf(key);
        CHECK(after.has_value());
        total_acked = after ? static_cast<std::size_t>(after->snd_una - (server_isn + 1)) : 0;

        ++rounds;
        CHECK(rounds < 50); // safety bound against an infinite loop on a bug
        if (rounds >= 50) break;
    }

    CHECK(reconstructed.size() == kTotalPayload);
    CHECK(reconstructed == payload);

    // --- Cumulatively ACK everything; send-buffer ownership returns to zero. ---

    auto final_snapshot = connections.snapshotOf(key);
    CHECK(final_snapshot.has_value());
    if (final_snapshot) {
        CHECK(final_snapshot->unsent_bytes == 0);
        CHECK(final_snapshot->owned_bytes == 0);
        CHECK(final_snapshot->snd_una == final_snapshot->snd_nxt);
        CHECK(final_snapshot->pending_count == 0);
    }

    return wirestack::test::failureCount() == 0 ? 0 : 1;
}
