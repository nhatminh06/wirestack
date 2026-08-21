// Composed pure-packet-path test for TCP option negotiation: a real
// Ethernet SYN carrying MSS and Window Scale options goes through the
// full parse -> option-parse -> connection-creation -> SYN-ACK chain,
// the reply is serialized and re-parsed, and the handshake completes
// with a scaled final-ACK window. Follows the established composed-test
// shape (no TapDevice, no root).

#include "wirestack/ethernet.hpp"
#include "wirestack/ipv4.hpp"
#include "wirestack/mac_address.hpp"
#include "wirestack/tcp.hpp"
#include "wirestack/tcp_connection.hpp"

#include "test_util.hpp"

using namespace wirestack;

namespace {

std::vector<std::byte> toBytes(std::initializer_list<std::uint8_t> values) {
    std::vector<std::byte> out;
    out.reserve(values.size());
    for (auto v : values) {
        out.push_back(static_cast<std::byte>(v));
    }
    return out;
}

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

    // Real Ethernet SYN carrying MSS=1200 and Window Scale=3.
    TcpSegment syn;
    syn.source_port = 54321;
    syn.destination_port = 8080;
    syn.sequence_number = 1000;
    syn.acknowledgment_number = 0;
    syn.flags.syn = true;
    syn.window_size = 65535;
    syn.urgent_pointer = 0;
    syn.options = toBytes({0x02, 0x04, 0x04, 0xb0,   // MSS 1200
                            0x01, 0x03, 0x03, 0x03}); // NOP, Window Scale 3

    auto syn_frame_bytes = buildFrame(syn, clientIp(), local_ip, clientMac(), local_mac);
    auto parsed_syn = parseFrame(syn_frame_bytes); // validates checksum
    CHECK(parsed_syn.has_value());
    if (!parsed_syn) return wirestack::test::failureCount() == 0 ? 0 : 1;

    auto reply = connections.handle(key, parsed_syn->tcp, t0).reply;
    CHECK(reply.has_value());
    if (!reply) return wirestack::test::failureCount() == 0 ? 0 : 1;

    // Exact SYN-ACK options: MSS is always Wirestack's own local path
    // MSS (1460), never derived from the peer's offered 1200; Window
    // Scale is offered back at Wirestack's fixed local shift (2),
    // independent of the peer's offered shift (3).
    CHECK(reply->options == toBytes({0x02, 0x04, 0x05, 0xb4, 0x01, 0x03, 0x03, 0x02}));
    CHECK(reply->flags.syn && reply->flags.ack);
    CHECK(reply->window_size == 65535); // SYN-ACK window field stays unscaled

    auto snapshot = connections.snapshotOf(key);
    CHECK(snapshot.has_value());
    if (snapshot) {
        CHECK(snapshot->peer_mss == 1200);
        CHECK(snapshot->effective_send_mss == 1200); // min(1460, 1200)
        CHECK(snapshot->peer_window_scale == 3);
        CHECK(snapshot->local_window_scale == 2);
        CHECK(snapshot->window_scaling_enabled);
    }

    // Serialize and re-parse the SYN-ACK through the real wire format.
    auto reply_frame_bytes = buildFrame(*reply, local_ip, clientIp(), local_mac, clientMac());
    auto parsed_reply = parseFrame(reply_frame_bytes);
    CHECK(parsed_reply.has_value());
    if (parsed_reply) {
        CHECK(parsed_reply->eth.destination == clientMac());
        CHECK(parsed_reply->eth.source == local_mac);
        CHECK(parsed_reply->ip.source == local_ip);
        CHECK(parsed_reply->ip.destination == clientIp());
        CHECK(parsed_reply->tcp.options == toBytes({0x02, 0x04, 0x05, 0xb4, 0x01, 0x03, 0x03, 0x02}));
        CHECK(parsed_reply->tcp.sequence_number == reply->sequence_number);
        CHECK(parsed_reply->tcp.acknowledgment_number == syn.sequence_number + 1);
    }

    // Final ACK, with a scaled window field (500 << 3 = 4000 logical).
    TcpSegment final_ack;
    final_ack.source_port = syn.source_port;
    final_ack.destination_port = syn.destination_port;
    final_ack.sequence_number = syn.sequence_number + 1;
    final_ack.acknowledgment_number = reply->sequence_number + 1;
    final_ack.flags.ack = true;
    final_ack.window_size = 500;
    final_ack.urgent_pointer = 0;

    auto final_ack_frame = buildFrame(final_ack, clientIp(), local_ip, clientMac(), local_mac);
    auto parsed_final_ack = parseFrame(final_ack_frame);
    CHECK(parsed_final_ack.has_value());
    if (parsed_final_ack) {
        connections.handle(key, parsed_final_ack->tcp, t0);
    }
    CHECK(connections.stateOf(key) == TcpState::Established);

    auto after = connections.snapshotOf(key);
    CHECK(after.has_value());
    if (after) {
        CHECK(after->snd_wnd == 4000); // 500 << 3, decoded post-handshake
    }

    return wirestack::test::failureCount() == 0 ? 0 : 1;
}
