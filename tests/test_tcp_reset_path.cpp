// Composed pure-packet-path tests for TCP reset handling: a closed-port
// reset built and sent through the real serializers, and an acceptable
// inbound RST against an established connection. Follows
// test_tcp_data_path.cpp's shape (no TapDevice, no root).

#include "wirestack/ethernet.hpp"
#include "wirestack/ipv4.hpp"
#include "wirestack/mac_address.hpp"
#include "wirestack/tcp.hpp"
#include "wirestack/tcp_connection.hpp"

#include "test_util.hpp"

using namespace wirestack;

namespace {

std::vector<std::byte> knownSynFrame() {
    std::vector<std::byte> out;
    for (std::uint8_t v : {
             0x02, 0x00, 0x00, 0x00, 0x00, 0x02, // Ethernet destination: Wirestack
             0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, // Ethernet source: host
             0x08, 0x00,                         // EtherType: IPv4
             0x45, 0x00, 0x00, 0x28, 0x1c, 0x46, 0x40, 0x00, 0x40, 0x06, 0x0a, 0x88, 0x0a, 0x00,
             0x00, 0x01, 0x0a, 0x00, 0x00, 0x02, 0xd4, 0x31, 0x1f, 0x90, 0x00, 0x00, 0x03, 0xe8,
             0x00, 0x00, 0x00, 0x00, 0x50, 0x02, 0xff, 0xff, 0xa4, 0x36, 0x00, 0x00,
         }) {
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

std::optional<TcpSegment> parseFrame(std::span<const std::byte> bytes) {
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

    return *segment;
}

} // namespace

int main() {
    auto local_ip = *Ipv4Address::parse("10.0.0.2");
    auto local_mac = *MacAddress::parse("02:00:00:00:00:02");
    constexpr TcpClock::time_point t0{};

    // --- Closed-port reset ---
    {
        TcpConnectionTable connections(8080); // 8081 below is unbound

        TcpSegment probe;
        probe.source_port = 54321;
        probe.destination_port = 8081;
        probe.sequence_number = 42;
        probe.acknowledgment_number = 0;
        probe.flags.syn = true;
        probe.window_size = 65535;

        auto probe_frame = buildFrame(probe, clientIp(), local_ip, clientMac(), local_mac);
        auto parsed_probe = parseFrame(probe_frame);
        CHECK(parsed_probe.has_value());
        if (!parsed_probe) return wirestack::test::failureCount() == 0 ? 0 : 1;

        TcpConnectionKey key{local_ip, 8081, clientIp(), 54321};
        auto reply = connections.handle(key, *parsed_probe, t0).reply;
        CHECK(reply.has_value());
        if (!reply) return wirestack::test::failureCount() == 0 ? 0 : 1;
        CHECK(reply->flags.rst);
        CHECK(reply->flags.ack);
        CHECK(reply->acknowledgment_number == 43); // probe seq + SYN's 1
        CHECK(!connections.stateOf(key).has_value());

        auto reset_frame = buildFrame(*reply, local_ip, clientIp(), local_mac, clientMac());
        auto parsed_reset = parseFrame(reset_frame);
        CHECK(parsed_reset.has_value());
        if (parsed_reset) {
            CHECK(parsed_reset->flags.rst);
            CHECK(parsed_reset->source_port == 8081);
            CHECK(parsed_reset->destination_port == 54321);
            CHECK(parsed_reset->sequence_number == 0);
            CHECK(parsed_reset->acknowledgment_number == 43);
        }
    }

    // --- Inbound RST against an established connection ---
    {
        TcpConnectionTable connections(8080);
        TcpConnectionKey key{local_ip, 8080, clientIp(), 54321};

        auto syn = parseFrame(knownSynFrame());
        CHECK(syn.has_value());
        if (!syn) return wirestack::test::failureCount() == 0 ? 0 : 1;

        auto syn_ack = connections.handle(key, *syn, t0).reply;
        CHECK(syn_ack.has_value());
        if (!syn_ack) return wirestack::test::failureCount() == 0 ? 0 : 1;
        std::uint32_t server_isn = syn_ack->sequence_number;

        TcpSegment final_ack;
        final_ack.source_port = syn->source_port;
        final_ack.destination_port = syn->destination_port;
        final_ack.sequence_number = syn->sequence_number + 1;
        final_ack.acknowledgment_number = server_isn + 1;
        final_ack.flags.ack = true;
        final_ack.window_size = 65535;
        connections.handle(key, final_ack, t0);
        CHECK(connections.stateOf(key) == TcpState::Established);

        // Leave a pending outgoing segment so removal-on-RST is provable.
        auto sent = connections.makeOutgoingData(key, std::vector<std::byte>{std::byte{0x42}}, t0);
        CHECK(!sent.segments.empty());

        TcpSegment client_rst;
        client_rst.source_port = syn->source_port;
        client_rst.destination_port = syn->destination_port;
        client_rst.sequence_number = syn->sequence_number + 1;
        client_rst.flags.rst = true;
        client_rst.window_size = 65535;

        auto rst_frame = buildFrame(client_rst, clientIp(), local_ip, clientMac(), local_mac);
        auto parsed_rst = parseFrame(rst_frame);
        CHECK(parsed_rst.has_value());
        if (!parsed_rst) return wirestack::test::failureCount() == 0 ? 0 : 1;

        auto result = connections.handle(key, *parsed_rst, t0);
        CHECK(result.connection_reset);
        CHECK(!result.reply.has_value());
        CHECK(!connections.stateOf(key).has_value());

        // No retransmission ever fires for the removed connection.
        auto due = connections.pollRetransmissions(t0 + kMaxRto * kMaxRetransmits);
        CHECK(due.retransmissions.empty());
    }

    return wirestack::test::failureCount() == 0 ? 0 : 1;
}
