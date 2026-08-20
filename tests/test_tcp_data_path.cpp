// Composed pure-packet-path test for established-connection data
// transfer, following test_tcp_handshake_path.cpp's shape (no TapDevice
// involved). The connection is established using the same known SYN
// frame and real handshake logic; the client data segment is then built
// as a TcpSegment and pushed through Wirestack's own serializers to
// produce a real Ethernet frame -- legitimate here because this test
// proves the established-data pipeline, not checksum-algorithm
// correctness (already independently proven via known vectors in
// test_tcp.cpp).

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

std::vector<std::byte> toBytes(std::string_view text) {
    std::vector<std::byte> out;
    out.reserve(text.size());
    for (char c : text) {
        out.push_back(static_cast<std::byte>(static_cast<unsigned char>(c)));
    }
    return out;
}

// Same known SYN frame as test_tcp_handshake_path.cpp: client
// 10.0.0.1/aa:bb:cc:dd:ee:ff:54321, server 10.0.0.2/02:00:00:00:00:02:8080,
// client_isn=1000.
std::vector<std::byte> knownSynFrame() {
    return toBytes({
        0x02, 0x00, 0x00, 0x00, 0x00, 0x02, // Ethernet destination: Wirestack
        0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, // Ethernet source: host
        0x08, 0x00,                         // EtherType: IPv4
        0x45, 0x00, 0x00, 0x28, 0x1c, 0x46, 0x40, 0x00, 0x40, 0x06, 0x0a, 0x88, 0x0a, 0x00, 0x00,
        0x01, 0x0a, 0x00, 0x00, 0x02,
        0xd4, 0x31, 0x1f, 0x90, 0x00, 0x00, 0x03, 0xe8, 0x00, 0x00, 0x00, 0x00, 0x50, 0x02, 0xff,
        0xff, 0xa4, 0x36, 0x00, 0x00,
    });
}

MacAddress clientMac() {
    return *MacAddress::parse("aa:bb:cc:dd:ee:ff");
}
Ipv4Address clientIp() {
    return *Ipv4Address::parse("10.0.0.1");
}

// Serializes `segment` as if sent by `source_ip`/`source_mac` to
// `dest_ip`/`dest_mac`, using Wirestack's own serializers.
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

} // namespace

int main() {
    auto local_ip = *Ipv4Address::parse("10.0.0.2");
    auto local_mac = *MacAddress::parse("02:00:00:00:00:02");
    TcpConnectionTable connections(8080);
    constexpr TcpClock::time_point t0{};

    // Establish the connection using the real handshake path.
    auto eth_result = parseEthernetFrame(knownSynFrame());
    auto* eth_frame = std::get_if<EthernetFrame>(&eth_result);
    CHECK(eth_frame != nullptr);
    if (eth_frame == nullptr) return wirestack::test::failureCount() == 0 ? 0 : 1;

    auto ip_result = parseIpv4Packet(eth_frame->payload);
    auto* ip_packet = std::get_if<Ipv4Packet>(&ip_result);
    CHECK(ip_packet != nullptr);
    if (ip_packet == nullptr) return wirestack::test::failureCount() == 0 ? 0 : 1;

    auto tcp_result = parseTcpSegment(ip_packet->payload, ip_packet->source, ip_packet->destination);
    auto* syn = std::get_if<TcpSegment>(&tcp_result);
    CHECK(syn != nullptr);
    if (syn == nullptr) return wirestack::test::failureCount() == 0 ? 0 : 1;

    TcpConnectionKey key{local_ip, syn->destination_port, ip_packet->source, syn->source_port};
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
    final_ack.urgent_pointer = 0;
    connections.handle(key, final_ack, t0);
    CHECK(connections.stateOf(key) == TcpState::Established);

    // Build a real Ethernet client-data frame carrying "hello wirestack".
    auto payload_text = toBytes("hello wirestack");
    TcpSegment client_data;
    client_data.source_port = syn->source_port;
    client_data.destination_port = syn->destination_port;
    client_data.sequence_number = syn->sequence_number + 1;
    client_data.acknowledgment_number = server_isn + 1;
    client_data.flags.psh = true;
    client_data.flags.ack = true;
    client_data.window_size = 65535;
    client_data.urgent_pointer = 0;
    client_data.payload = payload_text;

    auto client_frame_bytes =
        buildFrame(client_data, clientIp(), local_ip, clientMac(), local_mac);

    // Push the frame through the full parse chain.
    auto parsed_eth = parseEthernetFrame(client_frame_bytes);
    auto* parsed_eth_frame = std::get_if<EthernetFrame>(&parsed_eth);
    CHECK(parsed_eth_frame != nullptr);
    if (parsed_eth_frame == nullptr) return wirestack::test::failureCount() == 0 ? 0 : 1;

    auto parsed_ip = parseIpv4Packet(parsed_eth_frame->payload);
    auto* parsed_ip_packet = std::get_if<Ipv4Packet>(&parsed_ip);
    CHECK(parsed_ip_packet != nullptr);
    if (parsed_ip_packet == nullptr) return wirestack::test::failureCount() == 0 ? 0 : 1;

    auto parsed_tcp =
        parseTcpSegment(parsed_ip_packet->payload, parsed_ip_packet->source, parsed_ip_packet->destination);
    auto* parsed_segment = std::get_if<TcpSegment>(&parsed_tcp);
    CHECK(parsed_segment != nullptr);
    if (parsed_segment == nullptr) return wirestack::test::failureCount() == 0 ? 0 : 1;

    auto result = connections.handle(key, *parsed_segment, t0);
    CHECK(result.accepted_payload == payload_text);
    CHECK(!result.reply.has_value());

    // Echo policy: send the accepted bytes back, unmodified.
    auto echo = connections.makeOutgoingData(key, result.accepted_payload, t0);
    CHECK(!echo.segments.empty());
    if (echo.segments.empty()) return wirestack::test::failureCount() == 0 ? 0 : 1;
    const auto& echo_segment = echo.segments.front();
    CHECK(echo_segment.sequence_number == server_isn + 1);
    CHECK(echo_segment.acknowledgment_number == syn->sequence_number + 1 + payload_text.size());
    CHECK(echo_segment.flags.psh);
    CHECK(echo_segment.flags.ack);
    CHECK(echo_segment.payload == payload_text);

    auto echo_frame_bytes = buildFrame(echo_segment, local_ip, clientIp(), local_mac, clientMac());

    // Re-parse the fully composed echo reply -- both checksums must
    // validate, or these parses would fail with BadChecksum.
    auto final_eth = parseEthernetFrame(echo_frame_bytes);
    auto* final_eth_frame = std::get_if<EthernetFrame>(&final_eth);
    CHECK(final_eth_frame != nullptr);
    if (final_eth_frame != nullptr) {
        CHECK(final_eth_frame->destination == clientMac());
        CHECK(final_eth_frame->source == local_mac);

        auto final_ip = parseIpv4Packet(final_eth_frame->payload);
        auto* final_ip_packet = std::get_if<Ipv4Packet>(&final_ip);
        CHECK(final_ip_packet != nullptr);
        if (final_ip_packet != nullptr) {
            CHECK(final_ip_packet->source == local_ip);
            CHECK(final_ip_packet->destination == clientIp());
            CHECK(final_ip_packet->protocol == 6);

            auto final_tcp = parseTcpSegment(final_ip_packet->payload, final_ip_packet->source,
                                              final_ip_packet->destination);
            auto* final_segment = std::get_if<TcpSegment>(&final_tcp);
            CHECK(final_segment != nullptr);
            if (final_segment != nullptr) {
                CHECK(final_segment->source_port == 8080);
                CHECK(final_segment->destination_port == syn->source_port);
                CHECK(final_segment->flags.psh);
                CHECK(final_segment->flags.ack);
                CHECK(final_segment->payload == payload_text);
                CHECK(final_segment->sequence_number == server_isn + 1);
                CHECK(final_segment->acknowledgment_number ==
                      syn->sequence_number + 1 + payload_text.size());
            }
        }
    }

    // Duplicate-packet-path proof: re-feed the identical client data
    // frame. The application must not be echoed twice.
    auto rcv_nxt_before_duplicate = connections.snapshotOf(key)->rcv_nxt;
    auto duplicate_result = connections.handle(key, *parsed_segment, t0);
    CHECK(duplicate_result.accepted_payload.empty());
    CHECK(duplicate_result.reply.has_value());
    if (duplicate_result.reply) {
        CHECK(duplicate_result.reply->flags.ack);
        CHECK(!duplicate_result.reply->flags.psh);
        CHECK(duplicate_result.reply->payload.empty());
    }
    CHECK(connections.snapshotOf(key)->rcv_nxt == rcv_nxt_before_duplicate);

    // Client's ACK of the echoed data.
    TcpSegment ack_of_echo;
    ack_of_echo.source_port = syn->source_port;
    ack_of_echo.destination_port = syn->destination_port;
    ack_of_echo.sequence_number = syn->sequence_number + 1 + static_cast<std::uint32_t>(payload_text.size());
    ack_of_echo.acknowledgment_number = echo_segment.sequence_number +
                                         static_cast<std::uint32_t>(echo_segment.payload.size());
    ack_of_echo.flags.ack = true;
    ack_of_echo.window_size = 65535;
    ack_of_echo.urgent_pointer = 0;

    auto final_ack_result = connections.handle(key, ack_of_echo, t0);
    CHECK(!final_ack_result.reply.has_value());

    auto snapshot = connections.snapshotOf(key);
    CHECK(snapshot.has_value());
    if (snapshot) {
        CHECK(snapshot->snd_una == snapshot->snd_nxt);
    }

    return wirestack::test::failureCount() == 0 ? 0 : 1;
}
