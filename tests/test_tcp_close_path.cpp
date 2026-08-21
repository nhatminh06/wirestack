// Composed pure-packet-path tests for TCP connection close, following
// test_tcp_data_path.cpp's shape (no TapDevice involved): the connection
// is established using the same known SYN frame and real handshake logic,
// then every close-related segment is built as a TcpSegment and pushed
// through Wirestack's own serializers to produce a real Ethernet frame,
// re-parsed to independently prove addressing and checksums.

#include "wirestack/ethernet.hpp"
#include "wirestack/ipv4.hpp"
#include "wirestack/mac_address.hpp"
#include "wirestack/tcp.hpp"
#include "wirestack/tcp_connection.hpp"

#include "test_util.hpp"

using namespace wirestack;

namespace {

std::vector<std::byte> toBytes(std::string_view text) {
    std::vector<std::byte> out;
    out.reserve(text.size());
    for (char c : text) {
        out.push_back(static_cast<std::byte>(static_cast<unsigned char>(c)));
    }
    return out;
}

// Same known SYN frame as test_tcp_handshake_path.cpp/test_tcp_data_path.cpp.
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

// Parses `bytes` as a full Ethernet/IPv4/TCP frame, returning the
// resulting TcpSegment. Fails the test and returns nullopt on any parse
// error (malformed frame or bad checksum).
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

// Establishes a connection on `connections` using the known SYN frame and
// a real handshake, returning the client's parsed SYN and the server's
// drawn ISN.
struct Handshake {
    TcpSegment syn;
    std::uint32_t server_isn;
};

std::optional<Handshake> establishViaWire(TcpConnectionTable& connections,
                                           const TcpConnectionKey& key, TcpClock::time_point now) {
    auto syn = parseFrame(knownSynFrame());
    if (!syn) return std::nullopt;

    auto syn_ack = connections.handle(key, *syn, now).reply;
    if (!syn_ack) return std::nullopt;
    std::uint32_t server_isn = syn_ack->sequence_number;

    TcpSegment final_ack;
    final_ack.source_port = syn->source_port;
    final_ack.destination_port = syn->destination_port;
    final_ack.sequence_number = syn->sequence_number + 1;
    final_ack.acknowledgment_number = server_isn + 1;
    final_ack.flags.ack = true;
    final_ack.window_size = 65535;
    connections.handle(key, final_ack, now);

    if (connections.stateOf(key) != TcpState::Established) return std::nullopt;
    return Handshake{*syn, server_isn};
}

} // namespace

int main() {
    auto local_ip = *Ipv4Address::parse("10.0.0.2");
    auto local_mac = *MacAddress::parse("02:00:00:00:00:02");
    constexpr TcpClock::time_point t0{};

    // --- Passive close ---
    {
        TcpConnectionTable connections(8080);
        TcpConnectionKey key{local_ip, 8080, clientIp(), 54321};
        auto hs = establishViaWire(connections, key, t0);
        CHECK(hs.has_value());
        if (!hs) return wirestack::test::failureCount() == 0 ? 0 : 1;

        auto payload_text = toBytes("goodbye");
        TcpSegment client_fin;
        client_fin.source_port = hs->syn.source_port;
        client_fin.destination_port = hs->syn.destination_port;
        client_fin.sequence_number = hs->syn.sequence_number + 1;
        client_fin.acknowledgment_number = hs->server_isn + 1;
        client_fin.flags.ack = true;
        client_fin.flags.fin = true;
        client_fin.window_size = 65535;
        client_fin.payload = payload_text;

        auto client_frame = buildFrame(client_fin, clientIp(), local_ip, clientMac(), local_mac);
        auto parsed = parseFrame(client_frame);
        CHECK(parsed.has_value());
        if (!parsed) return wirestack::test::failureCount() == 0 ? 0 : 1;

        auto result = connections.handle(key, *parsed, t0);
        CHECK(result.accepted_payload == payload_text);
        CHECK(result.peer_closed);
        CHECK(!result.reply.has_value()); // echo below will ACK the FIN too
        CHECK(connections.stateOf(key) == TcpState::CloseWait);

        // Echo the accepted bytes back, then initiate the local close --
        // exactly what main.cpp's handleTcp does.
        auto echo = connections.makeOutgoingData(key, result.accepted_payload, t0);
        CHECK(!echo.segments.empty());
        if (echo.segments.empty()) return wirestack::test::failureCount() == 0 ? 0 : 1;
        const auto& echo_segment = echo.segments.front();
        CHECK(echo_segment.acknowledgment_number ==
              hs->syn.sequence_number + 1 + payload_text.size() + 1); // covers payload + FIN

        auto local_fin_result = connections.beginClose(key, t0);
        CHECK(local_fin_result.accepted);
        auto local_fin = local_fin_result.fin;
        CHECK(local_fin.has_value());
        CHECK(connections.stateOf(key) == TcpState::LastAck);
        if (!local_fin) return wirestack::test::failureCount() == 0 ? 0 : 1;

        // Serialize and re-parse both outgoing segments to independently
        // prove addressing, flags, and checksums.
        auto echo_frame = buildFrame(echo_segment, local_ip, clientIp(), local_mac, clientMac());
        auto parsed_echo = parseFrame(echo_frame);
        CHECK(parsed_echo.has_value());
        if (parsed_echo) {
            CHECK(parsed_echo->flags.psh);
            CHECK(parsed_echo->flags.ack);
            CHECK(!parsed_echo->flags.fin);
            CHECK(parsed_echo->payload == payload_text);
        }

        auto fin_frame = buildFrame(*local_fin, local_ip, clientIp(), local_mac, clientMac());
        auto parsed_fin = parseFrame(fin_frame);
        CHECK(parsed_fin.has_value());
        if (parsed_fin) {
            CHECK(parsed_fin->flags.fin);
            CHECK(parsed_fin->flags.ack);
            CHECK(parsed_fin->payload.empty());
            CHECK(parsed_fin->sequence_number == local_fin->sequence_number);
        }

        // Client ACKs both the echoed data and the local FIN in one
        // segment (cumulative ACK covering the whole pending queue).
        TcpSegment client_ack;
        client_ack.source_port = hs->syn.source_port;
        client_ack.destination_port = hs->syn.destination_port;
        client_ack.sequence_number =
            hs->syn.sequence_number + 1 + static_cast<std::uint32_t>(payload_text.size()) + 1;
        client_ack.acknowledgment_number = local_fin->sequence_number + 1;
        client_ack.flags.ack = true;
        client_ack.window_size = 65535;

        auto ack_frame = buildFrame(client_ack, clientIp(), local_ip, clientMac(), local_mac);
        auto parsed_ack = parseFrame(ack_frame);
        CHECK(parsed_ack.has_value());
        if (parsed_ack) {
            auto final_result = connections.handle(key, *parsed_ack, t0);
            CHECK(!final_result.reply.has_value());
            CHECK(final_result.accepted_payload.empty());
        }

        CHECK(!connections.stateOf(key).has_value()); // connection removed
    }

    // --- Active close ---
    {
        TcpConnectionTable connections(8080);
        TcpConnectionKey key{local_ip, 8080, clientIp(), 54321};
        auto hs = establishViaWire(connections, key, t0);
        CHECK(hs.has_value());
        if (!hs) return wirestack::test::failureCount() == 0 ? 0 : 1;

        auto local_fin_result = connections.beginClose(key, t0);
        CHECK(local_fin_result.accepted);
        auto local_fin = local_fin_result.fin;
        CHECK(local_fin.has_value());
        CHECK(connections.stateOf(key) == TcpState::FinWait1);
        if (!local_fin) return wirestack::test::failureCount() == 0 ? 0 : 1;

        auto fin_frame = buildFrame(*local_fin, local_ip, clientIp(), local_mac, clientMac());
        auto parsed_fin = parseFrame(fin_frame);
        CHECK(parsed_fin.has_value());
        if (parsed_fin) {
            CHECK(parsed_fin->flags.fin);
            CHECK(parsed_fin->flags.ack);
        }

        // Client ACKs Wirestack's FIN.
        TcpSegment client_ack;
        client_ack.source_port = hs->syn.source_port;
        client_ack.destination_port = hs->syn.destination_port;
        client_ack.sequence_number = hs->syn.sequence_number + 1;
        client_ack.acknowledgment_number = local_fin->sequence_number + 1;
        client_ack.flags.ack = true;
        client_ack.window_size = 65535;

        auto ack_frame = buildFrame(client_ack, clientIp(), local_ip, clientMac(), local_mac);
        auto parsed_ack = parseFrame(ack_frame);
        CHECK(parsed_ack.has_value());
        if (parsed_ack) {
            connections.handle(key, *parsed_ack, t0);
        }
        CHECK(connections.stateOf(key) == TcpState::FinWait2);

        // Client sends its own FIN|ACK.
        TcpSegment client_fin;
        client_fin.source_port = hs->syn.source_port;
        client_fin.destination_port = hs->syn.destination_port;
        client_fin.sequence_number = hs->syn.sequence_number + 1;
        client_fin.acknowledgment_number = local_fin->sequence_number + 1;
        client_fin.flags.ack = true;
        client_fin.flags.fin = true;
        client_fin.window_size = 65535;

        auto client_fin_frame =
            buildFrame(client_fin, clientIp(), local_ip, clientMac(), local_mac);
        auto parsed_client_fin = parseFrame(client_fin_frame);
        CHECK(parsed_client_fin.has_value());
        if (!parsed_client_fin) return wirestack::test::failureCount() == 0 ? 0 : 1;

        auto result = connections.handle(key, *parsed_client_fin, t0);
        CHECK(result.peer_closed);
        CHECK(connections.stateOf(key) == TcpState::TimeWait);
        CHECK(result.reply.has_value());

        if (result.reply) {
            auto ack_frame_out = buildFrame(*result.reply, local_ip, clientIp(), local_mac,
                                             clientMac());
            auto parsed_ack_out = parseFrame(ack_frame_out);
            CHECK(parsed_ack_out.has_value());
            if (parsed_ack_out) {
                CHECK(parsed_ack_out->flags.ack);
                CHECK(!parsed_ack_out->flags.fin);
                CHECK(parsed_ack_out->acknowledgment_number == client_fin.sequence_number + 1);
            }
        }

        // Synthetic clock advance: exactly the TIME_WAIT deadline.
        auto expired = connections.pollRetransmissions(t0 + kTimeWaitDuration);
        CHECK(expired.time_wait_expired.size() == 1);
        CHECK(!connections.stateOf(key).has_value());
    }

    return wirestack::test::failureCount() == 0 ? 0 : 1;
}
