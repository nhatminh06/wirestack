// Composed pure-packet-path loss-recovery test (no TAP, no sleep, no
// root, no real clock): a known SYN is answered but its SYN-ACK is
// intentionally never delivered back; a synthetic clock is advanced to
// the retransmission deadline and the resulting SYN-ACK retransmission
// is serialized/re-parsed through the real wire format. The handshake is
// then completed, a client data segment is accepted and echoed, the echo
// is intentionally dropped, and the same loss-recovery proof is repeated
// for the data path, ending with the client's cumulative ACK draining
// the pending queue.

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

// Same known SYN frame as test_tcp_handshake_path.cpp/test_tcp_data_path.cpp:
// client 10.0.0.1/aa:bb:cc:dd:ee:ff:54321, server 10.0.0.2/02:00:00:00:00:02:8080,
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

    // --- SYN-ACK loss and retransmission ---

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
    auto syn_ack = connections.handle(key, *syn, t0).reply; // obtained, but never "delivered"
    CHECK(syn_ack.has_value());
    if (!syn_ack) return wirestack::test::failureCount() == 0 ? 0 : 1;
    std::uint32_t server_isn = syn_ack->sequence_number;

    auto handshake_deadline = t0 + kInitialRto;
    auto due = connections.pollRetransmissions(handshake_deadline);
    CHECK(due.retransmissions.size() == 1);
    if (due.retransmissions.size() == 1) {
        CHECK(due.retransmissions[0].key == key);
    }

    // Serialize the retransmitted SYN-ACK through the real wire format
    // and verify it independently by re-parsing.
    if (due.retransmissions.size() == 1) {
        auto retransmit_frame_bytes =
            buildFrame(due.retransmissions[0].segment, local_ip, clientIp(), local_mac, clientMac());
        auto parsed_eth = parseEthernetFrame(retransmit_frame_bytes);
        auto* parsed_eth_frame = std::get_if<EthernetFrame>(&parsed_eth);
        CHECK(parsed_eth_frame != nullptr);
        if (parsed_eth_frame != nullptr) {
            CHECK(parsed_eth_frame->destination == clientMac());
            CHECK(parsed_eth_frame->source == local_mac);

            auto parsed_ip = parseIpv4Packet(parsed_eth_frame->payload); // validates IPv4 checksum
            auto* parsed_ip_packet = std::get_if<Ipv4Packet>(&parsed_ip);
            CHECK(parsed_ip_packet != nullptr);
            if (parsed_ip_packet != nullptr) {
                CHECK(parsed_ip_packet->source == local_ip);
                CHECK(parsed_ip_packet->destination == clientIp());

                auto parsed_tcp = parseTcpSegment(parsed_ip_packet->payload, parsed_ip_packet->source,
                                                   parsed_ip_packet->destination); // validates TCP checksum
                auto* parsed_segment = std::get_if<TcpSegment>(&parsed_tcp);
                CHECK(parsed_segment != nullptr);
                if (parsed_segment != nullptr) {
                    CHECK(parsed_segment->flags.syn);
                    CHECK(parsed_segment->flags.ack);
                    CHECK(parsed_segment->sequence_number == server_isn);
                    CHECK(parsed_segment->acknowledgment_number == syn->sequence_number + 1);
                }
            }
        }
    }

    // Handshake completes (client's ACK, arriving after seeing the
    // retransmission).
    TcpSegment final_ack;
    final_ack.source_port = syn->source_port;
    final_ack.destination_port = syn->destination_port;
    final_ack.sequence_number = syn->sequence_number + 1;
    final_ack.acknowledgment_number = server_isn + 1;
    final_ack.flags.ack = true;
    final_ack.window_size = 65535;
    final_ack.urgent_pointer = 0;
    connections.handle(key, final_ack, handshake_deadline);
    CHECK(connections.stateOf(key) == TcpState::Established);
    auto after_handshake = connections.snapshotOf(key);
    CHECK(after_handshake.has_value());
    if (after_handshake) {
        CHECK(after_handshake->pending_count == 0); // pending SYN-ACK drained
    }

    // --- Application-data loss and retransmission ---

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

    auto client_frame_bytes = buildFrame(client_data, clientIp(), local_ip, clientMac(), local_mac);

    auto parsed_client_eth = parseEthernetFrame(client_frame_bytes);
    auto* parsed_client_eth_frame = std::get_if<EthernetFrame>(&parsed_client_eth);
    CHECK(parsed_client_eth_frame != nullptr);
    if (parsed_client_eth_frame == nullptr) return wirestack::test::failureCount() == 0 ? 0 : 1;

    auto parsed_client_ip = parseIpv4Packet(parsed_client_eth_frame->payload);
    auto* parsed_client_ip_packet = std::get_if<Ipv4Packet>(&parsed_client_ip);
    CHECK(parsed_client_ip_packet != nullptr);
    if (parsed_client_ip_packet == nullptr) return wirestack::test::failureCount() == 0 ? 0 : 1;

    auto parsed_client_tcp = parseTcpSegment(parsed_client_ip_packet->payload,
                                              parsed_client_ip_packet->source,
                                              parsed_client_ip_packet->destination);
    auto* parsed_client_segment = std::get_if<TcpSegment>(&parsed_client_tcp);
    CHECK(parsed_client_segment != nullptr);
    if (parsed_client_segment == nullptr) return wirestack::test::failureCount() == 0 ? 0 : 1;

    auto data_time = handshake_deadline;
    auto received = connections.handle(key, *parsed_client_segment, data_time);
    CHECK(received.accepted_payload == payload_text);

    auto echo = connections.makeOutgoingData(key, received.accepted_payload, data_time);
    CHECK(!echo.segments.empty()); // obtained, but never "delivered" -- simulated loss
    if (echo.segments.empty()) return wirestack::test::failureCount() == 0 ? 0 : 1;
    const auto& echo_segment = echo.segments.front();

    auto data_deadline = data_time + kInitialRto;
    auto data_due = connections.pollRetransmissions(data_deadline);
    CHECK(data_due.retransmissions.size() == 1);
    if (data_due.retransmissions.size() == 1) {
        CHECK(data_due.retransmissions[0].key == key);
        CHECK(data_due.retransmissions[0].segment.sequence_number == echo_segment.sequence_number);
        CHECK(data_due.retransmissions[0].segment.payload == payload_text);

        auto retransmit_frame_bytes = buildFrame(data_due.retransmissions[0].segment, local_ip,
                                                  clientIp(), local_mac, clientMac());
        auto parsed_eth2 = parseEthernetFrame(retransmit_frame_bytes);
        auto* parsed_eth_frame2 = std::get_if<EthernetFrame>(&parsed_eth2);
        CHECK(parsed_eth_frame2 != nullptr);
        if (parsed_eth_frame2 != nullptr) {
            CHECK(parsed_eth_frame2->destination == clientMac());
            CHECK(parsed_eth_frame2->source == local_mac);

            auto parsed_ip2 = parseIpv4Packet(parsed_eth_frame2->payload);
            auto* parsed_ip_packet2 = std::get_if<Ipv4Packet>(&parsed_ip2);
            CHECK(parsed_ip_packet2 != nullptr);
            if (parsed_ip_packet2 != nullptr) {
                CHECK(parsed_ip_packet2->source == local_ip);
                CHECK(parsed_ip_packet2->destination == clientIp());

                auto parsed_tcp2 = parseTcpSegment(parsed_ip_packet2->payload, parsed_ip_packet2->source,
                                                    parsed_ip_packet2->destination);
                auto* parsed_segment2 = std::get_if<TcpSegment>(&parsed_tcp2);
                CHECK(parsed_segment2 != nullptr);
                if (parsed_segment2 != nullptr) {
                    CHECK(parsed_segment2->flags.psh);
                    CHECK(parsed_segment2->flags.ack);
                    CHECK(parsed_segment2->payload == payload_text);
                    CHECK(parsed_segment2->sequence_number == echo_segment.sequence_number);
                    CHECK(parsed_segment2->acknowledgment_number ==
                          syn->sequence_number + 1 + payload_text.size());
                }
            }
        }
    }

    // Client's cumulative ACK of the retransmitted echo drains the queue.
    TcpSegment ack_of_echo;
    ack_of_echo.source_port = syn->source_port;
    ack_of_echo.destination_port = syn->destination_port;
    ack_of_echo.sequence_number =
        syn->sequence_number + 1 + static_cast<std::uint32_t>(payload_text.size());
    ack_of_echo.acknowledgment_number =
        echo_segment.sequence_number + static_cast<std::uint32_t>(echo_segment.payload.size());
    ack_of_echo.flags.ack = true;
    ack_of_echo.window_size = 65535;
    ack_of_echo.urgent_pointer = 0;

    auto final_ack_result = connections.handle(key, ack_of_echo, data_deadline);
    CHECK(!final_ack_result.reply.has_value());

    auto final_snapshot = connections.snapshotOf(key);
    CHECK(final_snapshot.has_value());
    if (final_snapshot) {
        CHECK(final_snapshot->snd_una == final_snapshot->snd_nxt);
        CHECK(final_snapshot->pending_count == 0);
    }

    return wirestack::test::failureCount() == 0 ? 0 : 1;
}
