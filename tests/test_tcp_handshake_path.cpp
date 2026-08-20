// Composed pure-packet-path test: a known Ethernet+IPv4+TCP SYN goes
// through the full parse -> connection-state -> reply-construction ->
// serialize chain, with no TapDevice involved. Then a hand-built final
// ACK is fed into the same connection table and the ESTABLISHED
// transition is verified.

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

// Ethernet(dst=02:00:00:00:00:02 src=aa:bb:cc:dd:ee:ff type=IPv4)
//   IPv4(src=10.0.0.1 dst=10.0.0.2 proto=TCP ttl=64, checksum=0x0a88)
//     TCP(srcport=54321 dstport=8080 seq=1000 ack=0 flags=SYN,
//         checksum=0xa436)
std::vector<std::byte> knownSynFrame() {
    return toBytes({
        // Ethernet header
        0x02, 0x00, 0x00, 0x00, 0x00, 0x02, // destination: Wirestack
        0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, // source: host
        0x08, 0x00,                         // EtherType: IPv4
        // IPv4 header
        0x45, 0x00, 0x00, 0x28, 0x1c, 0x46, 0x40, 0x00, 0x40, 0x06, 0x0a, 0x88, 0x0a, 0x00, 0x00,
        0x01, 0x0a, 0x00, 0x00, 0x02,
        // TCP segment: SYN
        0xd4, 0x31, 0x1f, 0x90, 0x00, 0x00, 0x03, 0xe8, 0x00, 0x00, 0x00, 0x00, 0x50, 0x02, 0xff,
        0xff, 0xa4, 0x36, 0x00, 0x00,
    });
}

} // namespace

int main() {
    auto local_ip = *Ipv4Address::parse("10.0.0.2");
    auto local_mac = *MacAddress::parse("02:00:00:00:00:02");
    TcpConnectionTable connections(8080);
    constexpr TcpClock::time_point t0{};

    auto eth_result = parseEthernetFrame(knownSynFrame());
    CHECK(std::holds_alternative<EthernetFrame>(eth_result));
    auto* eth_frame = std::get_if<EthernetFrame>(&eth_result);
    CHECK(eth_frame != nullptr);
    if (eth_frame == nullptr) {
        return wirestack::test::failureCount() == 0 ? 0 : 1;
    }

    auto ip_result = parseIpv4Packet(eth_frame->payload);
    CHECK(std::holds_alternative<Ipv4Packet>(ip_result));
    auto* ip_packet = std::get_if<Ipv4Packet>(&ip_result);
    CHECK(ip_packet != nullptr);
    if (ip_packet == nullptr) {
        return wirestack::test::failureCount() == 0 ? 0 : 1;
    }
    CHECK(ip_packet->destination == local_ip);
    CHECK(ip_packet->protocol == 6);

    auto tcp_result = parseTcpSegment(ip_packet->payload, ip_packet->source, ip_packet->destination);
    CHECK(std::holds_alternative<TcpSegment>(tcp_result));
    auto* syn = std::get_if<TcpSegment>(&tcp_result);
    CHECK(syn != nullptr);
    if (syn == nullptr) {
        return wirestack::test::failureCount() == 0 ? 0 : 1;
    }
    CHECK(syn->flags.syn);
    CHECK(syn->destination_port == 8080);

    TcpConnectionKey key{local_ip, syn->destination_port, ip_packet->source, syn->source_port};
    auto reply = connections.handle(key, *syn, t0).reply;
    CHECK(reply.has_value());
    if (!reply) {
        return wirestack::test::failureCount() == 0 ? 0 : 1;
    }
    CHECK(reply->flags.syn);
    CHECK(reply->flags.ack);
    CHECK(reply->acknowledgment_number == syn->sequence_number + 1);
    std::uint32_t server_isn = reply->sequence_number;

    auto reply_tcp_bytes = serializeTcpSegment(*reply, local_ip, ip_packet->source);
    CHECK(std::holds_alternative<std::vector<std::byte>>(reply_tcp_bytes));

    Ipv4Packet reply_ip;
    reply_ip.ttl = 64;
    reply_ip.protocol = ip_packet->protocol;
    reply_ip.source = local_ip;
    reply_ip.destination = ip_packet->source;
    reply_ip.payload = std::get<std::vector<std::byte>>(reply_tcp_bytes);

    auto reply_ip_bytes = serializeIpv4Packet(reply_ip);
    CHECK(std::holds_alternative<std::vector<std::byte>>(reply_ip_bytes));

    EthernetFrame reply_frame;
    reply_frame.destination = eth_frame->source;
    reply_frame.source = local_mac;
    reply_frame.ether_type = static_cast<std::uint16_t>(EtherType::Ipv4);
    reply_frame.payload = std::get<std::vector<std::byte>>(reply_ip_bytes);

    auto final_bytes = serializeEthernetFrame(reply_frame);

    // Re-parse the fully composed SYN-ACK reply and check MAC/IP/port
    // reversal, flags, ack number, and that both checksums validate.
    auto final_eth = parseEthernetFrame(final_bytes);
    CHECK(std::holds_alternative<EthernetFrame>(final_eth));
    auto* final_eth_frame = std::get_if<EthernetFrame>(&final_eth);
    CHECK(final_eth_frame != nullptr);
    if (final_eth_frame != nullptr) {
        CHECK(final_eth_frame->destination == *MacAddress::parse("aa:bb:cc:dd:ee:ff"));
        CHECK(final_eth_frame->source == local_mac);

        auto final_ip = parseIpv4Packet(final_eth_frame->payload); // validates IPv4 checksum
        CHECK(std::holds_alternative<Ipv4Packet>(final_ip));
        auto* final_ip_packet = std::get_if<Ipv4Packet>(&final_ip);
        CHECK(final_ip_packet != nullptr);
        if (final_ip_packet != nullptr) {
            CHECK(final_ip_packet->source == local_ip);
            CHECK(final_ip_packet->destination == *Ipv4Address::parse("10.0.0.1"));
            CHECK(final_ip_packet->protocol == 6);

            auto final_tcp = parseTcpSegment(final_ip_packet->payload, final_ip_packet->source,
                                              final_ip_packet->destination); // validates TCP checksum
            CHECK(std::holds_alternative<TcpSegment>(final_tcp));
            auto* final_segment = std::get_if<TcpSegment>(&final_tcp);
            CHECK(final_segment != nullptr);
            if (final_segment != nullptr) {
                CHECK(final_segment->source_port == 8080);
                CHECK(final_segment->destination_port == 54321);
                CHECK(final_segment->flags.syn);
                CHECK(final_segment->flags.ack);
                CHECK(final_segment->sequence_number == server_isn);
                CHECK(final_segment->acknowledgment_number == 1001);
            }
        }
    }

    // Final ACK, fed into the same connection table -> ESTABLISHED.
    TcpSegment final_ack;
    final_ack.source_port = syn->source_port;
    final_ack.destination_port = syn->destination_port;
    final_ack.sequence_number = syn->sequence_number + 1;
    final_ack.acknowledgment_number = server_isn + 1;
    final_ack.flags.ack = true;
    final_ack.window_size = 65535;
    final_ack.urgent_pointer = 0;

    auto no_reply = connections.handle(key, final_ack, t0).reply;
    CHECK(!no_reply.has_value());
    CHECK(connections.stateOf(key) == TcpState::Established);

    return wirestack::test::failureCount() == 0 ? 0 : 1;
}
