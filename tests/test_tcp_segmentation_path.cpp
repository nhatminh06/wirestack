// Composed pure-packet-path test for outgoing TCP segmentation: an
// application send larger than 2*MSS is segmented, each segment is
// pushed through the real Ethernet/IPv4/TCP serializers and re-parsed,
// and the client's cumulative ACK retires every pending entry. Follows
// the established composed-test shape (no TapDevice, no root).

#include "wirestack/ethernet.hpp"
#include "wirestack/ipv4.hpp"
#include "wirestack/mac_address.hpp"
#include "wirestack/tcp.hpp"
#include "wirestack/tcp_connection.hpp"

#include "test_util.hpp"

using namespace wirestack;

namespace {

constexpr std::size_t kEthernetMtu = 1500;
constexpr std::size_t kEthernetHeaderLength = 14;

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

    auto syn = parseFrame(knownSynFrame());
    CHECK(syn.has_value());
    if (!syn) return wirestack::test::failureCount() == 0 ? 0 : 1;

    auto syn_ack = connections.handle(key, syn->tcp, t0).reply;
    CHECK(syn_ack.has_value());
    if (!syn_ack) return wirestack::test::failureCount() == 0 ? 0 : 1;
    std::uint32_t server_isn = syn_ack->sequence_number;

    TcpSegment final_ack;
    final_ack.source_port = syn->tcp.source_port;
    final_ack.destination_port = syn->tcp.destination_port;
    final_ack.sequence_number = syn->tcp.sequence_number + 1;
    final_ack.acknowledgment_number = server_isn + 1;
    final_ack.flags.ack = true;
    final_ack.window_size = 65535;
    connections.handle(key, final_ack, t0);
    CHECK(connections.stateOf(key) == TcpState::Established);

    // 2*MSS + 500 bytes -> at least 3 segments.
    std::size_t total = 2 * kTcpMss + 500;
    std::vector<std::byte> payload;
    payload.reserve(total);
    for (std::size_t i = 0; i < total; ++i) {
        payload.push_back(static_cast<std::byte>(i % 256));
    }

    auto sent = connections.makeOutgoingData(key, payload, t0);
    CHECK(sent.segments.size() == 3);
    if (sent.segments.size() != 3) return wirestack::test::failureCount() == 0 ? 0 : 1;

    std::uint32_t expected_seq = server_isn + 1;
    std::vector<std::byte> reconstructed;
    for (const auto& segment : sent.segments) {
        CHECK(segment.payload.size() <= kTcpMss);
        CHECK(segment.sequence_number == expected_seq);
        CHECK(segment.flags.ack);

        auto frame_bytes = buildFrame(segment, local_ip, clientIp(), local_mac, clientMac());
        CHECK(frame_bytes.size() <= kEthernetHeaderLength + kEthernetMtu);

        auto parsed = parseFrame(frame_bytes); // validates both checksums
        CHECK(parsed.has_value());
        if (parsed) {
            std::size_t ipv4_total_length = 20 + parsed->ip.payload.size();
            CHECK(ipv4_total_length <= kEthernetMtu);
            CHECK(parsed->tcp.payload.size() <= kTcpMss);
            CHECK(parsed->tcp.sequence_number == segment.sequence_number);
            CHECK(parsed->tcp.payload == segment.payload);
            CHECK(parsed->eth.destination == clientMac());
            CHECK(parsed->eth.source == local_mac);
            CHECK(parsed->ip.source == local_ip);
            CHECK(parsed->ip.destination == clientIp());
        }

        expected_seq += static_cast<std::uint32_t>(segment.payload.size());
        reconstructed.insert(reconstructed.end(), segment.payload.begin(), segment.payload.end());
    }
    CHECK(reconstructed == payload);

    auto before_ack = connections.snapshotOf(key);
    CHECK(before_ack.has_value());
    if (before_ack) CHECK(before_ack->pending_count == 3);

    // Cumulative ACK covering all three segments.
    TcpSegment client_ack;
    client_ack.source_port = syn->tcp.source_port;
    client_ack.destination_port = syn->tcp.destination_port;
    client_ack.sequence_number = syn->tcp.sequence_number + 1;
    client_ack.acknowledgment_number = expected_seq;
    client_ack.flags.ack = true;
    client_ack.window_size = 65535;

    auto ack_frame = buildFrame(client_ack, clientIp(), local_ip, clientMac(), local_mac);
    auto parsed_ack = parseFrame(ack_frame);
    CHECK(parsed_ack.has_value());
    if (parsed_ack) {
        auto ack_result = connections.handle(key, parsed_ack->tcp, t0);
        CHECK(!ack_result.reply.has_value());
    }

    auto after_ack = connections.snapshotOf(key);
    CHECK(after_ack.has_value());
    if (after_ack) {
        CHECK(after_ack->pending_count == 0);
        CHECK(after_ack->snd_una == after_ack->snd_nxt);
    }

    auto due = connections.pollRetransmissions(t0 + kMaxRto * kMaxRetransmits);
    CHECK(due.retransmissions.empty());

    return wirestack::test::failureCount() == 0 ? 0 : 1;
}
