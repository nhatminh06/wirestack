// Composed pure-packet-path test: known Ethernet+IPv4+UDP request bytes go
// through the full parse -> endpoint-delivery -> reply-construction ->
// serialize chain, with no TapDevice involved.

#include "wirestack/ethernet.hpp"
#include "wirestack/ipv4.hpp"
#include "wirestack/mac_address.hpp"
#include "wirestack/udp.hpp"
#include "wirestack/udp_endpoint.hpp"

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

// Ethernet(dst=02:00:00:00:00:02 src=aa:bb:cc:dd:ee:ff type=IPv4)
//   IPv4(src=10.0.0.1 dst=10.0.0.2 proto=UDP ttl=64, checksum=0x0a84)
//     UDP(srcport=43210 dstport=9000 payload="hello", checksum=0xdc0c)
std::vector<std::byte> knownRequestFrame() {
    return toBytes({
        // Ethernet header
        0x02, 0x00, 0x00, 0x00, 0x00, 0x02, // destination: Wirestack
        0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, // source: host
        0x08, 0x00,                         // EtherType: IPv4
        // IPv4 header
        0x45, 0x00, 0x00, 0x21, 0x1c, 0x46, 0x40, 0x00, 0x40, 0x11, 0x0a, 0x84, 0x0a, 0x00, 0x00,
        0x01, 0x0a, 0x00, 0x00, 0x02,
        // UDP datagram
        0xa8, 0xca, 0x23, 0x28, 0x00, 0x0d, 0xdc, 0x0c, 0x68, 0x65, 0x6c, 0x6c, 0x6f,
    });
}

} // namespace

int main() {
    auto local_ip = *Ipv4Address::parse("10.0.0.2");
    auto local_mac = *MacAddress::parse("02:00:00:00:00:02");

    UdpEndpointTable endpoints;
    endpoints.bind(9000, [](std::span<const std::byte> request) {
        return std::vector<std::byte>(request.begin(), request.end());
    });

    auto eth_result = parseEthernetFrame(knownRequestFrame());
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
    CHECK(ip_packet->protocol == 17);

    auto udp_result = parseUdpDatagram(ip_packet->payload, ip_packet->source, ip_packet->destination);
    CHECK(std::holds_alternative<UdpDatagram>(udp_result));
    auto* request = std::get_if<UdpDatagram>(&udp_result);
    CHECK(request != nullptr);
    if (request == nullptr) {
        return wirestack::test::failureCount() == 0 ? 0 : 1;
    }
    CHECK(request->source_port == 43210);
    CHECK(request->destination_port == 9000);
    CHECK(request->payload == toBytes("hello"));

    auto response = endpoints.deliver(request->destination_port, request->payload);
    CHECK(response.has_value());
    if (!response) {
        return wirestack::test::failureCount() == 0 ? 0 : 1;
    }

    UdpDatagram reply;
    reply.source_port = request->destination_port;
    reply.destination_port = request->source_port;
    reply.payload = *response;

    auto reply_udp_bytes = serializeUdpDatagram(reply, local_ip, ip_packet->source);
    CHECK(std::holds_alternative<std::vector<std::byte>>(reply_udp_bytes));

    Ipv4Packet reply_ip;
    reply_ip.ttl = 64;
    reply_ip.protocol = ip_packet->protocol;
    reply_ip.source = local_ip;
    reply_ip.destination = ip_packet->source;
    reply_ip.payload = std::get<std::vector<std::byte>>(reply_udp_bytes);

    auto reply_ip_bytes = serializeIpv4Packet(reply_ip);
    CHECK(std::holds_alternative<std::vector<std::byte>>(reply_ip_bytes));

    EthernetFrame reply_frame;
    reply_frame.destination = eth_frame->source;
    reply_frame.source = local_mac;
    reply_frame.ether_type = static_cast<std::uint16_t>(EtherType::Ipv4);
    reply_frame.payload = std::get<std::vector<std::byte>>(reply_ip_bytes);

    auto final_bytes = serializeEthernetFrame(reply_frame);

    // Re-parse the fully composed reply and check MAC/IP/port reversal,
    // payload preservation, and that the reply's UDP checksum validates.
    auto final_eth = parseEthernetFrame(final_bytes);
    CHECK(std::holds_alternative<EthernetFrame>(final_eth));
    auto* final_eth_frame = std::get_if<EthernetFrame>(&final_eth);
    CHECK(final_eth_frame != nullptr);
    if (final_eth_frame != nullptr) {
        CHECK(final_eth_frame->destination == *MacAddress::parse("aa:bb:cc:dd:ee:ff"));
        CHECK(final_eth_frame->source == local_mac);

        auto final_ip = parseIpv4Packet(final_eth_frame->payload);
        CHECK(std::holds_alternative<Ipv4Packet>(final_ip));
        auto* final_ip_packet = std::get_if<Ipv4Packet>(&final_ip);
        CHECK(final_ip_packet != nullptr);
        if (final_ip_packet != nullptr) {
            CHECK(final_ip_packet->source == local_ip);
            CHECK(final_ip_packet->destination == *Ipv4Address::parse("10.0.0.1"));
            CHECK(final_ip_packet->protocol == 17);

            auto final_udp = parseUdpDatagram(final_ip_packet->payload, final_ip_packet->source,
                                               final_ip_packet->destination);
            CHECK(std::holds_alternative<UdpDatagram>(final_udp));
            auto* final_datagram = std::get_if<UdpDatagram>(&final_udp);
            CHECK(final_datagram != nullptr);
            if (final_datagram != nullptr) {
                CHECK(final_datagram->source_port == 9000);
                CHECK(final_datagram->destination_port == 43210);
                CHECK(final_datagram->payload == toBytes("hello"));
            }
        }
    }

    return wirestack::test::failureCount() == 0 ? 0 : 1;
}
