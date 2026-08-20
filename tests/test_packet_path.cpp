// Composed pure-packet-path test: known Ethernet+IPv4+ICMP Echo Request
// bytes go through the full parse -> reply-construction -> serialize
// chain, with no TapDevice involved (see rule 41 in the milestone spec:
// pure packet logic stays testable without root).

#include "wirestack/ethernet.hpp"
#include "wirestack/icmp.hpp"
#include "wirestack/ipv4.hpp"
#include "wirestack/mac_address.hpp"

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
//   IPv4(src=10.0.0.1 dst=10.0.0.2 proto=ICMP ttl=64, checksum=0x0a91)
//     ICMP EchoRequest(id=0x1234 seq=0x0001 payload="abcdefgh", checksum=0x5435)
std::vector<std::byte> knownRequestFrame() {
    return toBytes({
        // Ethernet header
        0x02, 0x00, 0x00, 0x00, 0x00, 0x02, // destination: Wirestack
        0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, // source: host
        0x08, 0x00,                         // EtherType: IPv4
        // IPv4 header
        0x45, 0x00, 0x00, 0x24, 0x1c, 0x46, 0x40, 0x00, 0x40, 0x01, 0x0a, 0x91, 0x0a, 0x00, 0x00,
        0x01, 0x0a, 0x00, 0x00, 0x02,
        // ICMP Echo Request
        0x08, 0x00, 0x54, 0x35, 0x12, 0x34, 0x00, 0x01, 0x61, 0x62, 0x63, 0x64, 0x65, 0x66, 0x67,
        0x68,
    });
}

} // namespace

int main() {
    auto local_ip = *Ipv4Address::parse("10.0.0.2");
    auto local_mac = *MacAddress::parse("02:00:00:00:00:02");

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

    auto icmp_result = parseIcmpEcho(ip_packet->payload);
    CHECK(std::holds_alternative<IcmpEcho>(icmp_result));
    auto* request = std::get_if<IcmpEcho>(&icmp_result);
    CHECK(request != nullptr);
    if (request == nullptr) {
        return wirestack::test::failureCount() == 0 ? 0 : 1;
    }
    CHECK(request->type == IcmpEchoType::EchoRequest);

    auto reply = makeEchoReply(*request);

    Ipv4Packet reply_ip;
    reply_ip.ttl = 64;
    reply_ip.protocol = ip_packet->protocol;
    reply_ip.source = local_ip;
    reply_ip.destination = ip_packet->source;
    reply_ip.payload = serializeIcmpEcho(reply);

    auto reply_ip_bytes = serializeIpv4Packet(reply_ip);
    CHECK(std::holds_alternative<std::vector<std::byte>>(reply_ip_bytes));

    EthernetFrame reply_frame;
    reply_frame.destination = eth_frame->source;
    reply_frame.source = local_mac;
    reply_frame.ether_type = static_cast<std::uint16_t>(EtherType::Ipv4);
    reply_frame.payload = std::get<std::vector<std::byte>>(reply_ip_bytes);

    auto final_bytes = serializeEthernetFrame(reply_frame);

    // Re-parse the fully composed reply and check it against the expected
    // semantics of an Echo Reply to the original request.
    auto final_eth = parseEthernetFrame(final_bytes);
    CHECK(std::holds_alternative<EthernetFrame>(final_eth));
    auto* final_eth_frame = std::get_if<EthernetFrame>(&final_eth);
    CHECK(final_eth_frame != nullptr);
    if (final_eth_frame != nullptr) {
        CHECK(final_eth_frame->destination == *MacAddress::parse("aa:bb:cc:dd:ee:ff"));
        CHECK(final_eth_frame->source == local_mac);
        CHECK(final_eth_frame->ether_type == static_cast<std::uint16_t>(EtherType::Ipv4));

        auto final_ip = parseIpv4Packet(final_eth_frame->payload);
        CHECK(std::holds_alternative<Ipv4Packet>(final_ip));
        auto* final_ip_packet = std::get_if<Ipv4Packet>(&final_ip);
        CHECK(final_ip_packet != nullptr);
        if (final_ip_packet != nullptr) {
            CHECK(final_ip_packet->source == local_ip);
            CHECK(final_ip_packet->destination == *Ipv4Address::parse("10.0.0.1"));
            CHECK(final_ip_packet->protocol == 1);

            auto final_icmp = parseIcmpEcho(final_ip_packet->payload);
            CHECK(std::holds_alternative<IcmpEcho>(final_icmp));
            auto* final_message = std::get_if<IcmpEcho>(&final_icmp);
            CHECK(final_message != nullptr);
            if (final_message != nullptr) {
                CHECK(final_message->type == IcmpEchoType::EchoReply);
                CHECK(final_message->identifier == 0x1234);
                CHECK(final_message->sequence == 0x0001);
                CHECK(final_message->payload ==
                      toBytes({0x61, 0x62, 0x63, 0x64, 0x65, 0x66, 0x67, 0x68}));
            }
        }
    }

    return wirestack::test::failureCount() == 0 ? 0 : 1;
}
