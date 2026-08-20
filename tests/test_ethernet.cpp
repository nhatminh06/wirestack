#include "wirestack/ethernet.hpp"

#include "test_util.hpp"

using wirestack::EthernetFrame;
using wirestack::EthernetParseError;
using wirestack::EtherType;
using wirestack::MacAddress;
using wirestack::parseEthernetFrame;
using wirestack::serializeEthernetFrame;

namespace {

std::vector<std::byte> toBytes(std::initializer_list<std::uint8_t> values) {
    std::vector<std::byte> out;
    out.reserve(values.size());
    for (auto v : values) {
        out.push_back(static_cast<std::byte>(v));
    }
    return out;
}

} // namespace

int main() {
    // valid decode of a known frame: dst, src, ethertype=IPv4, 4-byte payload
    {
        auto bytes = toBytes({
            0x11, 0x22, 0x33, 0x44, 0x55, 0x66, // destination
            0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, // source
            0x08, 0x00,                         // ethertype: IPv4
            0xde, 0xad, 0xbe, 0xef,              // payload
        });

        auto result = parseEthernetFrame(bytes);
        CHECK(std::holds_alternative<EthernetFrame>(result));
        if (auto* frame = std::get_if<EthernetFrame>(&result)) {
            CHECK(frame->destination.toString() == "11:22:33:44:55:66");
            CHECK(frame->source.toString() == "aa:bb:cc:dd:ee:ff");
            CHECK(frame->ether_type == static_cast<std::uint16_t>(EtherType::Ipv4));
            CHECK(frame->payload == toBytes({0xde, 0xad, 0xbe, 0xef}));
        }
    }

    // encode/decode round trip
    {
        EthernetFrame original;
        original.destination = *MacAddress::parse("01:02:03:04:05:06");
        original.source = *MacAddress::parse("10:20:30:40:50:60");
        original.ether_type = static_cast<std::uint16_t>(EtherType::Arp);
        original.payload = toBytes({1, 2, 3, 4, 5});

        auto serialized = serializeEthernetFrame(original);
        auto result = parseEthernetFrame(serialized);
        CHECK(std::holds_alternative<EthernetFrame>(result));
        if (auto* frame = std::get_if<EthernetFrame>(&result)) {
            CHECK(frame->destination == original.destination);
            CHECK(frame->source == original.source);
            CHECK(frame->ether_type == original.ether_type);
            CHECK(frame->payload == original.payload);
        }
    }

    // truncated frames rejected
    {
        CHECK(std::holds_alternative<EthernetParseError>(parseEthernetFrame({})));

        auto six_bytes = toBytes({1, 2, 3, 4, 5, 6});
        CHECK(std::holds_alternative<EthernetParseError>(parseEthernetFrame(six_bytes)));

        auto thirteen_bytes = toBytes(
            {1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13});
        CHECK(std::holds_alternative<EthernetParseError>(parseEthernetFrame(thirteen_bytes)));
    }

    // minimum-size frame: exactly 14 bytes, empty payload
    {
        auto bytes = toBytes({
            0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0,
            0x08, 0x06,
        });
        auto result = parseEthernetFrame(bytes);
        CHECK(std::holds_alternative<EthernetFrame>(result));
        if (auto* frame = std::get_if<EthernetFrame>(&result)) {
            CHECK(frame->payload.empty());
            CHECK(frame->ether_type == static_cast<std::uint16_t>(EtherType::Arp));
        }
    }

    // unknown/unsupported ethertype value still decodes (raw value preserved)
    {
        auto bytes = toBytes({
            0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0,
            0x12, 0x34,
        });
        auto result = parseEthernetFrame(bytes);
        CHECK(std::holds_alternative<EthernetFrame>(result));
        if (auto* frame = std::get_if<EthernetFrame>(&result)) {
            CHECK(frame->ether_type == 0x1234);
        }
    }

    return wirestack::test::failureCount() == 0 ? 0 : 1;
}
