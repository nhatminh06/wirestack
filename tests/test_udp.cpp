#include "wirestack/udp.hpp"

#include "wirestack/checksum.hpp"

#include "test_util.hpp"

using wirestack::Ipv4Address;
using wirestack::parseUdpDatagram;
using wirestack::serializeUdpDatagram;
using wirestack::UdpDatagram;
using wirestack::UdpParseError;
using wirestack::UdpSerializeError;

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

// src=10.0.0.1 dst=10.0.0.2 srcport=54321 dstport=9000 payload="hello"
// (odd length: 5 bytes). Checksum 0xb0a5 independently computed (Python,
// RFC 1071 algorithm over pseudo-header + header + payload) and hardcoded
// here, not produced by serializeUdpDatagram.
Ipv4Address knownSource() {
    return *Ipv4Address::parse("10.0.0.1");
}
Ipv4Address knownDestination() {
    return *Ipv4Address::parse("10.0.0.2");
}
std::vector<std::byte> knownDatagramBytes() {
    return toBytes({
        0xd4, 0x31, // source port 54321
        0x23, 0x28, // destination port 9000
        0x00, 0x0d, // length 13
        0xb0, 0xa5, // checksum
        0x68, 0x65, 0x6c, 0x6c, 0x6f, // "hello"
    });
}

void fixChecksum(std::vector<std::byte>& bytes, Ipv4Address source, Ipv4Address destination) {
    bytes[6] = std::byte{0x00};
    bytes[7] = std::byte{0x00};
    std::vector<std::byte> pseudo;
    for (auto b : source.bytes()) pseudo.push_back(static_cast<std::byte>(b));
    for (auto b : destination.bytes()) pseudo.push_back(static_cast<std::byte>(b));
    pseudo.push_back(std::byte{0});
    pseudo.push_back(std::byte{17});
    auto len = static_cast<std::uint16_t>(bytes.size());
    pseudo.push_back(static_cast<std::byte>((len >> 8) & 0xff));
    pseudo.push_back(static_cast<std::byte>(len & 0xff));
    pseudo.insert(pseudo.end(), bytes.begin(), bytes.end());
    std::uint16_t checksum = wirestack::internetChecksum(pseudo);
    bytes[6] = static_cast<std::byte>((checksum >> 8) & 0xff);
    bytes[7] = static_cast<std::byte>(checksum & 0xff);
}

} // namespace

int main() {
    // known-vector parse
    {
        auto result = parseUdpDatagram(knownDatagramBytes(), knownSource(), knownDestination());
        CHECK(std::holds_alternative<UdpDatagram>(result));
        if (auto* datagram = std::get_if<UdpDatagram>(&result)) {
            CHECK(datagram->source_port == 54321);
            CHECK(datagram->destination_port == 9000);
            CHECK(datagram->payload == toBytes("hello"));
        }
    }

    // known-vector serialize, exact byte comparison
    {
        UdpDatagram datagram;
        datagram.source_port = 54321;
        datagram.destination_port = 9000;
        datagram.payload = toBytes("hello");

        auto result = serializeUdpDatagram(datagram, knownSource(), knownDestination());
        CHECK(std::holds_alternative<std::vector<std::byte>>(result));
        if (auto* bytes = std::get_if<std::vector<std::byte>>(&result)) {
            CHECK(*bytes == knownDatagramBytes());
        }
    }

    // independent checksum vector: src=192.168.1.10 dst=192.168.1.20
    // srcport=12345 dstport=80 payload="test data" (9 bytes, odd) ->
    // checksum 0x8121, computed independently in Python.
    {
        auto source = *Ipv4Address::parse("192.168.1.10");
        auto destination = *Ipv4Address::parse("192.168.1.20");
        UdpDatagram datagram;
        datagram.source_port = 12345;
        datagram.destination_port = 80;
        datagram.payload = toBytes("test data");

        auto result = serializeUdpDatagram(datagram, source, destination);
        CHECK(std::holds_alternative<std::vector<std::byte>>(result));
        if (auto* bytes = std::get_if<std::vector<std::byte>>(&result)) {
            CHECK((*bytes)[6] == std::byte{0x81});
            CHECK((*bytes)[7] == std::byte{0x21});
        }
    }

    // round trip
    {
        UdpDatagram original;
        original.source_port = 1;
        original.destination_port = 65535;
        original.payload = toBytes({1, 2, 3, 4});

        auto source = *Ipv4Address::parse("172.16.0.1");
        auto destination = *Ipv4Address::parse("172.16.0.2");
        auto serialized = serializeUdpDatagram(original, source, destination);
        CHECK(std::holds_alternative<std::vector<std::byte>>(serialized));
        auto* bytes = std::get_if<std::vector<std::byte>>(&serialized);
        CHECK(bytes != nullptr);
        if (bytes != nullptr) {
            auto result = parseUdpDatagram(*bytes, source, destination);
            CHECK(std::holds_alternative<UdpDatagram>(result));
            if (auto* datagram = std::get_if<UdpDatagram>(&result)) {
                CHECK(datagram->source_port == original.source_port);
                CHECK(datagram->destination_port == original.destination_port);
                CHECK(datagram->payload == original.payload);
            }
        }
    }

    // malformed: 0-byte and 7-byte input -> TooShort
    {
        CHECK(std::holds_alternative<UdpParseError>(
            parseUdpDatagram({}, knownSource(), knownDestination())));

        auto seven = knownDatagramBytes();
        seven.resize(7);
        auto result = parseUdpDatagram(seven, knownSource(), knownDestination());
        CHECK(std::holds_alternative<UdpParseError>(result));
        if (auto* err = std::get_if<UdpParseError>(&result)) {
            CHECK(*err == UdpParseError::TooShort);
        }
    }

    // malformed: declared length < 8
    {
        auto bytes = knownDatagramBytes();
        bytes[4] = std::byte{0x00};
        bytes[5] = std::byte{0x07};
        fixChecksum(bytes, knownSource(), knownDestination());
        auto result = parseUdpDatagram(bytes, knownSource(), knownDestination());
        CHECK(std::holds_alternative<UdpParseError>(result));
        if (auto* err = std::get_if<UdpParseError>(&result)) {
            CHECK(*err == UdpParseError::InvalidLength);
        }
    }

    // malformed: declared length > available bytes
    {
        auto bytes = knownDatagramBytes();
        bytes.pop_back(); // 12 bytes available, header still declares 13
        auto result = parseUdpDatagram(bytes, knownSource(), knownDestination());
        CHECK(std::holds_alternative<UdpParseError>(result));
        if (auto* err = std::get_if<UdpParseError>(&result)) {
            CHECK(*err == UdpParseError::InvalidLength);
        }
    }

    // positive: length == 8, empty payload
    {
        std::vector<std::byte> bytes = toBytes({0x00, 0x01, 0x00, 0x02, 0x00, 0x08, 0x00, 0x00});
        fixChecksum(bytes, knownSource(), knownDestination());
        auto result = parseUdpDatagram(bytes, knownSource(), knownDestination());
        CHECK(std::holds_alternative<UdpDatagram>(result));
        if (auto* datagram = std::get_if<UdpDatagram>(&result)) {
            CHECK(datagram->payload.empty());
        }
    }

    // Ethernet/IPv4-padding-style safety: extra bytes beyond the declared
    // UDP length must not become part of the payload.
    {
        auto bytes = knownDatagramBytes();
        bytes.insert(bytes.end(), 6, std::byte{0x00});
        auto result = parseUdpDatagram(bytes, knownSource(), knownDestination());
        CHECK(std::holds_alternative<UdpDatagram>(result));
        if (auto* datagram = std::get_if<UdpDatagram>(&result)) {
            CHECK(datagram->payload == toBytes("hello"));
            CHECK(datagram->payload.size() == 5);
        }
    }

    // checksum == 0 accepted without validation, even over corrupted data
    {
        auto bytes = knownDatagramBytes();
        bytes[6] = std::byte{0x00};
        bytes[7] = std::byte{0x00};
        bytes[8] = std::byte{0xff}; // corrupt payload after zeroing checksum
        auto result = parseUdpDatagram(bytes, knownSource(), knownDestination());
        CHECK(std::holds_alternative<UdpDatagram>(result));
    }

    // nonzero but wrong checksum -> BadChecksum
    {
        auto bytes = knownDatagramBytes();
        bytes[8] = std::byte{0xff}; // corrupt payload, checksum unchanged
        auto result = parseUdpDatagram(bytes, knownSource(), knownDestination());
        CHECK(std::holds_alternative<UdpParseError>(result));
        if (auto* err = std::get_if<UdpParseError>(&result)) {
            CHECK(*err == UdpParseError::BadChecksum);
        }
    }

    // pseudo-header sensitivity: same bytes, different destination IP ->
    // must now report BadChecksum (proves the pseudo-header actually
    // participates in validation, not just the UDP bytes themselves).
    {
        auto wrong_destination = *Ipv4Address::parse("10.0.0.3");
        auto result = parseUdpDatagram(knownDatagramBytes(), knownSource(), wrong_destination);
        CHECK(std::holds_alternative<UdpParseError>(result));
        if (auto* err = std::get_if<UdpParseError>(&result)) {
            CHECK(*err == UdpParseError::BadChecksum);
        }
    }

    // computed checksum of exactly 0 is transmitted as 0xffff: src=10.0.0.2
    // dst=10.0.0.1 srcport=9000 dstport=54321 payload={0xf4,0x7d} was found
    // (independently, by search) to produce a raw computed checksum of
    // 0x0000.
    {
        auto source = *Ipv4Address::parse("10.0.0.2");
        auto destination = *Ipv4Address::parse("10.0.0.1");
        UdpDatagram datagram;
        datagram.source_port = 9000;
        datagram.destination_port = 54321;
        datagram.payload = toBytes({0xf4, 0x7d});

        auto result = serializeUdpDatagram(datagram, source, destination);
        CHECK(std::holds_alternative<std::vector<std::byte>>(result));
        if (auto* bytes = std::get_if<std::vector<std::byte>>(&result)) {
            CHECK((*bytes)[6] == std::byte{0xff});
            CHECK((*bytes)[7] == std::byte{0xff});
        }
    }

    // serialization: oversized payload fails explicitly
    {
        UdpDatagram datagram;
        datagram.source_port = 1;
        datagram.destination_port = 2;
        datagram.payload.resize(65536 - 8 + 1);
        auto result = serializeUdpDatagram(datagram, knownSource(), knownDestination());
        CHECK(std::holds_alternative<UdpSerializeError>(result));
        if (auto* err = std::get_if<UdpSerializeError>(&result)) {
            CHECK(*err == UdpSerializeError::PayloadTooLarge);
        }
    }

    return wirestack::test::failureCount() == 0 ? 0 : 1;
}
