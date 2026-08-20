#include "wirestack/ipv4.hpp"

#include "wirestack/checksum.hpp"

#include "test_util.hpp"

using wirestack::Ipv4Address;
using wirestack::Ipv4Packet;
using wirestack::Ipv4ParseError;
using wirestack::Ipv4SerializeError;
using wirestack::parseIpv4Packet;
using wirestack::serializeIpv4Packet;

namespace {

std::vector<std::byte> toBytes(std::initializer_list<std::uint8_t> values) {
    std::vector<std::byte> out;
    out.reserve(values.size());
    for (auto v : values) {
        out.push_back(static_cast<std::byte>(v));
    }
    return out;
}

// Recomputes and writes the header checksum in place, for tests that
// modify a header field and need a validly-checksummed header again.
void fixChecksum(std::vector<std::byte>& bytes) {
    bytes[10] = std::byte{0x00};
    bytes[11] = std::byte{0x00};
    std::uint16_t checksum = wirestack::internetChecksum(std::span(bytes).first(20));
    bytes[10] = static_cast<std::byte>((checksum >> 8) & 0xff);
    bytes[11] = static_cast<std::byte>(checksum & 0xff);
}

// Hand-built valid header (checksum independently computed, not via
// serializeIpv4Packet): version=4 IHL=5, total_length=24, id=0x1c46,
// flags=DF (0x4000), ttl=64, protocol=1 (ICMP), src=10.0.0.1,
// dst=10.0.0.2, checksum=0x0a9d, payload=de ad be ef. Used for decode-side
// tests -- DF is set here specifically to exercise "DF alone is accepted".
std::vector<std::byte> knownRequestBytes() {
    return toBytes({
        0x45, 0x00,             // version/IHL, DSCP/ECN
        0x00, 0x18,             // total length: 24
        0x1c, 0x46,             // identification
        0x40, 0x00,             // flags: DF, fragment offset 0
        0x40, 0x01,             // ttl=64, protocol=1 (ICMP)
        0x0a, 0x9d,             // header checksum
        0x0a, 0x00, 0x00, 0x01, // source: 10.0.0.1
        0x0a, 0x00, 0x00, 0x02, // destination: 10.0.0.2
        0xde, 0xad, 0xbe, 0xef, // payload
    });
}

// Same semantics as knownRequestBytes, but with flags=0 -- what
// serializeIpv4Packet actually produces, since Ipv4Packet has no stored
// flags/fragment-offset field (every packet Wirestack builds is
// unfragmented) and so cannot reproduce an incoming DF bit on output.
std::vector<std::byte> knownSerializedBytes() {
    return toBytes({
        0x45, 0x00,
        0x00, 0x18,
        0x1c, 0x46,
        0x00, 0x00, // flags: none, fragment offset 0
        0x40, 0x01,
        0x4a, 0x9d, // header checksum (differs from knownRequestBytes: flags word changed)
        0x0a, 0x00, 0x00, 0x01,
        0x0a, 0x00, 0x00, 0x02,
        0xde, 0xad, 0xbe, 0xef,
    });
}

} // namespace

int main() {
    // known-vector header decode
    {
        auto result = parseIpv4Packet(knownRequestBytes());
        CHECK(std::holds_alternative<Ipv4Packet>(result));
        if (auto* packet = std::get_if<Ipv4Packet>(&result)) {
            CHECK(packet->dscp_ecn == 0);
            CHECK(packet->identification == 0x1c46);
            CHECK(packet->ttl == 64);
            CHECK(packet->protocol == 1);
            CHECK(packet->source == *Ipv4Address::parse("10.0.0.1"));
            CHECK(packet->destination == *Ipv4Address::parse("10.0.0.2"));
            CHECK(packet->payload == toBytes({0xde, 0xad, 0xbe, 0xef}));
        }
    }

    // known-vector serialize, exact byte comparison
    {
        Ipv4Packet packet;
        packet.dscp_ecn = 0;
        packet.identification = 0x1c46;
        packet.ttl = 64;
        packet.protocol = 1;
        packet.source = *Ipv4Address::parse("10.0.0.1");
        packet.destination = *Ipv4Address::parse("10.0.0.2");
        packet.payload = toBytes({0xde, 0xad, 0xbe, 0xef});

        auto result = serializeIpv4Packet(packet);
        CHECK(std::holds_alternative<std::vector<std::byte>>(result));
        if (auto* bytes = std::get_if<std::vector<std::byte>>(&result)) {
            CHECK(*bytes == knownSerializedBytes());
        }
    }

    // round trip
    {
        Ipv4Packet original;
        original.dscp_ecn = 0x2e;
        original.identification = 0xabcd;
        original.ttl = 32;
        original.protocol = 6; // TCP, still a valid IPv4 packet to build
        original.source = *Ipv4Address::parse("192.168.1.1");
        original.destination = *Ipv4Address::parse("192.168.1.2");
        original.payload = toBytes({1, 2, 3, 4, 5});

        auto serialized = serializeIpv4Packet(original);
        CHECK(std::holds_alternative<std::vector<std::byte>>(serialized));
        auto* bytes = std::get_if<std::vector<std::byte>>(&serialized);
        CHECK(bytes != nullptr);
        if (bytes != nullptr) {
            auto result = parseIpv4Packet(*bytes);
            CHECK(std::holds_alternative<Ipv4Packet>(result));
            if (auto* packet = std::get_if<Ipv4Packet>(&result)) {
                CHECK(packet->dscp_ecn == original.dscp_ecn);
                CHECK(packet->identification == original.identification);
                CHECK(packet->ttl == original.ttl);
                CHECK(packet->protocol == original.protocol);
                CHECK(packet->source == original.source);
                CHECK(packet->destination == original.destination);
                CHECK(packet->payload == original.payload);
            }
        }
    }

    // malformed: too short
    {
        CHECK(std::holds_alternative<Ipv4ParseError>(parseIpv4Packet({})));

        auto nineteen = knownRequestBytes();
        nineteen.resize(19);
        auto result = parseIpv4Packet(nineteen);
        CHECK(std::holds_alternative<Ipv4ParseError>(result));
        if (auto* err = std::get_if<Ipv4ParseError>(&result)) {
            CHECK(*err == Ipv4ParseError::TooShort);
        }
    }

    // malformed: version != 4
    {
        auto bytes = knownRequestBytes();
        bytes[0] = std::byte{0x65}; // version 6, IHL 5
        auto result = parseIpv4Packet(bytes);
        CHECK(std::holds_alternative<Ipv4ParseError>(result));
        if (auto* err = std::get_if<Ipv4ParseError>(&result)) {
            CHECK(*err == Ipv4ParseError::UnsupportedVersion);
        }
    }

    // malformed: IHL < 5
    {
        auto bytes = knownRequestBytes();
        bytes[0] = std::byte{0x44}; // version 4, IHL 4
        auto result = parseIpv4Packet(bytes);
        CHECK(std::holds_alternative<Ipv4ParseError>(result));
        if (auto* err = std::get_if<Ipv4ParseError>(&result)) {
            CHECK(*err == Ipv4ParseError::InvalidHeaderLength);
        }
    }

    // malformed: IHL > 5 (options, unsupported)
    {
        auto bytes = knownRequestBytes();
        bytes[0] = std::byte{0x46}; // version 4, IHL 6
        auto result = parseIpv4Packet(bytes);
        CHECK(std::holds_alternative<Ipv4ParseError>(result));
        if (auto* err = std::get_if<Ipv4ParseError>(&result)) {
            CHECK(*err == Ipv4ParseError::UnsupportedOptions);
        }
    }

    // malformed: bad header checksum
    {
        auto bytes = knownRequestBytes();
        bytes[11] = std::byte{0x9e}; // flip the low checksum byte
        auto result = parseIpv4Packet(bytes);
        CHECK(std::holds_alternative<Ipv4ParseError>(result));
        if (auto* err = std::get_if<Ipv4ParseError>(&result)) {
            CHECK(*err == Ipv4ParseError::BadChecksum);
        }
    }

    // malformed: total_length > available bytes
    {
        auto bytes = knownRequestBytes();
        bytes.pop_back(); // now 23 bytes, but header still declares 24
        // checksum is unaffected (payload isn't covered by it), so this
        // exercises InvalidTotalLength specifically, not BadChecksum.
        auto result = parseIpv4Packet(bytes);
        CHECK(std::holds_alternative<Ipv4ParseError>(result));
        if (auto* err = std::get_if<Ipv4ParseError>(&result)) {
            CHECK(*err == Ipv4ParseError::InvalidTotalLength);
        }
    }

    // malformed: total_length < header length
    {
        auto bytes = knownRequestBytes();
        // total_length = 10, header checksum must still be recomputed
        // since flipping total_length changes the checksum-covered bytes.
        bytes[2] = std::byte{0x00};
        bytes[3] = std::byte{0x0a};
        fixChecksum(bytes);

        auto result = parseIpv4Packet(bytes);
        CHECK(std::holds_alternative<Ipv4ParseError>(result));
        if (auto* err = std::get_if<Ipv4ParseError>(&result)) {
            CHECK(*err == Ipv4ParseError::InvalidTotalLength);
        }
    }

    // malformed: MF set (fragmented)
    {
        auto bytes = knownRequestBytes();
        bytes[6] = std::byte{0x20}; // MF bit, no DF, offset 0
        fixChecksum(bytes);

        auto result = parseIpv4Packet(bytes);
        CHECK(std::holds_alternative<Ipv4ParseError>(result));
        if (auto* err = std::get_if<Ipv4ParseError>(&result)) {
            CHECK(*err == Ipv4ParseError::Fragmented);
        }
    }

    // malformed: nonzero fragment offset
    {
        auto bytes = knownRequestBytes();
        bytes[6] = std::byte{0x00};
        bytes[7] = std::byte{0x08}; // offset = 8, no flags
        fixChecksum(bytes);

        auto result = parseIpv4Packet(bytes);
        CHECK(std::holds_alternative<Ipv4ParseError>(result));
        if (auto* err = std::get_if<Ipv4ParseError>(&result)) {
            CHECK(*err == Ipv4ParseError::Fragmented);
        }
    }

    // positive: DF alone (already set in knownRequestBytes) parses fine
    {
        auto result = parseIpv4Packet(knownRequestBytes());
        CHECK(std::holds_alternative<Ipv4Packet>(result));
    }

    // Ethernet trailing padding: total_length=24 declared, extra bytes appended
    {
        auto bytes = knownRequestBytes();
        bytes.insert(bytes.end(), 10, std::byte{0x00});
        auto result = parseIpv4Packet(bytes);
        CHECK(std::holds_alternative<Ipv4Packet>(result));
        if (auto* packet = std::get_if<Ipv4Packet>(&result)) {
            CHECK(packet->payload == toBytes({0xde, 0xad, 0xbe, 0xef}));
            CHECK(packet->payload.size() == 4);
        }
    }

    // unsupported upper protocol remains valid IPv4
    {
        auto bytes = knownRequestBytes();
        bytes[9] = std::byte{0x11}; // protocol = 17 (UDP)
        fixChecksum(bytes);

        auto result = parseIpv4Packet(bytes);
        CHECK(std::holds_alternative<Ipv4Packet>(result));
        if (auto* packet = std::get_if<Ipv4Packet>(&result)) {
            CHECK(packet->protocol == 17);
        }
    }

    // serialization: oversized payload fails explicitly
    {
        Ipv4Packet packet;
        packet.source = *Ipv4Address::parse("10.0.0.1");
        packet.destination = *Ipv4Address::parse("10.0.0.2");
        packet.payload.resize(65536 - 20 + 1); // total_length would be 65537
        auto result = serializeIpv4Packet(packet);
        CHECK(std::holds_alternative<Ipv4SerializeError>(result));
        if (auto* err = std::get_if<Ipv4SerializeError>(&result)) {
            CHECK(*err == Ipv4SerializeError::PayloadTooLarge);
        }
    }

    return wirestack::test::failureCount() == 0 ? 0 : 1;
}
