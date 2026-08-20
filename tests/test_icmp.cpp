#include "wirestack/icmp.hpp"

#include "wirestack/checksum.hpp"

#include "test_util.hpp"

using wirestack::IcmpEcho;
using wirestack::IcmpEchoType;
using wirestack::IcmpParseError;
using wirestack::makeEchoReply;
using wirestack::parseIcmpEcho;
using wirestack::serializeIcmpEcho;

namespace {

std::vector<std::byte> toBytes(std::initializer_list<std::uint8_t> values) {
    std::vector<std::byte> out;
    out.reserve(values.size());
    for (auto v : values) {
        out.push_back(static_cast<std::byte>(v));
    }
    return out;
}

// Independently-checksummed Echo Request: id=0x1234, seq=0x0001,
// payload="abcdefgh". Not generated via serializeIcmpEcho.
std::vector<std::byte> knownRequestBytes() {
    return toBytes({
        0x08, 0x00,             // type=8 (EchoRequest), code=0
        0x54, 0x35,             // checksum
        0x12, 0x34,             // identifier
        0x00, 0x01,             // sequence
        0x61, 0x62, 0x63, 0x64, 0x65, 0x66, 0x67, 0x68, // "abcdefgh"
    });
}

// Same identifier/sequence/payload, type=0 (EchoReply), independently
// checksummed.
std::vector<std::byte> knownReplyBytes() {
    return toBytes({
        0x00, 0x00,
        0x5c, 0x35,
        0x12, 0x34,
        0x00, 0x01,
        0x61, 0x62, 0x63, 0x64, 0x65, 0x66, 0x67, 0x68,
    });
}

void fixChecksum(std::vector<std::byte>& bytes) {
    bytes[2] = std::byte{0x00};
    bytes[3] = std::byte{0x00};
    std::uint16_t checksum = wirestack::internetChecksum(bytes);
    bytes[2] = static_cast<std::byte>((checksum >> 8) & 0xff);
    bytes[3] = static_cast<std::byte>(checksum & 0xff);
}

} // namespace

int main() {
    // known-vector Echo Request decode
    {
        auto result = parseIcmpEcho(knownRequestBytes());
        CHECK(std::holds_alternative<IcmpEcho>(result));
        if (auto* message = std::get_if<IcmpEcho>(&result)) {
            CHECK(message->type == IcmpEchoType::EchoRequest);
            CHECK(message->identifier == 0x1234);
            CHECK(message->sequence == 0x0001);
            CHECK(message->payload == toBytes({0x61, 0x62, 0x63, 0x64, 0x65, 0x66, 0x67, 0x68}));
        }
    }

    // known-vector Echo Reply serialize, exact byte comparison
    {
        IcmpEcho reply;
        reply.type = IcmpEchoType::EchoReply;
        reply.identifier = 0x1234;
        reply.sequence = 0x0001;
        reply.payload = toBytes({0x61, 0x62, 0x63, 0x64, 0x65, 0x66, 0x67, 0x68});

        CHECK(serializeIcmpEcho(reply) == knownReplyBytes());
    }

    // malformed: too short
    {
        CHECK(std::holds_alternative<IcmpParseError>(parseIcmpEcho({})));

        auto seven = knownRequestBytes();
        seven.resize(7);
        auto result = parseIcmpEcho(seven);
        CHECK(std::holds_alternative<IcmpParseError>(result));
        if (auto* err = std::get_if<IcmpParseError>(&result)) {
            CHECK(*err == IcmpParseError::TooShort);
        }
    }

    // malformed: bad checksum
    {
        auto bytes = knownRequestBytes();
        bytes[3] = std::byte{0x36}; // flip a checksum byte
        auto result = parseIcmpEcho(bytes);
        CHECK(std::holds_alternative<IcmpParseError>(result));
        if (auto* err = std::get_if<IcmpParseError>(&result)) {
            CHECK(*err == IcmpParseError::BadChecksum);
        }
    }

    // malformed: nonzero code
    {
        auto bytes = knownRequestBytes();
        bytes[1] = std::byte{0x01};
        fixChecksum(bytes);
        auto result = parseIcmpEcho(bytes);
        CHECK(std::holds_alternative<IcmpParseError>(result));
        if (auto* err = std::get_if<IcmpParseError>(&result)) {
            CHECK(*err == IcmpParseError::InvalidCode);
        }
    }

    // malformed: unsupported type (3 = Destination Unreachable)
    {
        auto bytes = knownRequestBytes();
        bytes[0] = std::byte{0x03};
        fixChecksum(bytes);
        auto result = parseIcmpEcho(bytes);
        CHECK(std::holds_alternative<IcmpParseError>(result));
        if (auto* err = std::get_if<IcmpParseError>(&result)) {
            CHECK(*err == IcmpParseError::UnsupportedType);
        }
    }

    // odd-length payload round trip
    {
        IcmpEcho original;
        original.type = IcmpEchoType::EchoRequest;
        original.identifier = 0x0001;
        original.sequence = 0x0002;
        original.payload = toBytes({1, 2, 3, 4, 5}); // odd length

        auto serialized = serializeIcmpEcho(original);
        auto result = parseIcmpEcho(serialized);
        CHECK(std::holds_alternative<IcmpEcho>(result));
        if (auto* message = std::get_if<IcmpEcho>(&result)) {
            CHECK(message->payload == original.payload);
        }
    }

    // makeEchoReply: identifier/sequence/payload preserved, type changes,
    // including a payload containing zero bytes (not treated as a C string).
    {
        IcmpEcho request;
        request.type = IcmpEchoType::EchoRequest;
        request.identifier = 0xbeef;
        request.sequence = 0x0007;
        request.payload = toBytes({0x00, 0xff, 0x00, 0x01, 0x00});

        auto reply = makeEchoReply(request);
        CHECK(reply.type == IcmpEchoType::EchoReply);
        CHECK(reply.identifier == request.identifier);
        CHECK(reply.sequence == request.sequence);
        CHECK(reply.payload == request.payload);
        CHECK(reply.payload.size() == 5);
    }

    return wirestack::test::failureCount() == 0 ? 0 : 1;
}
