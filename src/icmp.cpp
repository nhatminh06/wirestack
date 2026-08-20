#include "wirestack/icmp.hpp"

#include "wirestack/checksum.hpp"

namespace wirestack {

namespace {

constexpr std::size_t kHeaderSize = 8;

constexpr std::size_t kTypeOffset = 0;
constexpr std::size_t kCodeOffset = 1;
constexpr std::size_t kChecksumOffset = 2;
constexpr std::size_t kIdentifierOffset = 4;
constexpr std::size_t kSequenceOffset = 6;

std::uint16_t readBigEndian16(std::span<const std::byte> data, std::size_t offset) {
    return static_cast<std::uint16_t>((static_cast<std::uint16_t>(data[offset]) << 8) |
                                       static_cast<std::uint16_t>(data[offset + 1]));
}

void writeBigEndian16(std::vector<std::byte>& out, std::uint16_t value) {
    out.push_back(static_cast<std::byte>((value >> 8) & 0xff));
    out.push_back(static_cast<std::byte>(value & 0xff));
}

} // namespace

IcmpParseResult parseIcmpEcho(std::span<const std::byte> data) {
    if (data.size() < kHeaderSize) {
        return IcmpParseError::TooShort;
    }

    std::uint8_t raw_type = static_cast<std::uint8_t>(data[kTypeOffset]);
    if (raw_type != static_cast<std::uint8_t>(IcmpEchoType::EchoRequest) &&
        raw_type != static_cast<std::uint8_t>(IcmpEchoType::EchoReply)) {
        return IcmpParseError::UnsupportedType;
    }

    std::uint8_t code = static_cast<std::uint8_t>(data[kCodeOffset]);
    if (code != 0) {
        return IcmpParseError::InvalidCode;
    }

    if (internetChecksum(data) != 0) {
        return IcmpParseError::BadChecksum;
    }

    IcmpEcho message;
    message.type = static_cast<IcmpEchoType>(raw_type);
    message.identifier = readBigEndian16(data, kIdentifierOffset);
    message.sequence = readBigEndian16(data, kSequenceOffset);

    auto payload_bytes = data.subspan(kHeaderSize);
    message.payload.assign(payload_bytes.begin(), payload_bytes.end());

    return message;
}

std::vector<std::byte> serializeIcmpEcho(const IcmpEcho& message) {
    std::vector<std::byte> out;
    out.reserve(kHeaderSize + message.payload.size());

    out.push_back(static_cast<std::byte>(message.type));
    out.push_back(static_cast<std::byte>(0)); // code
    writeBigEndian16(out, 0);                 // checksum placeholder, filled in below
    writeBigEndian16(out, message.identifier);
    writeBigEndian16(out, message.sequence);
    out.insert(out.end(), message.payload.begin(), message.payload.end());

    std::uint16_t checksum = internetChecksum(out);
    out[kChecksumOffset] = static_cast<std::byte>((checksum >> 8) & 0xff);
    out[kChecksumOffset + 1] = static_cast<std::byte>(checksum & 0xff);

    return out;
}

IcmpEcho makeEchoReply(const IcmpEcho& request) {
    IcmpEcho reply;
    reply.type = IcmpEchoType::EchoReply;
    reply.identifier = request.identifier;
    reply.sequence = request.sequence;
    reply.payload = request.payload;
    return reply;
}

} // namespace wirestack
