#include "wirestack/ipv4.hpp"

#include "wirestack/checksum.hpp"

namespace wirestack {

namespace {

constexpr std::size_t kHeaderSize = 20;
constexpr std::uint8_t kSupportedVersion = 4;
constexpr std::uint8_t kSupportedIhl = 5;
constexpr std::size_t kMaxTotalLength = 65535;

constexpr std::size_t kVersionIhlOffset = 0;
constexpr std::size_t kDscpEcnOffset = 1;
constexpr std::size_t kTotalLengthOffset = 2;
constexpr std::size_t kIdentificationOffset = 4;
constexpr std::size_t kFlagsFragmentOffset = 6;
constexpr std::size_t kTtlOffset = 8;
constexpr std::size_t kProtocolOffset = 9;
constexpr std::size_t kChecksumOffset = 10;
constexpr std::size_t kSourceOffset = 12;
constexpr std::size_t kDestinationOffset = 16;

constexpr std::uint16_t kFlagMoreFragments = 0x2000; // bit 13 of the flags+offset word
constexpr std::uint16_t kFragmentOffsetMask = 0x1fff; // low 13 bits

std::uint16_t readBigEndian16(std::span<const std::byte> data, std::size_t offset) {
    return static_cast<std::uint16_t>((static_cast<std::uint16_t>(data[offset]) << 8) |
                                       static_cast<std::uint16_t>(data[offset + 1]));
}

void writeBigEndian16(std::vector<std::byte>& out, std::uint16_t value) {
    out.push_back(static_cast<std::byte>((value >> 8) & 0xff));
    out.push_back(static_cast<std::byte>(value & 0xff));
}

Ipv4Address readIpv4Address(std::span<const std::byte> data, std::size_t offset) {
    std::array<std::uint8_t, Ipv4Address::kSize> bytes{};
    for (std::size_t i = 0; i < Ipv4Address::kSize; ++i) {
        bytes[i] = static_cast<std::uint8_t>(data[offset + i]);
    }
    return Ipv4Address(bytes);
}

void writeIpv4Address(std::vector<std::byte>& out, const Ipv4Address& ip) {
    for (std::uint8_t byte : ip.bytes()) {
        out.push_back(static_cast<std::byte>(byte));
    }
}

} // namespace

Ipv4ParseResult parseIpv4Packet(std::span<const std::byte> data) {
    if (data.size() < kHeaderSize) {
        return Ipv4ParseError::TooShort;
    }

    std::uint8_t version_ihl = static_cast<std::uint8_t>(data[kVersionIhlOffset]);
    std::uint8_t version = static_cast<std::uint8_t>(version_ihl >> 4);
    std::uint8_t ihl = static_cast<std::uint8_t>(version_ihl & 0x0f);

    if (version != kSupportedVersion) {
        return Ipv4ParseError::UnsupportedVersion;
    }
    if (ihl < kSupportedIhl) {
        return Ipv4ParseError::InvalidHeaderLength;
    }
    if (ihl != kSupportedIhl) {
        return Ipv4ParseError::UnsupportedOptions;
    }

    // Checksum covers only the fixed 20-byte header and does not depend on
    // total_length, so it can be validated before total_length is trusted.
    if (internetChecksum(data.first(kHeaderSize)) != 0) {
        return Ipv4ParseError::BadChecksum;
    }

    std::uint16_t total_length = readBigEndian16(data, kTotalLengthOffset);
    if (total_length < kHeaderSize || total_length > data.size()) {
        return Ipv4ParseError::InvalidTotalLength;
    }

    std::uint16_t flags_fragment = readBigEndian16(data, kFlagsFragmentOffset);
    bool more_fragments = (flags_fragment & kFlagMoreFragments) != 0;
    std::uint16_t fragment_offset = flags_fragment & kFragmentOffsetMask;
    if (more_fragments || fragment_offset != 0) {
        return Ipv4ParseError::Fragmented;
    }

    Ipv4Packet packet;
    packet.dscp_ecn = static_cast<std::uint8_t>(data[kDscpEcnOffset]);
    packet.identification = readBigEndian16(data, kIdentificationOffset);
    packet.ttl = static_cast<std::uint8_t>(data[kTtlOffset]);
    packet.protocol = static_cast<std::uint8_t>(data[kProtocolOffset]);
    packet.source = readIpv4Address(data, kSourceOffset);
    packet.destination = readIpv4Address(data, kDestinationOffset);

    auto payload_bytes = data.subspan(kHeaderSize, total_length - kHeaderSize);
    packet.payload.assign(payload_bytes.begin(), payload_bytes.end());

    return packet;
}

Ipv4SerializeResult serializeIpv4Packet(const Ipv4Packet& packet) {
    std::size_t total_length = kHeaderSize + packet.payload.size();
    if (total_length > kMaxTotalLength) {
        return Ipv4SerializeError::PayloadTooLarge;
    }

    std::vector<std::byte> out;
    out.reserve(total_length);

    out.push_back(static_cast<std::byte>((kSupportedVersion << 4) | kSupportedIhl));
    out.push_back(static_cast<std::byte>(packet.dscp_ecn));
    writeBigEndian16(out, static_cast<std::uint16_t>(total_length));
    writeBigEndian16(out, packet.identification);
    writeBigEndian16(out, 0); // unfragmented: no flags, offset 0
    out.push_back(static_cast<std::byte>(packet.ttl));
    out.push_back(static_cast<std::byte>(packet.protocol));
    writeBigEndian16(out, 0); // checksum placeholder, filled in below
    writeIpv4Address(out, packet.source);
    writeIpv4Address(out, packet.destination);

    std::uint16_t checksum = internetChecksum(std::span(out).first(kHeaderSize));
    out[kChecksumOffset] = static_cast<std::byte>((checksum >> 8) & 0xff);
    out[kChecksumOffset + 1] = static_cast<std::byte>(checksum & 0xff);

    out.insert(out.end(), packet.payload.begin(), packet.payload.end());

    return out;
}

} // namespace wirestack
