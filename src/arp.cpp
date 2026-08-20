#include "wirestack/arp.hpp"

namespace wirestack {

namespace {

constexpr std::size_t kPacketSize = 28;

constexpr std::size_t kHardwareTypeOffset = 0;
constexpr std::size_t kProtocolTypeOffset = 2;
constexpr std::size_t kHardwareSizeOffset = 4;
constexpr std::size_t kProtocolSizeOffset = 5;
constexpr std::size_t kOperationOffset = 6;
constexpr std::size_t kSenderMacOffset = 8;
constexpr std::size_t kSenderIpOffset = 14;
constexpr std::size_t kTargetMacOffset = 18;
constexpr std::size_t kTargetIpOffset = 24;

constexpr std::uint16_t kHardwareTypeEthernet = 1;
constexpr std::uint16_t kProtocolTypeIpv4 = 0x0800;
constexpr std::uint8_t kHardwareSizeEthernet = 6;
constexpr std::uint8_t kProtocolSizeIpv4 = 4;

std::uint16_t readBigEndian16(std::span<const std::byte> data, std::size_t offset) {
    return static_cast<std::uint16_t>((static_cast<std::uint16_t>(data[offset]) << 8) |
                                       static_cast<std::uint16_t>(data[offset + 1]));
}

void writeBigEndian16(std::vector<std::byte>& out, std::uint16_t value) {
    out.push_back(static_cast<std::byte>((value >> 8) & 0xff));
    out.push_back(static_cast<std::byte>(value & 0xff));
}

MacAddress readMacAddress(std::span<const std::byte> data, std::size_t offset) {
    std::array<std::uint8_t, MacAddress::kSize> bytes{};
    for (std::size_t i = 0; i < MacAddress::kSize; ++i) {
        bytes[i] = static_cast<std::uint8_t>(data[offset + i]);
    }
    return MacAddress(bytes);
}

void writeMacAddress(std::vector<std::byte>& out, const MacAddress& mac) {
    for (std::uint8_t byte : mac.bytes()) {
        out.push_back(static_cast<std::byte>(byte));
    }
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

ArpParseResult parseArpPacket(std::span<const std::byte> payload) {
    if (payload.size() < kPacketSize) {
        return ArpParseError::TooShort;
    }

    if (readBigEndian16(payload, kHardwareTypeOffset) != kHardwareTypeEthernet) {
        return ArpParseError::UnsupportedHardwareType;
    }
    if (readBigEndian16(payload, kProtocolTypeOffset) != kProtocolTypeIpv4) {
        return ArpParseError::UnsupportedProtocolType;
    }
    if (static_cast<std::uint8_t>(payload[kHardwareSizeOffset]) != kHardwareSizeEthernet) {
        return ArpParseError::InvalidHardwareSize;
    }
    if (static_cast<std::uint8_t>(payload[kProtocolSizeOffset]) != kProtocolSizeIpv4) {
        return ArpParseError::InvalidProtocolSize;
    }

    std::uint16_t raw_operation = readBigEndian16(payload, kOperationOffset);
    if (raw_operation != static_cast<std::uint16_t>(ArpOperation::Request) &&
        raw_operation != static_cast<std::uint16_t>(ArpOperation::Reply)) {
        return ArpParseError::UnsupportedOperation;
    }

    ArpPacket packet;
    packet.operation = static_cast<ArpOperation>(raw_operation);
    packet.sender_mac = readMacAddress(payload, kSenderMacOffset);
    packet.sender_ip = readIpv4Address(payload, kSenderIpOffset);
    packet.target_mac = readMacAddress(payload, kTargetMacOffset);
    packet.target_ip = readIpv4Address(payload, kTargetIpOffset);
    return packet;
}

std::vector<std::byte> serializeArpPacket(const ArpPacket& packet) {
    std::vector<std::byte> out;
    out.reserve(kPacketSize);

    writeBigEndian16(out, kHardwareTypeEthernet);
    writeBigEndian16(out, kProtocolTypeIpv4);
    out.push_back(static_cast<std::byte>(kHardwareSizeEthernet));
    out.push_back(static_cast<std::byte>(kProtocolSizeIpv4));
    writeBigEndian16(out, static_cast<std::uint16_t>(packet.operation));
    writeMacAddress(out, packet.sender_mac);
    writeIpv4Address(out, packet.sender_ip);
    writeMacAddress(out, packet.target_mac);
    writeIpv4Address(out, packet.target_ip);

    return out;
}

ArpPacket makeArpReply(const ArpPacket& request, Ipv4Address local_ip, MacAddress local_mac) {
    ArpPacket reply;
    reply.operation = ArpOperation::Reply;
    reply.sender_mac = local_mac;
    reply.sender_ip = local_ip;
    reply.target_mac = request.sender_mac;
    reply.target_ip = request.sender_ip;
    return reply;
}

std::optional<ArpPacket> maybeReply(const ArpPacket& request, Ipv4Address local_ip,
                                     MacAddress local_mac) {
    if (request.target_ip != local_ip) {
        return std::nullopt;
    }
    return makeArpReply(request, local_ip, local_mac);
}

} // namespace wirestack
