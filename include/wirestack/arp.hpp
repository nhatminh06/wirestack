#pragma once

#include <cstddef>
#include <cstdint>
#include <optional>
#include <span>
#include <variant>
#include <vector>

#include "wirestack/ipv4_address.hpp"
#include "wirestack/mac_address.hpp"

namespace wirestack {

enum class ArpOperation : std::uint16_t {
    Request = 1,
    Reply = 2,
};

struct ArpPacket {
    ArpOperation operation;
    MacAddress sender_mac;
    Ipv4Address sender_ip;
    MacAddress target_mac;
    Ipv4Address target_ip;
};

enum class ArpParseError {
    TooShort,
    UnsupportedHardwareType,
    UnsupportedProtocolType,
    InvalidHardwareSize,
    InvalidProtocolSize,
    UnsupportedOperation,
};

using ArpParseResult = std::variant<ArpPacket, ArpParseError>;

// Parses the Ethernet + IPv4 ARP form only (hardware type 1, protocol type
// 0x0800, hardware size 6, protocol size 4). `payload` may be longer than
// the 28-byte logical packet (Ethernet minimum-frame padding); only the
// first 28 bytes are interpreted.
ArpParseResult parseArpPacket(std::span<const std::byte> payload);

std::vector<std::byte> serializeArpPacket(const ArpPacket& packet);

// Builds the reply packet for a request, using the given local IP/MAC as
// sender. Does not check whether the request targets the local IP.
ArpPacket makeArpReply(const ArpPacket& request, Ipv4Address local_ip, MacAddress local_mac);

// Applies the local-IP targeting rule: returns a reply only when
// `request.target_ip == local_ip`, nullopt otherwise.
std::optional<ArpPacket> maybeReply(const ArpPacket& request, Ipv4Address local_ip,
                                     MacAddress local_mac);

} // namespace wirestack
