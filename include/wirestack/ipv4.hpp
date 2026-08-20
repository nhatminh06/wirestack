#pragma once

#include <cstddef>
#include <cstdint>
#include <span>
#include <variant>
#include <vector>

#include "wirestack/ipv4_address.hpp"

namespace wirestack {

struct Ipv4Packet {
    std::uint8_t dscp_ecn = 0;
    std::uint16_t identification = 0;
    std::uint8_t ttl = 64;
    std::uint8_t protocol = 0;
    Ipv4Address source;
    Ipv4Address destination;
    std::vector<std::byte> payload;
};

enum class Ipv4ParseError {
    TooShort,
    UnsupportedVersion,
    InvalidHeaderLength,
    UnsupportedOptions,
    InvalidTotalLength,
    Fragmented,
    BadChecksum,
};

using Ipv4ParseResult = std::variant<Ipv4Packet, Ipv4ParseError>;

// `data` is the Ethernet payload; it may contain trailing bytes beyond the
// packet's own declared total length (Ethernet minimum-frame padding).
// Only the base 20-byte header (IHL == 5) is supported; fragmented packets
// (MF set or a nonzero fragment offset) are rejected. DF alone is accepted.
Ipv4ParseResult parseIpv4Packet(std::span<const std::byte> data);

enum class Ipv4SerializeError {
    PayloadTooLarge,
};

using Ipv4SerializeResult = std::variant<std::vector<std::byte>, Ipv4SerializeError>;

// Always serializes version=4, IHL=5, an unfragmented header (DF-equivalent,
// offset 0). Fails explicitly rather than truncating if the payload would
// push total_length past 65535.
Ipv4SerializeResult serializeIpv4Packet(const Ipv4Packet& packet);

} // namespace wirestack
