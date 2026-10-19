#pragma once

#include <cstddef>
#include <cstdint>
#include <span>
#include <variant>
#include <vector>

#include "wirestack/mac_address.hpp"

namespace wirestack {

enum class EtherType : std::uint16_t {
    Ipv4 = 0x0800,
    Arp = 0x0806,
};

struct EthernetFrame {
    MacAddress destination;
    MacAddress source;
    std::uint16_t ether_type = 0;
    std::vector<std::byte> payload;
};

inline constexpr std::size_t kMaxEthernetFrameLength = 65535;

enum class EthernetParseError {
    TooShort,
    TooLong,
};

using EthernetParseResult = std::variant<EthernetFrame, EthernetParseError>;

// Parses an Ethernet II frame. `data` must contain at least the 14-byte
// header (destination + source + ethertype); everything after is payload.
// Inputs larger than kMaxEthernetFrameLength are rejected to bound allocation.
EthernetParseResult parseEthernetFrame(std::span<const std::byte> data);

std::vector<std::byte> serializeEthernetFrame(const EthernetFrame& frame);

} // namespace wirestack
