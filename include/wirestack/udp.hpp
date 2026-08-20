#pragma once

#include <cstddef>
#include <cstdint>
#include <span>
#include <variant>
#include <vector>

#include "wirestack/ipv4_address.hpp"

namespace wirestack {

struct UdpDatagram {
    std::uint16_t source_port;
    std::uint16_t destination_port;
    std::vector<std::byte> payload;
};

enum class UdpParseError {
    TooShort,
    InvalidLength,
    BadChecksum,
};

using UdpParseResult = std::variant<UdpDatagram, UdpParseError>;

// `bytes` is the IPv4 payload (already trimmed to IPv4's declared total
// length). `source`/`destination` are the IPv4 addresses from that same
// packet, needed only for the pseudo-header checksum -- UdpDatagram itself
// does not depend on Ipv4Packet. A checksum field of 0 means "not
// provided" for IPv4 UDP and is accepted without validation; any other
// value is validated against the pseudo-header.
UdpParseResult parseUdpDatagram(std::span<const std::byte> bytes, Ipv4Address source,
                                 Ipv4Address destination);

enum class UdpSerializeError {
    PayloadTooLarge,
};

using UdpSerializeResult = std::variant<std::vector<std::byte>, UdpSerializeError>;

// Always generates a real checksum (never emits the "no checksum"
// zero encoding).
UdpSerializeResult serializeUdpDatagram(const UdpDatagram& datagram, Ipv4Address source,
                                         Ipv4Address destination);

} // namespace wirestack
