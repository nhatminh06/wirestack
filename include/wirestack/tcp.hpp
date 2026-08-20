#pragma once

#include <cstddef>
#include <cstdint>
#include <span>
#include <variant>
#include <vector>

#include "wirestack/ipv4_address.hpp"

namespace wirestack {

struct TcpFlags {
    bool fin = false;
    bool syn = false;
    bool rst = false;
    bool psh = false;
    bool ack = false;
    bool urg = false;
    bool ece = false;
    bool cwr = false;

    friend bool operator==(const TcpFlags&, const TcpFlags&) = default;
};

struct TcpSegment {
    std::uint16_t source_port;
    std::uint16_t destination_port;
    std::uint32_t sequence_number;
    std::uint32_t acknowledgment_number;
    TcpFlags flags;
    std::uint16_t window_size;
    std::uint16_t urgent_pointer;
    std::vector<std::byte> options;
    std::vector<std::byte> payload;
};

enum class TcpParseError {
    TooShort,
    InvalidDataOffset,
    BadChecksum,
};

using TcpParseResult = std::variant<TcpSegment, TcpParseError>;

// `bytes` is the IPv4 payload (already trimmed to IPv4's declared total
// length). `source`/`destination` are that packet's IPv4 addresses,
// needed only for the pseudo-header checksum. Unlike UDP, TCP has no
// zero-means-omitted checksum exemption -- the checksum is always
// validated.
TcpParseResult parseTcpSegment(std::span<const std::byte> bytes, Ipv4Address source,
                                Ipv4Address destination);

// Maximum bytes a single TCP segment can represent: the pseudo-header
// length field is 16 bits.
inline constexpr std::size_t kMaxTcpSegmentLength = 65535;

// Data offset is a 4-bit field measured in 32-bit words, so a TCP header
// (20-byte base + options) cannot exceed 60 bytes, i.e. options cannot
// exceed 40 bytes.
inline constexpr std::size_t kMaxTcpOptionsLength = 40;

enum class TcpSerializeError {
    PayloadTooLarge,
    UnalignedOptions, // segment.options.size() is not a multiple of 4
    OptionsTooLong,    // segment.options.size() > kMaxTcpOptionsLength
};

using TcpSerializeResult = std::variant<std::vector<std::byte>, TcpSerializeError>;

// `segment.options` must already be padded to a multiple of 4 bytes by
// the caller; data offset is derived from its size.
TcpSerializeResult serializeTcpSegment(const TcpSegment& segment, Ipv4Address source,
                                        Ipv4Address destination);

} // namespace wirestack
