#pragma once

#include <cstddef>
#include <cstdint>
#include <span>
#include <variant>
#include <vector>

namespace wirestack {

enum class IcmpEchoType : std::uint8_t {
    EchoReply = 0,
    EchoRequest = 8,
};

struct IcmpEcho {
    IcmpEchoType type;
    std::uint16_t identifier;
    std::uint16_t sequence;
    std::vector<std::byte> payload;
};

enum class IcmpParseError {
    TooShort,
    UnsupportedType,
    InvalidCode,
    BadChecksum,
};

using IcmpParseResult = std::variant<IcmpEcho, IcmpParseError>;

// Only Echo Request/Reply (type 8/0, code 0). The checksum covers the
// entire message (header + identifier/sequence + payload) with no
// pseudo-header, unlike UDP/TCP.
IcmpParseResult parseIcmpEcho(std::span<const std::byte> data);

std::vector<std::byte> serializeIcmpEcho(const IcmpEcho& message);

// Builds the reply for an Echo Request: type 8 -> 0, code stays 0,
// identifier/sequence/payload preserved exactly. Does not check the
// request's type; the caller only calls this for EchoRequest input.
IcmpEcho makeEchoReply(const IcmpEcho& request);

} // namespace wirestack
