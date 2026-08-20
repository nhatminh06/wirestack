#pragma once

#include <array>
#include <compare>
#include <cstdint>
#include <optional>
#include <span>
#include <string>
#include <string_view>

namespace wirestack {

class Ipv4Address {
public:
    static constexpr std::size_t kSize = 4;

    constexpr Ipv4Address() = default;
    explicit constexpr Ipv4Address(std::array<std::uint8_t, kSize> bytes) : bytes_(bytes) {}

    // Strict dotted-decimal: exactly 4 octets, each "0"-"255" with no
    // leading zeros, separated by '.', nothing else.
    static std::optional<Ipv4Address> parse(std::string_view text);

    std::string toString() const;

    std::span<const std::uint8_t, kSize> bytes() const { return bytes_; }

    friend bool operator==(const Ipv4Address&, const Ipv4Address&) = default;
    friend auto operator<=>(const Ipv4Address&, const Ipv4Address&) = default;

private:
    std::array<std::uint8_t, kSize> bytes_{};
};

} // namespace wirestack
