#pragma once

#include <array>
#include <cstdint>
#include <optional>
#include <span>
#include <string>
#include <string_view>

namespace wirestack {

class MacAddress {
public:
    static constexpr std::size_t kSize = 6;

    constexpr MacAddress() = default;
    explicit constexpr MacAddress(std::array<std::uint8_t, kSize> bytes) : bytes_(bytes) {}

    // Expects "xx:xx:xx:xx:xx:xx" with lowercase or uppercase hex digits.
    static std::optional<MacAddress> parse(std::string_view text);

    // Lowercase, zero-padded, colon-separated.
    std::string toString() const;

    std::span<const std::uint8_t, kSize> bytes() const { return bytes_; }

    bool isBroadcast() const;

    friend bool operator==(const MacAddress&, const MacAddress&) = default;

    static const MacAddress kBroadcast;

private:
    std::array<std::uint8_t, kSize> bytes_{};
};

} // namespace wirestack
