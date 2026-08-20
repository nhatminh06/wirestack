#include "wirestack/ipv4_address.hpp"

#include <charconv>
#include <cstdio>

namespace wirestack {

namespace {

std::optional<std::uint8_t> parseOctet(std::string_view group) {
    if (group.empty() || group.size() > 3) {
        return std::nullopt;
    }
    if (group.size() > 1 && group[0] == '0') {
        return std::nullopt; // reject leading zeros, e.g. "01"
    }
    for (char c : group) {
        if (c < '0' || c > '9') {
            return std::nullopt;
        }
    }

    unsigned value = 0;
    auto result = std::from_chars(group.data(), group.data() + group.size(), value);
    if (result.ec != std::errc{} || result.ptr != group.data() + group.size() || value > 255) {
        return std::nullopt;
    }
    return static_cast<std::uint8_t>(value);
}

} // namespace

std::optional<Ipv4Address> Ipv4Address::parse(std::string_view text) {
    std::array<std::uint8_t, kSize> bytes{};

    std::size_t group_start = 0;
    for (std::size_t i = 0; i < kSize; ++i) {
        std::size_t dot_pos = text.find('.', group_start);
        bool is_last_group = (i == kSize - 1);

        std::size_t group_end = is_last_group ? text.size() : dot_pos;
        if (group_end == std::string_view::npos) {
            return std::nullopt;
        }
        if (is_last_group && dot_pos != std::string_view::npos) {
            return std::nullopt; // trailing dot or extra group
        }

        auto octet = parseOctet(text.substr(group_start, group_end - group_start));
        if (!octet) {
            return std::nullopt;
        }
        bytes[i] = *octet;

        group_start = group_end + 1;
    }

    return Ipv4Address(bytes);
}

std::string Ipv4Address::toString() const {
    char buf[16]; // "255.255.255.255\0"
    std::snprintf(buf, sizeof(buf), "%u.%u.%u.%u", bytes_[0], bytes_[1], bytes_[2], bytes_[3]);
    return std::string(buf);
}

} // namespace wirestack
