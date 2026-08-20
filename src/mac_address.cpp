#include "wirestack/mac_address.hpp"

#include <charconv>
#include <cstdio>

namespace wirestack {

namespace {

std::optional<std::uint8_t> parseHexByte(std::string_view group) {
    if (group.size() != 2) {
        return std::nullopt;
    }
    std::uint8_t value = 0;
    auto result = std::from_chars(group.data(), group.data() + group.size(), value, 16);
    if (result.ec != std::errc{} || result.ptr != group.data() + group.size()) {
        return std::nullopt;
    }
    return value;
}

} // namespace

std::optional<MacAddress> MacAddress::parse(std::string_view text) {
    std::array<std::uint8_t, kSize> bytes{};

    std::size_t group_start = 0;
    for (std::size_t i = 0; i < kSize; ++i) {
        std::size_t separator_pos = text.find(':', group_start);
        bool is_last_group = (i == kSize - 1);

        std::size_t group_end = is_last_group ? text.size() : separator_pos;
        if (group_end == std::string_view::npos) {
            return std::nullopt;
        }
        if (is_last_group && separator_pos != std::string_view::npos) {
            return std::nullopt; // trailing colon or extra group
        }

        auto byte = parseHexByte(text.substr(group_start, group_end - group_start));
        if (!byte) {
            return std::nullopt;
        }
        bytes[i] = *byte;

        group_start = group_end + 1;
    }

    return MacAddress(bytes);
}

std::string MacAddress::toString() const {
    char buf[18]; // "xx:xx:xx:xx:xx:xx\0"
    std::snprintf(buf, sizeof(buf), "%02x:%02x:%02x:%02x:%02x:%02x", bytes_[0], bytes_[1],
                  bytes_[2], bytes_[3], bytes_[4], bytes_[5]);
    return std::string(buf);
}

bool MacAddress::isBroadcast() const {
    return *this == kBroadcast;
}

const MacAddress MacAddress::kBroadcast{{0xff, 0xff, 0xff, 0xff, 0xff, 0xff}};

} // namespace wirestack
