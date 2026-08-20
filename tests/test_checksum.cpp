#include "wirestack/checksum.hpp"

#include <vector>

#include "test_util.hpp"

using wirestack::internetChecksum;

namespace {

std::vector<std::byte> toBytes(std::initializer_list<std::uint8_t> values) {
    std::vector<std::byte> out;
    out.reserve(values.size());
    for (auto v : values) {
        out.push_back(static_cast<std::byte>(v));
    }
    return out;
}

} // namespace

int main() {
    // RFC 1071 section 3 worked example: words 0x0001, 0xf203, 0xf4f5,
    // 0xf6f7 sum (one's complement) to 0xddf2, checksum is its complement,
    // 0x220d.
    {
        auto bytes = toBytes({0x00, 0x01, 0xf2, 0x03, 0xf4, 0xf5, 0xf6, 0xf7});
        CHECK(internetChecksum(bytes) == 0x220d);
    }

    // Validation idiom used by ipv4.cpp/icmp.cpp: compute the checksum
    // with the checksum field zeroed, write it into that field, then
    // summing the whole thing again (checksum field included) must yield
    // 0.
    {
        auto zeroed = toBytes({0x00, 0x00, 0xf2, 0x03, 0xf4, 0xf5, 0xf6, 0xf7});
        auto checksum = internetChecksum(zeroed);
        auto with_checksum = toBytes({static_cast<std::uint8_t>(checksum >> 8),
                                       static_cast<std::uint8_t>(checksum & 0xff), 0xf2, 0x03,
                                       0xf4, 0xf5, 0xf6, 0xf7});
        CHECK(internetChecksum(with_checksum) == 0);
    }

    // Odd-length input: the trailing byte is the high half of the final word.
    {
        auto even = toBytes({0x00, 0x01, 0xf2, 0x03});
        auto odd = toBytes({0x00, 0x01, 0xf2, 0x03, 0xf4});
        auto padded = toBytes({0x00, 0x01, 0xf2, 0x03, 0xf4, 0x00});
        CHECK(internetChecksum(odd) == internetChecksum(padded));
        CHECK(internetChecksum(odd) != internetChecksum(even));
    }

    // Single-byte corruption changes the checksum.
    {
        auto original = toBytes({0x45, 0x00, 0x00, 0x28, 0x1c, 0x46, 0x40, 0x00});
        auto corrupted = toBytes({0x45, 0x00, 0x00, 0x28, 0x1c, 0x47, 0x40, 0x00});
        CHECK(internetChecksum(original) != internetChecksum(corrupted));
    }

    return wirestack::test::failureCount() == 0 ? 0 : 1;
}
