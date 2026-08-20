#include "wirestack/checksum.hpp"

namespace wirestack {

std::uint16_t internetChecksum(std::span<const std::byte> data) {
    std::uint32_t sum = 0;

    std::size_t i = 0;
    for (; i + 1 < data.size(); i += 2) {
        std::uint16_t word = static_cast<std::uint16_t>(
            (static_cast<std::uint16_t>(data[i]) << 8) | static_cast<std::uint16_t>(data[i + 1]));
        sum += word;
    }
    if (i < data.size()) {
        // Odd byte count: the final byte is the high half of the last
        // 16-bit word, with the missing low byte treated as zero.
        sum += static_cast<std::uint16_t>(static_cast<std::uint16_t>(data[i]) << 8);
    }

    while ((sum >> 16) != 0) {
        sum = (sum & 0xffff) + (sum >> 16);
    }

    return static_cast<std::uint16_t>(~sum & 0xffff);
}

} // namespace wirestack
