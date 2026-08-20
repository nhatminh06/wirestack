#pragma once

#include <cstddef>
#include <cstdint>
#include <span>

namespace wirestack {

// RFC 1071 one's-complement Internet checksum, used by both the IPv4
// header checksum and the ICMP message checksum. Convention: computing
// this over a header/message with the checksum field already filled in
// (as received on the wire) yields 0 for a valid checksum -- the sum of
// all words including a correct checksum field is all-ones, and this
// function returns the complement of the sum. To generate a checksum,
// compute over the same bytes with the checksum field set to zero.
std::uint16_t internetChecksum(std::span<const std::byte> data);

} // namespace wirestack
