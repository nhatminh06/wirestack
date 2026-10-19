#include "wirestack/ipv4.hpp"

#include <cstddef>
#include <cstdint>
#include <span>

extern "C" int LLVMFuzzerTestOneInput(const std::uint8_t* data, std::size_t size) {
    auto bytes = std::span(reinterpret_cast<const std::byte*>(data), size);
    (void)wirestack::parseIpv4Packet(bytes);
    return 0;
}
