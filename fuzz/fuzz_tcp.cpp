#include "wirestack/tcp.hpp"

#include <array>
#include <cstddef>
#include <cstdint>
#include <span>

extern "C" int LLVMFuzzerTestOneInput(const std::uint8_t* data, std::size_t size) {
    auto bytes = std::span(reinterpret_cast<const std::byte*>(data), size);
    wirestack::Ipv4Address source(std::array<std::uint8_t, 4>{10, 0, 0, 1});
    wirestack::Ipv4Address destination(std::array<std::uint8_t, 4>{10, 0, 0, 2});
    (void)wirestack::parseTcpSegment(bytes, source, destination);
    (void)wirestack::parseTcpOptions(bytes);
    return 0;
}
