#include "wirestack/udp_endpoint.hpp"

namespace wirestack {

bool UdpEndpointTable::bind(std::uint16_t port, UdpHandler handler) {
    if (port == 0) {
        return false;
    }
    return handlers_.emplace(port, std::move(handler)).second;
}

std::optional<std::vector<std::byte>> UdpEndpointTable::deliver(
    std::uint16_t port, std::span<const std::byte> payload) const {
    auto it = handlers_.find(port);
    if (it == handlers_.end()) {
        return std::nullopt;
    }
    return it->second(payload);
}

} // namespace wirestack
