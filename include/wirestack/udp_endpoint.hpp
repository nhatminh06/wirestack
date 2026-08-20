#pragma once

#include <cstddef>
#include <cstdint>
#include <functional>
#include <map>
#include <optional>
#include <span>
#include <vector>

namespace wirestack {

using UdpHandler = std::function<std::vector<std::byte>(std::span<const std::byte> request)>;

class UdpEndpointTable {
public:
    // Rejects port 0. Returns false if the port is already bound.
    bool bind(std::uint16_t port, UdpHandler handler);

    // Returns the handler's response payload, or nullopt if nothing is
    // bound to `port`.
    std::optional<std::vector<std::byte>> deliver(std::uint16_t port,
                                                    std::span<const std::byte> payload) const;

private:
    std::map<std::uint16_t, UdpHandler> handlers_;
};

} // namespace wirestack
