#pragma once

#include <map>
#include <optional>

#include "wirestack/ipv4_address.hpp"
#include "wirestack/mac_address.hpp"

namespace wirestack {

class ArpCache {
public:
    // Overwrites any existing mapping for `ip`.
    void insert(Ipv4Address ip, MacAddress mac);

    std::optional<MacAddress> lookup(Ipv4Address ip) const;

private:
    std::map<Ipv4Address, MacAddress> entries_;
};

} // namespace wirestack
