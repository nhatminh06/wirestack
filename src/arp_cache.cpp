#include "wirestack/arp_cache.hpp"

namespace wirestack {

void ArpCache::insert(Ipv4Address ip, MacAddress mac) {
    entries_[ip] = mac;
}

std::optional<MacAddress> ArpCache::lookup(Ipv4Address ip) const {
    auto it = entries_.find(ip);
    if (it == entries_.end()) {
        return std::nullopt;
    }
    return it->second;
}

} // namespace wirestack
