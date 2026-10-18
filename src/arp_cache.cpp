#include "wirestack/arp_cache.hpp"

namespace wirestack {

ArpCache::ArpCache(std::size_t capacity, ArpClock::duration entry_lifetime)
    : capacity_(capacity), entry_lifetime_(entry_lifetime) {}

bool ArpCache::makeRoom() {
    if (entries_.size() < capacity_) return true;

    auto oldest = entries_.end();
    for (auto it = entries_.begin(); it != entries_.end(); ++it) {
        if (it->second.state == ArpNeighborState::Incomplete) continue;
        if (oldest == entries_.end() || it->second.updated_at < oldest->second.updated_at) {
            oldest = it;
        }
    }
    if (oldest == entries_.end()) return false;
    entries_.erase(oldest);
    return true;
}

void ArpCache::expire(ArpClock::time_point now) {
    for (auto it = entries_.begin(); it != entries_.end();) {
        if (it->second.state != ArpNeighborState::Incomplete &&
            now - it->second.updated_at >= entry_lifetime_) {
            it = entries_.erase(it);
        } else {
            ++it;
        }
    }
}

void ArpCache::insert(Ipv4Address ip, MacAddress mac, ArpClock::time_point now) {
    expire(now);
    auto it = entries_.find(ip);
    if (it == entries_.end()) {
        if (!makeRoom()) return;
        entries_.emplace(ip,
                         Entry{ArpNeighborState::Resolved, mac, now, std::nullopt, 0});
        return;
    }
    it->second = Entry{ArpNeighborState::Resolved, mac, now, std::nullopt, 0};
}

std::optional<MacAddress> ArpCache::lookup(Ipv4Address ip, ArpClock::time_point now) {
    expire(now);
    auto it = entries_.find(ip);
    if (it == entries_.end() || it->second.state != ArpNeighborState::Resolved) return std::nullopt;
    return it->second.mac;
}

bool ArpCache::beginResolution(Ipv4Address ip, ArpClock::time_point now) {
    expire(now);
    if (entries_.contains(ip)) return false;
    if (!makeRoom()) return false;
    entries_.emplace(ip, Entry{ArpNeighborState::Incomplete, std::nullopt, now,
                               now + kArpRetryInterval, 1});
    return true;
}

ArpPollResult ArpCache::poll(ArpClock::time_point now) {
    expire(now);
    ArpPollResult result;
    for (auto& [ip, entry] : entries_) {
        if (entry.state != ArpNeighborState::Incomplete || !entry.next_deadline ||
            now < *entry.next_deadline) {
            continue;
        }
        if (entry.transmit_count >= kArpMaxTransmissions) {
            entry.state = ArpNeighborState::Failed;
            entry.updated_at = now;
            entry.next_deadline.reset();
            result.failed.push_back(ip);
        } else {
            ++entry.transmit_count;
            entry.next_deadline = now + kArpRetryInterval;
            result.requests.push_back(ip);
        }
    }
    return result;
}

std::optional<ArpClock::time_point> ArpCache::nextDeadline() const {
    std::optional<ArpClock::time_point> deadline;
    for (const auto& [ip, entry] : entries_) {
        (void)ip;
        std::optional<ArpClock::time_point> candidate = entry.next_deadline;
        if (entry.state != ArpNeighborState::Incomplete) {
            candidate = entry.updated_at + entry_lifetime_;
        }
        if (candidate && (!deadline || *candidate < *deadline)) deadline = candidate;
    }
    return deadline;
}

std::optional<ArpNeighborState> ArpCache::stateOf(Ipv4Address ip, ArpClock::time_point now) {
    expire(now);
    auto it = entries_.find(ip);
    if (it == entries_.end()) return std::nullopt;
    return it->second.state;
}

} // namespace wirestack
