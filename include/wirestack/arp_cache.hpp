#pragma once

#include <chrono>
#include <cstddef>
#include <map>
#include <optional>
#include <vector>

#include "wirestack/ipv4_address.hpp"
#include "wirestack/mac_address.hpp"

namespace wirestack {

using ArpClock = std::chrono::steady_clock;

inline constexpr std::chrono::seconds kArpRetryInterval{1};
inline constexpr std::chrono::minutes kArpEntryLifetime{5};
inline constexpr std::size_t kArpCacheCapacity = 256;
inline constexpr int kArpMaxTransmissions = 3;

enum class ArpNeighborState {
    Resolved,
    Incomplete,
    Failed,
};

struct ArpPollResult {
    std::vector<Ipv4Address> requests;
    std::vector<Ipv4Address> failed;
};

class ArpCache {
public:
    explicit ArpCache(std::size_t capacity = kArpCacheCapacity,
                      ArpClock::duration entry_lifetime = kArpEntryLifetime);

    // Overwrites any existing mapping for `ip`.
    void insert(Ipv4Address ip, MacAddress mac, ArpClock::time_point now = ArpClock::now());

    std::optional<MacAddress> lookup(Ipv4Address ip,
                                     ArpClock::time_point now = ArpClock::now());

    // Returns true only when the caller should send the initial request.
    bool beginResolution(Ipv4Address ip, ArpClock::time_point now);
    ArpPollResult poll(ArpClock::time_point now);
    std::optional<ArpClock::time_point> nextDeadline() const;
    std::optional<ArpNeighborState> stateOf(Ipv4Address ip,
                                            ArpClock::time_point now = ArpClock::now());

    std::size_t size() const { return entries_.size(); }

private:
    struct Entry {
        ArpNeighborState state;
        std::optional<MacAddress> mac;
        ArpClock::time_point updated_at;
        std::optional<ArpClock::time_point> next_deadline;
        int transmit_count = 0;
    };

    bool makeRoom();
    void expire(ArpClock::time_point now);

    std::size_t capacity_;
    ArpClock::duration entry_lifetime_;
    std::map<Ipv4Address, Entry> entries_;
};

} // namespace wirestack
