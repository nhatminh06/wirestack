#include "wirestack/arp_cache.hpp"

#include "test_util.hpp"

#include <chrono>
#include <vector>

using wirestack::ArpCache;
using wirestack::ArpClock;
using wirestack::ArpNeighborState;
using wirestack::Ipv4Address;
using wirestack::kArpEntryLifetime;
using wirestack::kArpMaxTransmissions;
using wirestack::kArpRetryInterval;
using wirestack::MacAddress;

int main() {
    constexpr ArpClock::time_point t0{};
    ArpCache cache;

    auto ip1 = *Ipv4Address::parse("10.0.0.1");
    auto ip2 = *Ipv4Address::parse("10.0.0.2");
    auto mac1 = *MacAddress::parse("aa:bb:cc:dd:ee:ff");
    auto mac2 = *MacAddress::parse("11:22:33:44:55:66");

    // lookup miss on empty cache
    CHECK(!cache.lookup(ip1, t0).has_value());

    // insert + lookup hit
    cache.insert(ip1, mac1, t0);
    auto found = cache.lookup(ip1, t0);
    CHECK(found.has_value());
    if (found) {
        CHECK(*found == mac1);
    }

    // lookup miss for an absent key
    CHECK(!cache.lookup(ip2, t0).has_value());

    // insert twice for the same IP replaces the mapping
    cache.insert(ip1, mac2, t0);
    auto replaced = cache.lookup(ip1, t0);
    CHECK(replaced.has_value());
    if (replaced) {
        CHECK(*replaced == mac2);
    }

    // Cold-cache resolution sends once, deduplicates waiters, retries twice, then fails.
    ArpCache resolving;
    CHECK(resolving.beginResolution(ip1, t0));
    CHECK(!resolving.beginResolution(ip1, t0));
    CHECK(resolving.stateOf(ip1, t0) == ArpNeighborState::Incomplete);
    CHECK(resolving.nextDeadline() == t0 + kArpRetryInterval);
    CHECK(resolving.poll(t0 + kArpRetryInterval - std::chrono::milliseconds{1}).requests.empty());
    for (int transmission = 2; transmission <= kArpMaxTransmissions; ++transmission) {
        auto due = resolving.poll(t0 + kArpRetryInterval * (transmission - 1));
        CHECK(due.requests == std::vector<Ipv4Address>{ip1});
        CHECK(due.failed.empty());
    }
    auto failed = resolving.poll(t0 + kArpRetryInterval * kArpMaxTransmissions);
    CHECK(failed.requests.empty());
    CHECK(failed.failed == std::vector<Ipv4Address>{ip1});
    CHECK(resolving.stateOf(ip1, t0 + kArpRetryInterval * kArpMaxTransmissions) ==
          ArpNeighborState::Failed);

    // A valid reply resolves all consumers waiting on the same IP.
    ArpCache shared;
    CHECK(shared.beginResolution(ip1, t0));
    CHECK(!shared.beginResolution(ip1, t0));
    shared.insert(ip1, mac1, t0 + std::chrono::milliseconds{10});
    CHECK(shared.stateOf(ip1, t0 + std::chrono::milliseconds{10}) ==
          ArpNeighborState::Resolved);
    CHECK(shared.lookup(ip1, t0 + std::chrono::milliseconds{10}) == mac1);
    CHECK(shared.lookup(ip1, t0 + std::chrono::milliseconds{10}) == mac1);

    // Resolved entries expire deterministically.
    CHECK(!shared.lookup(ip1, t0 + std::chrono::milliseconds{10} + kArpEntryLifetime)
               .has_value());

    // Capacity replaces the oldest resolved entry but never an active resolution.
    auto ip3 = *Ipv4Address::parse("10.0.0.3");
    ArpCache bounded(2);
    bounded.insert(ip1, mac1, t0);
    bounded.insert(ip2, mac2, t0 + std::chrono::seconds{1});
    bounded.insert(ip3, mac1, t0 + std::chrono::seconds{2});
    CHECK(!bounded.lookup(ip1, t0 + std::chrono::seconds{2}).has_value());
    CHECK(bounded.lookup(ip2, t0 + std::chrono::seconds{2}) == mac2);
    CHECK(bounded.lookup(ip3, t0 + std::chrono::seconds{2}) == mac1);

    ArpCache pending_only(1);
    CHECK(pending_only.beginResolution(ip1, t0));
    CHECK(!pending_only.beginResolution(ip2, t0));
    CHECK(pending_only.stateOf(ip1, t0) == ArpNeighborState::Incomplete);

    return wirestack::test::failureCount() == 0 ? 0 : 1;
}
