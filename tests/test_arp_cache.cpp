#include "wirestack/arp_cache.hpp"

#include "test_util.hpp"

using wirestack::ArpCache;
using wirestack::Ipv4Address;
using wirestack::MacAddress;

int main() {
    ArpCache cache;

    auto ip1 = *Ipv4Address::parse("10.0.0.1");
    auto ip2 = *Ipv4Address::parse("10.0.0.2");
    auto mac1 = *MacAddress::parse("aa:bb:cc:dd:ee:ff");
    auto mac2 = *MacAddress::parse("11:22:33:44:55:66");

    // lookup miss on empty cache
    CHECK(!cache.lookup(ip1).has_value());

    // insert + lookup hit
    cache.insert(ip1, mac1);
    auto found = cache.lookup(ip1);
    CHECK(found.has_value());
    if (found) {
        CHECK(*found == mac1);
    }

    // lookup miss for an absent key
    CHECK(!cache.lookup(ip2).has_value());

    // insert twice for the same IP replaces the mapping
    cache.insert(ip1, mac2);
    auto replaced = cache.lookup(ip1);
    CHECK(replaced.has_value());
    if (replaced) {
        CHECK(*replaced == mac2);
    }

    return wirestack::test::failureCount() == 0 ? 0 : 1;
}
