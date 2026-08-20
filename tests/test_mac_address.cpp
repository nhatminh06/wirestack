#include "wirestack/mac_address.hpp"

#include "test_util.hpp"

using wirestack::MacAddress;

int main() {
    // valid parse + round trip
    auto mac = MacAddress::parse("aa:bb:cc:dd:ee:ff");
    CHECK(mac.has_value());
    if (mac) {
        CHECK(mac->toString() == "aa:bb:cc:dd:ee:ff");
    }

    // uppercase accepted, normalized to lowercase on output
    auto upper = MacAddress::parse("AA:BB:CC:DD:EE:FF");
    CHECK(upper.has_value());
    if (upper) {
        CHECK(upper->toString() == "aa:bb:cc:dd:ee:ff");
        CHECK(mac.has_value() && *upper == *mac);
    }

    // rejects: wrong length (too few groups)
    CHECK(!MacAddress::parse("aa:bb:cc:dd:ee").has_value());

    // rejects: wrong length (too many groups)
    CHECK(!MacAddress::parse("aa:bb:cc:dd:ee:ff:00").has_value());

    // rejects: missing colons
    CHECK(!MacAddress::parse("aabbccddeeff").has_value());

    // rejects: non-hex characters
    CHECK(!MacAddress::parse("gg:bb:cc:dd:ee:ff").has_value());

    // rejects: trailing colon
    CHECK(!MacAddress::parse("aa:bb:cc:dd:ee:ff:").has_value());

    // rejects: single-digit group
    CHECK(!MacAddress::parse("a:bb:cc:dd:ee:ff").has_value());

    // rejects: empty string
    CHECK(!MacAddress::parse("").has_value());

    // broadcast
    CHECK(MacAddress::kBroadcast.toString() == "ff:ff:ff:ff:ff:ff");
    CHECK(MacAddress::kBroadcast.isBroadcast());
    CHECK(!mac.has_value() || !mac->isBroadcast());

    return wirestack::test::failureCount() == 0 ? 0 : 1;
}
