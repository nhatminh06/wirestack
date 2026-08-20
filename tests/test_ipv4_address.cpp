#include "wirestack/ipv4_address.hpp"

#include "test_util.hpp"

using wirestack::Ipv4Address;

int main() {
    // valid parse + round trip
    auto addr = Ipv4Address::parse("10.0.0.2");
    CHECK(addr.has_value());
    if (addr) {
        CHECK(addr->toString() == "10.0.0.2");
    }

    auto zero = Ipv4Address::parse("0.0.0.0");
    CHECK(zero.has_value());
    if (zero) {
        CHECK(zero->toString() == "0.0.0.0");
    }

    auto max = Ipv4Address::parse("255.255.255.255");
    CHECK(max.has_value());
    if (max) {
        CHECK(max->toString() == "255.255.255.255");
    }

    // equality
    CHECK(addr.has_value() && zero.has_value() && *addr != *zero);
    CHECK(Ipv4Address::parse("10.0.0.2") == addr);

    // rejects: octet > 255
    CHECK(!Ipv4Address::parse("256.0.0.1").has_value());
    CHECK(!Ipv4Address::parse("10.0.0.999").has_value());

    // rejects: too few octets
    CHECK(!Ipv4Address::parse("10.0.0").has_value());

    // rejects: too many octets
    CHECK(!Ipv4Address::parse("10.0.0.2.1").has_value());

    // rejects: non-numeric input
    CHECK(!Ipv4Address::parse("a.b.c.d").has_value());

    // rejects: empty input
    CHECK(!Ipv4Address::parse("").has_value());

    // rejects: empty octet
    CHECK(!Ipv4Address::parse("10..0.2").has_value());

    // rejects: leading zero
    CHECK(!Ipv4Address::parse("010.0.0.2").has_value());
    CHECK(!Ipv4Address::parse("10.0.0.02").has_value());

    // trailing dot
    CHECK(!Ipv4Address::parse("10.0.0.2.").has_value());

    return wirestack::test::failureCount() == 0 ? 0 : 1;
}
