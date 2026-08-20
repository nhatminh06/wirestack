#include "wirestack/udp_endpoint.hpp"

#include "test_util.hpp"

using wirestack::UdpEndpointTable;

int main() {
    UdpEndpointTable table;

    // bind port 0 is rejected
    CHECK(!table.bind(0, [](auto) { return std::vector<std::byte>{}; }));

    // first bind succeeds
    CHECK(table.bind(9000, [](std::span<const std::byte> request) {
        return std::vector<std::byte>(request.begin(), request.end());
    }));

    // duplicate bind on the same port fails
    CHECK(!table.bind(9000, [](auto) { return std::vector<std::byte>{}; }));

    // a different port succeeds
    CHECK(table.bind(9001, [](auto) {
        return std::vector<std::byte>{std::byte{0x2a}};
    }));

    // deliver to a bound port returns the handler's output
    std::vector<std::byte> request = {std::byte{'h'}, std::byte{'i'}};
    auto response = table.deliver(9000, request);
    CHECK(response.has_value());
    if (response) {
        CHECK(*response == request);
    }

    auto other_response = table.deliver(9001, {});
    CHECK(other_response.has_value());
    if (other_response) {
        CHECK(*other_response == std::vector<std::byte>{std::byte{0x2a}});
    }

    // deliver to an unbound port returns nullopt
    CHECK(!table.deliver(9002, request).has_value());

    return wirestack::test::failureCount() == 0 ? 0 : 1;
}
