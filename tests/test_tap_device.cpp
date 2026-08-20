#include "wirestack/tap_device.hpp"

#include <cerrno>
#include <string>

#include "test_util.hpp"

using wirestack::tap_detail::fitsInterfaceName;
using wirestack::tap_detail::formatErrno;
using wirestack::tap_detail::kMaxInterfaceNameLength;

int main() {
    CHECK(fitsInterfaceName(""));
    CHECK(fitsInterfaceName(std::string(kMaxInterfaceNameLength, 'a')));
    CHECK(!fitsInterfaceName(std::string(kMaxInterfaceNameLength + 1, 'a')));
    CHECK(fitsInterfaceName("wire0"));

    auto message = formatErrno("failed to open /dev/net/tun", EACCES);
    CHECK(message == "failed to open /dev/net/tun: Permission denied");

    return wirestack::test::failureCount() == 0 ? 0 : 1;
}
