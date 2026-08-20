#include <cstdio>
#include <string>
#include <variant>

#include "wirestack/ethernet.hpp"
#include "wirestack/mac_address.hpp"
#include "wirestack/tap_device.hpp"

// Writes one fixed Ethernet frame out through a TAP device. Exists only to
// prove the serialize -> TapDevice::write -> kernel path works; it does not
// implement any protocol (no ARP reply logic, no dst/src derivation).

int main(int argc, char** argv) {
    if (argc != 2) {
        std::fprintf(stderr, "usage: %s <tap-interface-name>\n", argv[0]);
        return 1;
    }

    auto opened = wirestack::TapDevice::open(argv[1]);
    if (auto* error = std::get_if<wirestack::TapOpenError>(&opened)) {
        std::fprintf(stderr, "tap_send: failed to open TAP: %s\n", error->message.c_str());
        return 1;
    }
    auto& tap = std::get<wirestack::TapDevice>(opened);

    wirestack::EthernetFrame frame;
    frame.destination = *wirestack::MacAddress::parse("ff:ff:ff:ff:ff:ff");
    frame.source = *wirestack::MacAddress::parse("02:00:00:00:00:01");
    frame.ether_type = static_cast<std::uint16_t>(wirestack::EtherType::Ipv4);
    frame.payload = {std::byte{0xde}, std::byte{0xad}, std::byte{0xbe}, std::byte{0xef}};

    auto serialized = wirestack::serializeEthernetFrame(frame);
    auto result = tap.write(serialized);
    if (auto* error = std::get_if<std::string>(&result)) {
        std::fprintf(stderr, "tap_send: %s\n", error->c_str());
        return 1;
    }

    std::printf("tap_send: wrote %zu bytes via %s\n", std::get<std::size_t>(result),
                std::string(tap.name()).c_str());
    return 0;
}
