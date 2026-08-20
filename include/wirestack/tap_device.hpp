#pragma once

#include <cstddef>
#include <span>
#include <string>
#include <string_view>
#include <variant>

namespace wirestack {

// Exposed for unit testing; not part of the intended public TAP API surface.
namespace tap_detail {

// Linux's ifreq.ifr_name holds IFNAMSIZ (16) bytes including the
// terminator, so a name must fit in this many bytes. Kept as our own
// constant rather than including <net/if.h> here, to keep Linux headers
// confined to tap_device.cpp; the .cpp asserts it matches IFNAMSIZ - 1.
inline constexpr std::size_t kMaxInterfaceNameLength = 15;

bool fitsInterfaceName(std::string_view name) noexcept;

std::string formatErrno(std::string_view context, int err);

} // namespace tap_detail

struct TapOpenError {
    std::string message;
};

class TapDevice {
public:
    static std::variant<TapDevice, TapOpenError> open(std::string_view requested_name);

    TapDevice(const TapDevice&) = delete;
    TapDevice& operator=(const TapDevice&) = delete;
    TapDevice(TapDevice&& other) noexcept;
    TapDevice& operator=(TapDevice&& other) noexcept;
    ~TapDevice();

    std::string_view name() const noexcept { return name_; }

    // Blocking single read. IFF_NO_PI means one read() yields exactly one
    // Ethernet frame, so no internal loop is needed here.
    std::variant<std::size_t, std::string> read(std::span<std::byte> buffer);

    // Blocking write, looping over partial writes.
    std::variant<std::size_t, std::string> write(std::span<const std::byte> frame);

private:
    TapDevice(int fd, std::string name) : fd_(fd), name_(std::move(name)) {}

    int fd_ = -1;
    std::string name_;
};

} // namespace wirestack
