#include "wirestack/tap_device.hpp"

#include <cerrno>
#include <cstring>
#include <utility>

#include <fcntl.h>
#include <linux/if_tun.h>
#include <net/if.h>
#include <sys/ioctl.h>
#include <unistd.h>

namespace wirestack {

static_assert(tap_detail::kMaxInterfaceNameLength == IFNAMSIZ - 1,
              "kMaxInterfaceNameLength must track IFNAMSIZ - 1");

namespace tap_detail {

bool fitsInterfaceName(std::string_view name) noexcept {
    return name.size() <= kMaxInterfaceNameLength;
}

std::string formatErrno(std::string_view context, int err) {
    return std::string(context) + ": " + std::strerror(err);
}

} // namespace tap_detail

std::variant<TapDevice, TapOpenError> TapDevice::open(std::string_view requested_name) {
    if (!tap_detail::fitsInterfaceName(requested_name)) {
        return TapOpenError{"interface name too long: " + std::string(requested_name)};
    }

    int fd = ::open("/dev/net/tun", O_RDWR);
    if (fd < 0) {
        return TapOpenError{tap_detail::formatErrno("failed to open /dev/net/tun", errno)};
    }

    ifreq ifr{};
    ifr.ifr_flags = IFF_TAP | IFF_NO_PI;
    requested_name.copy(ifr.ifr_name, tap_detail::kMaxInterfaceNameLength);

    if (::ioctl(fd, TUNSETIFF, &ifr) < 0) {
        auto err = tap_detail::formatErrno("TUNSETIFF failed", errno);
        ::close(fd);
        return TapOpenError{std::move(err)};
    }

    return TapDevice(fd, std::string(ifr.ifr_name));
}

TapDevice::TapDevice(TapDevice&& other) noexcept : fd_(other.fd_), name_(std::move(other.name_)) {
    other.fd_ = -1;
}

TapDevice& TapDevice::operator=(TapDevice&& other) noexcept {
    if (this != &other) {
        if (fd_ >= 0) {
            ::close(fd_);
        }
        fd_ = other.fd_;
        name_ = std::move(other.name_);
        other.fd_ = -1;
    }
    return *this;
}

TapDevice::~TapDevice() {
    if (fd_ >= 0) {
        ::close(fd_);
    }
}

std::variant<std::size_t, std::string> TapDevice::read(std::span<std::byte> buffer) {
    for (;;) {
        ssize_t n = ::read(fd_, buffer.data(), buffer.size());
        if (n >= 0) {
            return static_cast<std::size_t>(n);
        }
        if (errno == EINTR) {
            continue;
        }
        return tap_detail::formatErrno("TAP read failed", errno);
    }
}

std::variant<std::size_t, std::string> TapDevice::write(std::span<const std::byte> frame) {
    std::size_t total_written = 0;
    while (total_written < frame.size()) {
        ssize_t n = ::write(fd_, frame.data() + total_written, frame.size() - total_written);
        if (n < 0) {
            if (errno == EINTR) {
                continue;
            }
            return tap_detail::formatErrno("TAP write failed", errno);
        }
        total_written += static_cast<std::size_t>(n);
    }
    return total_written;
}

} // namespace wirestack
