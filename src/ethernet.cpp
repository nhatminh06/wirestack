#include "wirestack/ethernet.hpp"

namespace wirestack {

namespace {

constexpr std::size_t kHeaderSize = 2 * MacAddress::kSize + 2;

MacAddress readMacAddress(std::span<const std::byte> data, std::size_t offset) {
    std::array<std::uint8_t, MacAddress::kSize> bytes{};
    for (std::size_t i = 0; i < MacAddress::kSize; ++i) {
        bytes[i] = static_cast<std::uint8_t>(data[offset + i]);
    }
    return MacAddress(bytes);
}

void writeMacAddress(std::vector<std::byte>& out, const MacAddress& mac) {
    for (std::uint8_t byte : mac.bytes()) {
        out.push_back(static_cast<std::byte>(byte));
    }
}

std::uint16_t readBigEndian16(std::span<const std::byte> data, std::size_t offset) {
    return static_cast<std::uint16_t>((static_cast<std::uint16_t>(data[offset]) << 8) |
                                       static_cast<std::uint16_t>(data[offset + 1]));
}

void writeBigEndian16(std::vector<std::byte>& out, std::uint16_t value) {
    out.push_back(static_cast<std::byte>((value >> 8) & 0xff));
    out.push_back(static_cast<std::byte>(value & 0xff));
}

} // namespace

EthernetParseResult parseEthernetFrame(std::span<const std::byte> data) {
    if (data.size() < kHeaderSize) {
        return EthernetParseError::TooShort;
    }

    EthernetFrame frame;
    frame.destination = readMacAddress(data, 0);
    frame.source = readMacAddress(data, MacAddress::kSize);
    frame.ether_type = readBigEndian16(data, 2 * MacAddress::kSize);

    auto payload_bytes = data.subspan(kHeaderSize);
    frame.payload.assign(payload_bytes.begin(), payload_bytes.end());

    return frame;
}

std::vector<std::byte> serializeEthernetFrame(const EthernetFrame& frame) {
    std::vector<std::byte> out;
    out.reserve(kHeaderSize + frame.payload.size());

    writeMacAddress(out, frame.destination);
    writeMacAddress(out, frame.source);
    writeBigEndian16(out, frame.ether_type);
    out.insert(out.end(), frame.payload.begin(), frame.payload.end());

    return out;
}

} // namespace wirestack
