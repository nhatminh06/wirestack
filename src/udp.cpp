#include "wirestack/udp.hpp"

#include "wirestack/checksum.hpp"

namespace wirestack {

namespace {

constexpr std::size_t kHeaderSize = 8;
constexpr std::size_t kMaxLength = 65535;
constexpr std::uint8_t kProtocolUdp = 17;

constexpr std::size_t kSourcePortOffset = 0;
constexpr std::size_t kDestinationPortOffset = 2;
constexpr std::size_t kLengthOffset = 4;
constexpr std::size_t kChecksumOffset = 6;

std::uint16_t readBigEndian16(std::span<const std::byte> data, std::size_t offset) {
    return static_cast<std::uint16_t>((static_cast<std::uint16_t>(data[offset]) << 8) |
                                       static_cast<std::uint16_t>(data[offset + 1]));
}

void writeBigEndian16(std::vector<std::byte>& out, std::uint16_t value) {
    out.push_back(static_cast<std::byte>((value >> 8) & 0xff));
    out.push_back(static_cast<std::byte>(value & 0xff));
}

void writeIpv4Address(std::vector<std::byte>& out, const Ipv4Address& ip) {
    for (std::uint8_t byte : ip.bytes()) {
        out.push_back(static_cast<std::byte>(byte));
    }
}

// Builds the IPv4 pseudo-header + UDP header + payload and runs it
// through the existing Internet checksum. The pseudo-header is never
// transmitted; it exists only to bind the checksum to the IPv4
// source/destination it was computed for.
std::uint16_t udpChecksum(Ipv4Address source, Ipv4Address destination,
                           std::span<const std::byte> udp_bytes) {
    std::vector<std::byte> buffer;
    buffer.reserve(12 + udp_bytes.size());

    writeIpv4Address(buffer, source);
    writeIpv4Address(buffer, destination);
    buffer.push_back(std::byte{0});
    buffer.push_back(static_cast<std::byte>(kProtocolUdp));
    writeBigEndian16(buffer, static_cast<std::uint16_t>(udp_bytes.size()));
    buffer.insert(buffer.end(), udp_bytes.begin(), udp_bytes.end());

    return internetChecksum(buffer);
}

} // namespace

UdpParseResult parseUdpDatagram(std::span<const std::byte> bytes, Ipv4Address source,
                                 Ipv4Address destination) {
    if (bytes.size() < kHeaderSize) {
        return UdpParseError::TooShort;
    }

    std::uint16_t length = readBigEndian16(bytes, kLengthOffset);
    if (length < kHeaderSize || length > bytes.size()) {
        return UdpParseError::InvalidLength;
    }

    auto logical_bytes = bytes.first(length);

    // A transmitted UDP checksum of zero means "not provided" in IPv4;
    // such datagrams are accepted without checksum validation.
    std::uint16_t checksum = readBigEndian16(bytes, kChecksumOffset);
    if (checksum != 0 && udpChecksum(source, destination, logical_bytes) != 0) {
        return UdpParseError::BadChecksum;
    }

    UdpDatagram datagram;
    datagram.source_port = readBigEndian16(bytes, kSourcePortOffset);
    datagram.destination_port = readBigEndian16(bytes, kDestinationPortOffset);
    auto payload_bytes = logical_bytes.subspan(kHeaderSize);
    datagram.payload.assign(payload_bytes.begin(), payload_bytes.end());

    return datagram;
}

UdpSerializeResult serializeUdpDatagram(const UdpDatagram& datagram, Ipv4Address source,
                                         Ipv4Address destination) {
    std::size_t total_length = kHeaderSize + datagram.payload.size();
    if (total_length > kMaxLength) {
        return UdpSerializeError::PayloadTooLarge;
    }

    std::vector<std::byte> out;
    out.reserve(total_length);

    writeBigEndian16(out, datagram.source_port);
    writeBigEndian16(out, datagram.destination_port);
    writeBigEndian16(out, static_cast<std::uint16_t>(total_length));
    writeBigEndian16(out, 0); // checksum placeholder, filled in below
    out.insert(out.end(), datagram.payload.begin(), datagram.payload.end());

    std::uint16_t checksum = udpChecksum(source, destination, out);
    if (checksum == 0) {
        // A computed checksum of zero is transmitted as 0xffff so it is
        // not confused with the IPv4 UDP no-checksum encoding.
        checksum = 0xffff;
    }
    out[kChecksumOffset] = static_cast<std::byte>((checksum >> 8) & 0xff);
    out[kChecksumOffset + 1] = static_cast<std::byte>(checksum & 0xff);

    return out;
}

} // namespace wirestack
