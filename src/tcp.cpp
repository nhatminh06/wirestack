#include "wirestack/tcp.hpp"

#include "wirestack/checksum.hpp"

namespace wirestack {

namespace {

constexpr std::size_t kMinHeaderSize = 20;
constexpr std::uint8_t kProtocolTcp = 6;

constexpr std::size_t kSourcePortOffset = 0;
constexpr std::size_t kDestinationPortOffset = 2;
constexpr std::size_t kSequenceOffset = 4;
constexpr std::size_t kAckOffset = 8;
constexpr std::size_t kDataOffsetOffset = 12;
constexpr std::size_t kFlagsOffset = 13;
constexpr std::size_t kWindowOffset = 14;
constexpr std::size_t kChecksumOffset = 16;
constexpr std::size_t kUrgentPointerOffset = 18;

constexpr std::uint8_t kFlagFin = 0x01;
constexpr std::uint8_t kFlagSyn = 0x02;
constexpr std::uint8_t kFlagRst = 0x04;
constexpr std::uint8_t kFlagPsh = 0x08;
constexpr std::uint8_t kFlagAck = 0x10;
constexpr std::uint8_t kFlagUrg = 0x20;
constexpr std::uint8_t kFlagEce = 0x40;
constexpr std::uint8_t kFlagCwr = 0x80;

std::uint16_t readBigEndian16(std::span<const std::byte> data, std::size_t offset) {
    return static_cast<std::uint16_t>((static_cast<std::uint16_t>(data[offset]) << 8) |
                                       static_cast<std::uint16_t>(data[offset + 1]));
}

std::uint32_t readBigEndian32(std::span<const std::byte> data, std::size_t offset) {
    return (static_cast<std::uint32_t>(data[offset]) << 24) |
           (static_cast<std::uint32_t>(data[offset + 1]) << 16) |
           (static_cast<std::uint32_t>(data[offset + 2]) << 8) |
           static_cast<std::uint32_t>(data[offset + 3]);
}

void writeBigEndian16(std::vector<std::byte>& out, std::uint16_t value) {
    out.push_back(static_cast<std::byte>((value >> 8) & 0xff));
    out.push_back(static_cast<std::byte>(value & 0xff));
}

void writeBigEndian32(std::vector<std::byte>& out, std::uint32_t value) {
    out.push_back(static_cast<std::byte>((value >> 24) & 0xff));
    out.push_back(static_cast<std::byte>((value >> 16) & 0xff));
    out.push_back(static_cast<std::byte>((value >> 8) & 0xff));
    out.push_back(static_cast<std::byte>(value & 0xff));
}

void writeIpv4Address(std::vector<std::byte>& out, const Ipv4Address& ip) {
    for (std::uint8_t byte : ip.bytes()) {
        out.push_back(static_cast<std::byte>(byte));
    }
}

TcpFlags decodeFlags(std::uint8_t byte) {
    TcpFlags flags;
    flags.fin = (byte & kFlagFin) != 0;
    flags.syn = (byte & kFlagSyn) != 0;
    flags.rst = (byte & kFlagRst) != 0;
    flags.psh = (byte & kFlagPsh) != 0;
    flags.ack = (byte & kFlagAck) != 0;
    flags.urg = (byte & kFlagUrg) != 0;
    flags.ece = (byte & kFlagEce) != 0;
    flags.cwr = (byte & kFlagCwr) != 0;
    return flags;
}

std::uint8_t encodeFlags(const TcpFlags& flags) {
    std::uint8_t byte = 0;
    if (flags.fin) byte |= kFlagFin;
    if (flags.syn) byte |= kFlagSyn;
    if (flags.rst) byte |= kFlagRst;
    if (flags.psh) byte |= kFlagPsh;
    if (flags.ack) byte |= kFlagAck;
    if (flags.urg) byte |= kFlagUrg;
    if (flags.ece) byte |= kFlagEce;
    if (flags.cwr) byte |= kFlagCwr;
    return byte;
}

// Builds the IPv4 pseudo-header + TCP segment and runs it through the
// existing Internet checksum. The pseudo-header is never transmitted.
std::uint16_t tcpChecksum(Ipv4Address source, Ipv4Address destination,
                           std::span<const std::byte> tcp_bytes) {
    std::vector<std::byte> buffer;
    buffer.reserve(12 + tcp_bytes.size());

    writeIpv4Address(buffer, source);
    writeIpv4Address(buffer, destination);
    buffer.push_back(std::byte{0});
    buffer.push_back(static_cast<std::byte>(kProtocolTcp));
    writeBigEndian16(buffer, static_cast<std::uint16_t>(tcp_bytes.size()));
    buffer.insert(buffer.end(), tcp_bytes.begin(), tcp_bytes.end());

    return internetChecksum(buffer);
}

} // namespace

TcpParseResult parseTcpSegment(std::span<const std::byte> bytes, Ipv4Address source,
                                Ipv4Address destination) {
    if (bytes.size() < kMinHeaderSize) {
        return TcpParseError::TooShort;
    }

    std::uint8_t data_offset_field = static_cast<std::uint8_t>(bytes[kDataOffsetOffset]) >> 4;
    std::size_t header_length = static_cast<std::size_t>(data_offset_field) * 4;
    if (data_offset_field < 5 || header_length > bytes.size()) {
        return TcpParseError::InvalidDataOffset;
    }

    if (tcpChecksum(source, destination, bytes) != 0) {
        return TcpParseError::BadChecksum;
    }

    TcpSegment segment;
    segment.source_port = readBigEndian16(bytes, kSourcePortOffset);
    segment.destination_port = readBigEndian16(bytes, kDestinationPortOffset);
    segment.sequence_number = readBigEndian32(bytes, kSequenceOffset);
    segment.acknowledgment_number = readBigEndian32(bytes, kAckOffset);
    segment.flags = decodeFlags(static_cast<std::uint8_t>(bytes[kFlagsOffset]));
    segment.window_size = readBigEndian16(bytes, kWindowOffset);
    segment.urgent_pointer = readBigEndian16(bytes, kUrgentPointerOffset);

    auto options_bytes = bytes.subspan(kMinHeaderSize, header_length - kMinHeaderSize);
    segment.options.assign(options_bytes.begin(), options_bytes.end());

    auto payload_bytes = bytes.subspan(header_length);
    segment.payload.assign(payload_bytes.begin(), payload_bytes.end());

    return segment;
}

TcpSerializeResult serializeTcpSegment(const TcpSegment& segment, Ipv4Address source,
                                        Ipv4Address destination) {
    if (segment.options.size() % 4 != 0) {
        return TcpSerializeError::UnalignedOptions;
    }
    if (segment.options.size() > kMaxTcpOptionsLength) {
        return TcpSerializeError::OptionsTooLong;
    }

    std::size_t total_length = kMinHeaderSize + segment.options.size() + segment.payload.size();
    if (total_length > kMaxTcpSegmentLength) {
        return TcpSerializeError::PayloadTooLarge;
    }

    std::uint8_t data_offset =
        static_cast<std::uint8_t>((kMinHeaderSize + segment.options.size()) / 4);

    std::vector<std::byte> out;
    out.reserve(total_length);

    writeBigEndian16(out, segment.source_port);
    writeBigEndian16(out, segment.destination_port);
    writeBigEndian32(out, segment.sequence_number);
    writeBigEndian32(out, segment.acknowledgment_number);
    out.push_back(static_cast<std::byte>(data_offset << 4));
    out.push_back(static_cast<std::byte>(encodeFlags(segment.flags)));
    writeBigEndian16(out, segment.window_size);
    writeBigEndian16(out, 0); // checksum placeholder, filled in below
    writeBigEndian16(out, segment.urgent_pointer);
    out.insert(out.end(), segment.options.begin(), segment.options.end());
    out.insert(out.end(), segment.payload.begin(), segment.payload.end());

    std::uint16_t checksum = tcpChecksum(source, destination, out);
    out[kChecksumOffset] = static_cast<std::byte>((checksum >> 8) & 0xff);
    out[kChecksumOffset + 1] = static_cast<std::byte>(checksum & 0xff);

    return out;
}

namespace {

constexpr std::uint8_t kOptionKindEndOfList = 0;
constexpr std::uint8_t kOptionKindNoOperation = 1;
constexpr std::uint8_t kOptionKindMss = 2;
constexpr std::uint8_t kOptionKindWindowScale = 3;
constexpr std::uint8_t kOptionKindSackPermitted = 4;
constexpr std::uint8_t kOptionKindSack = 5;

} // namespace

TcpOptionParseResult parseTcpOptions(std::span<const std::byte> options) {
    TcpParsedOptions parsed;
    std::size_t i = 0;

    while (i < options.size()) {
        auto kind = static_cast<std::uint8_t>(options[i]);

        if (kind == kOptionKindEndOfList) {
            break; // remaining bytes are padding, ignored
        }
        if (kind == kOptionKindNoOperation) {
            i += 1;
            continue;
        }

        if (i + 1 >= options.size()) {
            return TcpOptionParseError::MissingLength;
        }
        auto length = static_cast<std::uint8_t>(options[i + 1]);
        if (length < 2) {
            return TcpOptionParseError::InvalidLength;
        }
        if (i + length > options.size()) {
            return TcpOptionParseError::TruncatedOption;
        }

        if (kind == kOptionKindMss) {
            if (length != 4) {
                return TcpOptionParseError::TruncatedOption;
            }
            if (parsed.maximum_segment_size.has_value()) {
                return TcpOptionParseError::DuplicateMss;
            }
            std::uint16_t value = readBigEndian16(options, i + 2);
            if (value == 0) {
                return TcpOptionParseError::InvalidMss;
            }
            parsed.maximum_segment_size = value;
        } else if (kind == kOptionKindWindowScale) {
            if (length != 3) {
                return TcpOptionParseError::TruncatedOption;
            }
            if (parsed.window_scale.has_value()) {
                return TcpOptionParseError::DuplicateWindowScale;
            }
            parsed.window_scale = static_cast<std::uint8_t>(options[i + 2]);
        } else if (kind == kOptionKindSackPermitted) {
            if (length != 2) {
                return TcpOptionParseError::InvalidSackPermittedLength;
            }
            if (parsed.sack_permitted) {
                return TcpOptionParseError::DuplicateSackPermitted;
            }
            parsed.sack_permitted = true;
        } else if (kind == kOptionKindSack) {
            if (length != 10 && length != 18 && length != 26 && length != 34) {
                return TcpOptionParseError::InvalidSackLength;
            }
            if (!parsed.sack_blocks.empty()) {
                return TcpOptionParseError::DuplicateSack;
            }
            std::size_t block_count = (static_cast<std::size_t>(length) - 2) / 8;
            for (std::size_t b = 0; b < block_count; ++b) {
                std::size_t block_offset = i + 2 + b * 8;
                std::uint32_t left = readBigEndian32(options, block_offset);
                std::uint32_t right = readBigEndian32(options, block_offset + 4);
                parsed.sack_blocks.push_back(TcpSackBlock{left, right});
            }
        }
        // Any other kind is an unknown well-formed option: safely
        // skipped below using its own declared length, never interpreted.

        i += length;
    }

    return parsed;
}

} // namespace wirestack
