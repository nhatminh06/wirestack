#include "wirestack/dns.hpp"

#include <algorithm>
#include <array>
#include <cctype>

namespace wirestack {

namespace {

bool isLdhChar(unsigned char c) {
    return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '-';
}

std::uint16_t readU16(std::span<const std::byte> bytes, std::size_t offset) {
    return static_cast<std::uint16_t>((static_cast<std::uint16_t>(bytes[offset]) << 8) |
                                       static_cast<std::uint16_t>(bytes[offset + 1]));
}

std::uint32_t readU32(std::span<const std::byte> bytes, std::size_t offset) {
    return (static_cast<std::uint32_t>(bytes[offset]) << 24) |
           (static_cast<std::uint32_t>(bytes[offset + 1]) << 16) |
           (static_cast<std::uint32_t>(bytes[offset + 2]) << 8) |
           static_cast<std::uint32_t>(bytes[offset + 3]);
}

void writeU16(std::vector<std::byte>& out, std::uint16_t value) {
    out.push_back(static_cast<std::byte>((value >> 8) & 0xff));
    out.push_back(static_cast<std::byte>(value & 0xff));
}

// One decoded domain name plus how many bytes it occupied in the record's
// OWN encoded field -- i.e. up to and including the terminating zero
// label, or up to and including a compression pointer's two bytes.
// Deliberately distinct from however far a pointer chain wandered inside
// the packet while decoding: that traversal cursor must never leak out
// and corrupt the caller's resource-record cursor (see docs/dns.md).
struct NameDecodeResult {
    std::string name;
    std::size_t bytes_in_record;
};

std::optional<NameDecodeResult> decodeName(std::span<const std::byte> packet,
                                             std::size_t start_offset) {
    std::string name;
    std::size_t cursor = start_offset;
    std::optional<std::size_t> record_end;
    int hops = 0;
    bool first_label = true;

    while (true) {
        if (cursor >= packet.size()) {
            return std::nullopt; // truncated name
        }
        auto len_byte = static_cast<std::uint8_t>(packet[cursor]);

        if ((len_byte & 0xC0) == 0xC0) {
            if (cursor + 1 >= packet.size()) {
                return std::nullopt; // incomplete pointer
            }
            auto pointer = static_cast<std::uint16_t>(
                (static_cast<std::uint16_t>(len_byte & 0x3F) << 8) |
                static_cast<std::uint8_t>(packet[cursor + 1]));
            if (!record_end) {
                record_end = cursor + 2;
            }
            // A pointer must reference strictly earlier in the packet than
            // itself. Combined with the hop bound below, this rejects a
            // self-pointer and makes any pointer loop impossible: each hop
            // strictly decreases the cursor, so a chain can visit at most
            // `cursor` distinct positions.
            if (pointer >= cursor) {
                return std::nullopt;
            }
            ++hops;
            if (hops > kMaxDnsPointerHops) {
                return std::nullopt;
            }
            cursor = pointer;
            continue;
        }

        if (len_byte == 0) {
            if (!record_end) {
                record_end = cursor + 1;
            }
            break;
        }

        if ((len_byte & 0xC0) != 0) {
            return std::nullopt; // reserved label-tag form (top bits 01 or 10)
        }

        std::size_t label_start = cursor + 1;
        if (label_start + len_byte > packet.size()) {
            return std::nullopt; // truncated label
        }
        if (!first_label) {
            name += '.';
        }
        first_label = false;
        for (std::size_t i = 0; i < len_byte; ++i) {
            auto c = static_cast<unsigned char>(packet[label_start + i]);
            name += static_cast<char>(std::tolower(c));
        }
        if (name.size() > kMaxDnsNameLength) {
            return std::nullopt;
        }
        cursor = label_start + len_byte;
    }

    return NameDecodeResult{std::move(name), *record_end - start_offset};
}

struct ResourceRecordHeader {
    std::string name;
    std::uint16_t type;
    std::uint16_t rr_class;
    std::uint32_t ttl;
    std::uint16_t rdlength;
    std::size_t rdata_offset;
    std::size_t next_offset; // offset of the byte following this record
};

std::optional<ResourceRecordHeader> decodeResourceRecord(std::span<const std::byte> packet,
                                                            std::size_t offset) {
    auto name = decodeName(packet, offset);
    if (!name) {
        return std::nullopt;
    }
    std::size_t cursor = offset + name->bytes_in_record;
    constexpr std::size_t kFixedFieldsSize = 10; // type(2) class(2) ttl(4) rdlength(2)
    if (cursor + kFixedFieldsSize > packet.size()) {
        return std::nullopt; // truncated RR fields
    }

    ResourceRecordHeader rr;
    rr.name = std::move(name->name);
    rr.type = readU16(packet, cursor);
    rr.rr_class = readU16(packet, cursor + 2);
    rr.ttl = readU32(packet, cursor + 4);
    rr.rdlength = readU16(packet, cursor + 8);
    rr.rdata_offset = cursor + kFixedFieldsSize;
    if (rr.rdata_offset + rr.rdlength > packet.size()) {
        return std::nullopt; // RDLENGTH beyond packet
    }
    rr.next_offset = rr.rdata_offset + rr.rdlength;
    return rr;
}

} // namespace

HostnameValidateResult normalizeHostname(std::string_view hostname) {
    if (hostname.empty() || hostname.size() > 253) {
        return {std::nullopt,
                hostname.empty() ? HostnameError::Empty : HostnameError::TooLong};
    }

    std::string normalized;
    normalized.reserve(hostname.size());

    std::size_t label_start = 0;
    while (label_start <= hostname.size()) {
        auto dot = hostname.find('.', label_start);
        std::string_view label = (dot == std::string_view::npos)
                                      ? hostname.substr(label_start)
                                      : hostname.substr(label_start, dot - label_start);
        if (label.empty()) {
            return {std::nullopt, HostnameError::EmptyLabel};
        }
        if (label.size() > kMaxDnsLabelLength) {
            return {std::nullopt, HostnameError::LabelTooLong};
        }
        if (label.front() == '-' || label.back() == '-') {
            return {std::nullopt, HostnameError::LeadingOrTrailingHyphen};
        }
        for (char c : label) {
            if (!isLdhChar(static_cast<unsigned char>(c))) {
                return {std::nullopt, HostnameError::InvalidChar};
            }
        }
        if (!normalized.empty()) {
            normalized += '.';
        }
        for (char c : label) {
            normalized += static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
        }

        if (dot == std::string_view::npos) {
            break;
        }
        label_start = dot + 1;
    }

    return {std::move(normalized), std::nullopt};
}

std::optional<std::vector<std::byte>> serializeDnsQuery(const DnsQuery& query) {
    auto normalized = normalizeHostname(query.hostname);
    if (!normalized.normalized || *normalized.normalized != query.hostname) {
        return std::nullopt; // caller must pass an already-normalized hostname
    }

    std::vector<std::byte> out;
    out.reserve(kDnsHeaderSize + query.hostname.size() + 8);

    writeU16(out, query.transaction_id);
    out.push_back(static_cast<std::byte>(0x01)); // QR=0 Opcode=0 AA=0 TC=0 RD=1
    out.push_back(static_cast<std::byte>(0x00)); // RA=0 Z=0 RCODE=0
    writeU16(out, 1);                            // QDCOUNT
    writeU16(out, 0);                            // ANCOUNT
    writeU16(out, 0);                            // NSCOUNT
    writeU16(out, 0);                            // ARCOUNT

    std::size_t label_start = 0;
    const std::string& hostname = query.hostname;
    while (label_start <= hostname.size()) {
        auto dot = hostname.find('.', label_start);
        std::string_view label = (dot == std::string::npos)
                                      ? std::string_view(hostname).substr(label_start)
                                      : std::string_view(hostname).substr(label_start,
                                                                           dot - label_start);
        out.push_back(static_cast<std::byte>(label.size()));
        for (char c : label) {
            out.push_back(static_cast<std::byte>(static_cast<unsigned char>(c)));
        }
        if (dot == std::string::npos) {
            break;
        }
        label_start = dot + 1;
    }
    out.push_back(static_cast<std::byte>(0x00)); // root label

    writeU16(out, 1); // QTYPE = A
    writeU16(out, 1); // QCLASS = IN

    if (out.size() > kMaxDnsMessageSize) {
        return std::nullopt;
    }
    return out;
}

DnsResponseParseResult parseDnsResponse(std::span<const std::byte> bytes,
                                          std::uint16_t expected_transaction_id,
                                          const std::string& expected_hostname) {
    auto malformed = DnsResponseParseResult{DnsResponseOutcome::Malformed, std::nullopt};

    if (bytes.size() < kDnsHeaderSize || bytes.size() > kMaxDnsMessageSize) {
        return malformed;
    }

    std::uint16_t id = readU16(bytes, 0);
    auto flags1 = static_cast<std::uint8_t>(bytes[2]);
    auto flags2 = static_cast<std::uint8_t>(bytes[3]);
    bool qr = (flags1 & 0x80) != 0;
    auto opcode = static_cast<std::uint8_t>((flags1 >> 3) & 0x0F);
    bool tc = (flags1 & 0x02) != 0;
    auto rcode = static_cast<std::uint8_t>(flags2 & 0x0F);
    std::uint16_t qdcount = readU16(bytes, 4);
    std::uint16_t ancount = readU16(bytes, 6);
    std::uint16_t nscount = readU16(bytes, 8);
    std::uint16_t arcount = readU16(bytes, 10);

    if (!qr) {
        return malformed; // a request presented as a response
    }
    if (opcode != 0) {
        return malformed;
    }
    if (qdcount != 1) {
        return malformed;
    }
    std::size_t total_records =
        static_cast<std::size_t>(ancount) + nscount + arcount;
    if (total_records > kMaxDnsRecordCount) {
        return malformed;
    }

    auto qname = decodeName(bytes, kDnsHeaderSize);
    if (!qname) {
        return malformed;
    }
    std::size_t cursor = kDnsHeaderSize + qname->bytes_in_record;
    if (cursor + 4 > bytes.size()) {
        return malformed;
    }
    std::uint16_t qtype = readU16(bytes, cursor);
    std::uint16_t qclass = readU16(bytes, cursor + 2);
    cursor += 4;

    if (id != expected_transaction_id) {
        return {DnsResponseOutcome::WrongTransaction, std::nullopt};
    }
    if (qname->name != expected_hostname || qtype != 1 || qclass != 1) {
        return {DnsResponseOutcome::WrongQuestion, std::nullopt};
    }
    if (tc) {
        return {DnsResponseOutcome::Truncated, std::nullopt};
    }
    if (rcode == 3) {
        return {DnsResponseOutcome::NxDomain, std::nullopt};
    }
    if (rcode == 5) {
        return {DnsResponseOutcome::Refused, std::nullopt};
    }
    if (rcode == 2) {
        return {DnsResponseOutcome::ServerFailure, std::nullopt};
    }
    if (rcode != 0) {
        return malformed; // unsupported RCODE value
    }

    std::optional<Ipv4Address> found;
    for (std::uint16_t i = 0; i < ancount; ++i) {
        auto rr = decodeResourceRecord(bytes, cursor);
        if (!rr) {
            return malformed;
        }
        cursor = rr->next_offset;
        if (!found && rr->type == 1 && rr->rr_class == 1 && rr->rdlength == 4 &&
            rr->name == expected_hostname) {
            std::array<std::uint8_t, 4> octets{};
            for (std::size_t i2 = 0; i2 < 4; ++i2) {
                octets[i2] = static_cast<std::uint8_t>(bytes[rr->rdata_offset + i2]);
            }
            found = Ipv4Address(octets);
        }
    }
    std::size_t remaining_records = static_cast<std::size_t>(nscount) + arcount;
    for (std::size_t i = 0; i < remaining_records; ++i) {
        auto rr = decodeResourceRecord(bytes, cursor);
        if (!rr) {
            return malformed;
        }
        cursor = rr->next_offset;
        // Authority/additional A records are never accepted, even an
        // otherwise-matching one -- Section 13 requires the answer section.
    }

    if (found) {
        return {DnsResponseOutcome::Resolved, found};
    }
    return {DnsResponseOutcome::NoAnswer, std::nullopt};
}

std::optional<std::vector<std::byte>> beginDnsQuery(DnsClientSession& session,
                                                      const DnsQuery& query,
                                                      DnsClock::time_point now) {
    auto bytes = serializeDnsQuery(query);
    if (!bytes) {
        return std::nullopt;
    }
    session.hostname = query.hostname;
    session.transaction_id = query.transaction_id;
    session.query_bytes = *bytes;
    session.transmit_count = 1;
    session.current_interval = kDnsInitialInterval;
    session.next_deadline = now + session.current_interval;
    session.state = DnsClientState::Pending;
    session.resolved_address.reset();
    session.failure_reason.reset();
    return session.query_bytes;
}

DnsPollResult pollDnsTimeout(DnsClientSession& session, DnsClock::time_point now) {
    DnsPollResult result;
    if (session.state != DnsClientState::Pending || !session.next_deadline) {
        return result;
    }
    if (now < *session.next_deadline) {
        return result;
    }

    if (session.transmit_count >= kDnsMaxTransmissions) {
        session.state = DnsClientState::Failed;
        session.failure_reason.reset(); // timeout has no DNS rcode
        session.next_deadline.reset();
        result.timed_out = true;
        return result;
    }

    session.transmit_count += 1;
    session.current_interval = std::min(session.current_interval * 2, kDnsMaxInterval);
    session.next_deadline = now + session.current_interval;
    result.retransmit = session.query_bytes;
    return result;
}

bool handleDnsResponse(DnsClientSession& session, Ipv4Address source_ip,
                        std::uint16_t source_port, std::uint16_t destination_port,
                        std::span<const std::byte> payload) {
    if (session.state != DnsClientState::Pending) {
        return false;
    }
    if (source_ip != session.server_ip || source_port != session.server_port ||
        destination_port != session.local_port) {
        return false;
    }

    auto parsed = parseDnsResponse(payload, session.transaction_id, session.hostname);
    switch (parsed.outcome) {
        case DnsResponseOutcome::WrongTransaction:
        case DnsResponseOutcome::WrongQuestion:
        case DnsResponseOutcome::Malformed:
        case DnsResponseOutcome::Truncated:
            // Ignore: wrong/unrelated/malformed datagrams never affect a
            // pending session; it keeps waiting until timeout (see
            // docs/dns.md).
            return false;
        case DnsResponseOutcome::Resolved:
            session.state = DnsClientState::Resolved;
            session.resolved_address = parsed.address;
            session.next_deadline.reset();
            return true;
        case DnsResponseOutcome::NoAnswer:
        case DnsResponseOutcome::NxDomain:
        case DnsResponseOutcome::ServerFailure:
        case DnsResponseOutcome::Refused:
            session.state = DnsClientState::Failed;
            session.failure_reason = parsed.outcome;
            session.next_deadline.reset();
            return true;
    }
    return false;
}

} // namespace wirestack
