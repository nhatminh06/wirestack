#pragma once

#include <chrono>
#include <cstddef>
#include <cstdint>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <vector>

#include "wirestack/ipv4_address.hpp"

namespace wirestack {

// Classic DNS message bound (see docs/dns.md): no EDNS, no DNS over TCP.
inline constexpr std::size_t kMaxDnsMessageSize = 512;
inline constexpr std::size_t kDnsHeaderSize = 12;
inline constexpr std::size_t kMaxDnsLabelLength = 63;
inline constexpr std::size_t kMaxDnsNameLength = 253;
// Bounds ANCOUNT+NSCOUNT+ARCOUNT together before any record is parsed.
inline constexpr std::size_t kMaxDnsRecordCount = 64;
// Bounds compression-pointer chain depth per name.
inline constexpr int kMaxDnsPointerHops = 16;

enum class HostnameError {
    Empty,
    TooLong,
    EmptyLabel,
    LabelTooLong,
    InvalidChar,
    LeadingOrTrailingHyphen,
};

struct HostnameValidateResult {
    // Set only on success: the hostname lowercased, otherwise unchanged.
    std::optional<std::string> normalized;
    std::optional<HostnameError> error;
};

// Validates a hostname per the ASCII/label rules in docs/dns.md and
// lowercases it on success. Does not resolve or touch the network.
HostnameValidateResult normalizeHostname(std::string_view hostname);

struct DnsQuery {
    std::uint16_t transaction_id = 0;
    std::string hostname; // must already be normalizeHostname'd
};

// Serializes a standard A/IN query (QR=0, Opcode=0, RD=1, QDCOUNT=1,
// ANCOUNT=NSCOUNT=ARCOUNT=0). Returns nullopt if `hostname` is invalid or
// the encoded message would exceed kMaxDnsMessageSize.
std::optional<std::vector<std::byte>> serializeDnsQuery(const DnsQuery& query);

enum class DnsResponseOutcome {
    Resolved,
    NoAnswer,      // no matching A answer, but otherwise a valid NOERROR response
    NxDomain,
    ServerFailure,
    Refused,
    Malformed,     // structurally invalid, or an outcome outside this milestone's scope
    Truncated,     // TC bit set
    WrongTransaction,
    WrongQuestion,
};

struct DnsResponseParseResult {
    DnsResponseOutcome outcome;
    // Set only when outcome == Resolved.
    std::optional<Ipv4Address> address;
};

// Parses and validates one UDP payload as a DNS response to the
// outstanding query identified by `expected_transaction_id` and
// `expected_hostname` (already normalized). Never reads out of bounds
// regardless of declared counts/lengths inside `bytes`. See docs/dns.md
// for the exact validation order and compression-pointer safety bounds.
DnsResponseParseResult parseDnsResponse(std::span<const std::byte> bytes,
                                          std::uint16_t expected_transaction_id,
                                          const std::string& expected_hostname);

// --- Bounded resolver client session (retry/timeout state) -----------------

using DnsClock = std::chrono::steady_clock;

// Fixed local UDP source port for the DNS client (see docs/dns.md --
// Wirestack has no general ephemeral-port allocator yet). Independent of
// the configured TCP source port.
inline constexpr std::uint16_t kDnsClientSourcePort = 53000;

inline constexpr std::chrono::milliseconds kDnsInitialInterval{1000};
inline constexpr std::chrono::milliseconds kDnsMaxInterval{4000};
// Total transmissions including the initial query (so 2 retries).
inline constexpr int kDnsMaxTransmissions = 3;

enum class DnsClientState {
    Pending,
    Resolved,
    Failed,
};

struct DnsClientSession {
    Ipv4Address server_ip;
    std::uint16_t server_port = 0;
    std::uint16_t local_port = kDnsClientSourcePort;
    std::string hostname; // normalized

    std::uint16_t transaction_id = 0;
    std::vector<std::byte> query_bytes; // exact bytes; retransmissions are byte-identical
    int transmit_count = 0;
    std::optional<DnsClock::time_point> next_deadline;
    std::chrono::milliseconds current_interval = kDnsInitialInterval;

    DnsClientState state = DnsClientState::Pending;
    std::optional<Ipv4Address> resolved_address;
    std::optional<DnsResponseOutcome> failure_reason;
};

// Builds session.query_bytes from `query`, records transmit 1 and arms
// next_deadline at now + kDnsInitialInterval. Returns the query bytes to
// send now, or nullopt if serialization failed (invalid hostname).
std::optional<std::vector<std::byte>> beginDnsQuery(DnsClientSession& session,
                                                      const DnsQuery& query,
                                                      DnsClock::time_point now);

struct DnsPollResult {
    // Set when a retry should be transmitted now (byte-identical to
    // session.query_bytes).
    std::optional<std::vector<std::byte>> retransmit;
    // True exactly on the call that exhausts kDnsMaxTransmissions --
    // session.state becomes Failed with failure_reason unset (timeout has
    // no DNS rcode).
    bool timed_out = false;
};

// A no-op unless session.state == Pending and session.next_deadline has
// passed. Never called again once session.state != Pending.
DnsPollResult pollDnsTimeout(DnsClientSession& session, DnsClock::time_point now);

// Validates the response's UDP-layer eligibility (source IP/port,
// destination port) before parsing. Returns true exactly on the call that
// moves session.state from Pending to Resolved or Failed (terminal);
// false for anything ignored (wrong source/port/transaction/question, or
// any call once session.state is no longer Pending).
bool handleDnsResponse(DnsClientSession& session, Ipv4Address source_ip,
                        std::uint16_t source_port, std::uint16_t destination_port,
                        std::span<const std::byte> payload);

} // namespace wirestack
