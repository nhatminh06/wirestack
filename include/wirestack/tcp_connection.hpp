#pragma once

#include <chrono>
#include <compare>
#include <cstddef>
#include <cstdint>
#include <map>
#include <optional>
#include <vector>

#include "wirestack/ipv4_address.hpp"
#include "wirestack/tcp.hpp"

namespace wirestack {

enum class TcpState {
    SynReceived,
    Established,
    FinWait1,
    FinWait2,
    CloseWait,
    Closing,
    LastAck,
    TimeWait,
};

struct TcpConnectionKey {
    Ipv4Address local_ip;
    std::uint16_t local_port;
    Ipv4Address remote_ip;
    std::uint16_t remote_port;

    friend bool operator==(const TcpConnectionKey&, const TcpConnectionKey&) = default;
    friend auto operator<=>(const TcpConnectionKey&, const TcpConnectionKey&) = default;
};

// Read-only snapshot of a connection's sequence-space and retransmission
// state, exposed for inspection (tests, logging) without exposing
// mutable internals.
struct TcpConnectionSnapshot {
    TcpState state;
    std::uint32_t rcv_nxt;
    std::uint32_t snd_una;
    std::uint32_t snd_nxt;
    std::size_t pending_count;
};

struct TcpReceiveResult {
    // An immediate reply to transmit as-is: a SYN-ACK during the
    // handshake, a pure ACK for a duplicate/out-of-order/overlapping
    // segment or an invalid ACK number, a pure ACK for a peer FIN that
    // arrived with no payload, or a closed-port/unknown-connection RST.
    // Never set at the same time as a non-empty accepted_payload.
    std::optional<TcpSegment> reply;

    // Non-empty only when new in-order application data was accepted by
    // this call. The caller is responsible for turning this into an
    // outgoing segment via makeOutgoingData -- echo policy (or any other
    // application behavior) lives outside this class.
    std::vector<std::byte> accepted_payload;

    // True exactly on the call that accepts the peer's FIN (never set
    // again for a later duplicate/out-of-order FIN). The caller decides
    // when to initiate its own close (e.g. via beginClose) -- this class
    // has no echo-specific or application-specific close policy.
    bool peer_closed = false;

    // True exactly on the call whose acceptable inbound RST removed the
    // connection. No reply is ever sent for an RST.
    bool connection_reset = false;

    // True exactly on the call whose valid final ACK gracefully removed
    // the connection via the passive-close LastAck transition. Distinct
    // from connection_reset, which covers RST removal -- callers that
    // key their own state off this connection (e.g. an application
    // buffer) can use either flag to know the connection is gone.
    bool connection_closed = false;
};

// Monotonic clock used for retransmission scheduling. steady_clock (not
// system_clock) so timeouts are unaffected by wall-clock adjustments.
using TcpClock = std::chrono::steady_clock;

// Educational RTO policy: initial timeout, doubled after each
// timeout-triggered retransmission up to a cap, abandoned after a fixed
// number of retransmissions. This is not RFC 6298 (no RTT sampling, no
// smoothed RTT/variance).
inline constexpr std::chrono::milliseconds kInitialRto{1000};
inline constexpr std::chrono::milliseconds kMaxRto{8000};
inline constexpr int kMaxRetransmits = 5;

// Educational fixed TIME_WAIT duration -- not adaptive, not based on any
// measured MSL.
inline constexpr std::chrono::seconds kTimeWaitDuration{60};

struct TcpDueRetransmission {
    TcpConnectionKey key;
    TcpSegment segment;
};

struct TcpTimeoutPollResult {
    // Segments to transmit as-is (sequence state already updated).
    std::vector<TcpDueRetransmission> retransmissions;
    // Connections removed after exhausting their retransmission budget.
    std::vector<TcpConnectionKey> timed_out;
    // Connections removed after their TIME_WAIT deadline expired.
    std::vector<TcpConnectionKey> time_wait_expired;
};

// Builds a reset for a segment addressed to an unbound port, or a bound
// port with no matching connection where the segment is not a valid new
// SYN. Stateless -- needs nothing beyond the inbound segment itself.
// Never called for an incoming RST (never respond to RST with RST).
TcpSegment makeClosedPortReset(const TcpSegment& incoming);

// Handles the passive three-way handshake (LISTEN is implicit: any key
// with no table entry is either unbound or not yet SYN'd), single
// in-order-segment receive with duplicate/out-of-order/overlap
// rejection, cumulative ACK processing, timeout-based retransmission of
// sequence-consuming segments (SYN-ACK, application data, FIN -- never
// pure ACKs), passive/active/simultaneous close, deterministic
// TIME_WAIT, and acceptable inbound RST. No segmentation/reassembly, no
// active open, no congestion control.
class TcpConnectionTable {
public:
    explicit TcpConnectionTable(std::uint16_t listen_port);

    // Updates connection state for `segment` (keyed by `key`) at time
    // `now` and returns any reply to transmit plus any newly accepted
    // application payload. Segments addressed to a port other than the
    // configured listen port never create state and never produce a
    // result.
    TcpReceiveResult handle(const TcpConnectionKey& key, const TcpSegment& segment,
                             TcpClock::time_point now);

    std::optional<TcpState> stateOf(const TcpConnectionKey& key) const;
    std::optional<TcpConnectionSnapshot> snapshotOf(const TcpConnectionKey& key) const;

    // Builds one PSH|ACK segment carrying `payload` for an Established or
    // CloseWait connection (half-close: the peer's FIN doesn't stop
    // Wirestack from still sending), registers it for retransmission, and
    // advances snd_nxt by payload.size(). Returns nullopt, leaving
    // connection state unchanged, for an unknown connection, a connection
    // in any other state, an empty payload, or a payload that would make
    // the segment exceed kMaxTcpSegmentLength.
    std::optional<TcpSegment> makeOutgoingData(const TcpConnectionKey& key,
                                                std::vector<std::byte> payload,
                                                TcpClock::time_point now);

    // Initiates a local close: builds a FIN|ACK segment, registers it for
    // retransmission, and advances snd_nxt by one. Returns nullopt,
    // leaving connection state unchanged, unless the connection exists
    // and is Established (-> FinWait1) or CloseWait (-> LastAck). Calling
    // this again for the same connection returns nullopt (state is no
    // longer Established/CloseWait), so it cannot create a second FIN.
    std::optional<TcpSegment> beginClose(const TcpConnectionKey& key, TcpClock::time_point now);

    // Returns segments whose retransmission deadline has passed as of
    // `now`, and removes any connection that has exhausted its
    // retransmission budget. A retransmission never advances snd_nxt or
    // snd_una and never re-delivers application data.
    TcpTimeoutPollResult pollRetransmissions(TcpClock::time_point now);

    // Earliest pending-retransmission deadline across all connections,
    // or nullopt if nothing is pending. Intended to size a poll() timeout.
    std::optional<TcpClock::time_point> nextRetransmissionDeadline() const;

private:
    struct PendingTransmission {
        std::uint32_t sequence_start;
        bool is_syn = false; // true only for the handshake SYN-ACK entry
        bool is_fin = false; // true only for a locally-initiated FIN entry
        TcpFlags flags;
        std::vector<std::byte> payload; // owned; empty when is_syn or is_fin
        TcpClock::time_point last_sent;
        TcpClock::duration rto = kInitialRto;
        int retransmit_count = 0;

        std::uint32_t sequenceEnd() const {
            return sequence_start + static_cast<std::uint32_t>(payload.size()) +
                   (is_syn ? 1u : 0u) + (is_fin ? 1u : 0u);
        }
    };

    struct Connection {
        TcpState state;
        std::uint32_t remote_isn;
        std::uint32_t local_isn;
        std::uint32_t rcv_nxt = 0;
        std::uint32_t snd_una = 0;
        std::uint32_t snd_nxt = 0;
        std::vector<PendingTransmission> pending; // sequence order, oldest first
        std::optional<std::uint32_t> local_fin_seq; // set once by beginClose
        std::optional<TcpClock::time_point> time_wait_deadline;
        // Internal signal set by handleSynchronized (LastAck's final ACK,
        // or an accepted RST) and consumed by handle() right after, which
        // erases the connection. Never observed outside this class.
        bool pending_removal = false;
    };

    // Not a secure or RFC 6528-style initial sequence number generator --
    // a small incrementing counter, isolated here so it can be replaced
    // later without touching handshake logic.
    std::uint32_t nextIsn();

    static TcpSegment makeSynAck(const TcpConnectionKey& key, const Connection& connection);
    static TcpSegment makePureAck(const TcpConnectionKey& key, const Connection& connection);
    static TcpSegment makeFin(const TcpConnectionKey& key, const Connection& connection);

    // Advances snd_una to `ack` and drains/trims the pending queue to
    // match, if `ack` is ahead of the current snd_una. A no-op for a
    // duplicate or stale ACK. Precondition: `ack` already validated by
    // the caller as not beyond snd_nxt. SYN and FIN both occupy a
    // 1-wide sequence range, so no ack value can land strictly inside
    // one -- the partial-trim branch below only ever trims data.
    static void retireAcknowledged(Connection& connection, std::uint32_t ack);

    // Moves `connection` into TimeWait, arming its expiration deadline
    // and dropping any (already-acknowledged) pending entries.
    static void startTimeWait(Connection& connection, TcpClock::time_point now);

    // Shared by every synchronized state except TimeWait: Established,
    // FinWait1, FinWait2, CloseWait, Closing, LastAck.
    static TcpReceiveResult handleSynchronized(const TcpConnectionKey& key, Connection& connection,
                                                const TcpSegment& segment, TcpClock::time_point now);

    // TimeWait has no payload/application events and only reacts to a
    // duplicate FIN (restarts the deadline) or an acceptable RST.
    static TcpReceiveResult handleTimeWait(const TcpConnectionKey& key, Connection& connection,
                                            const TcpSegment& segment, TcpClock::time_point now);

    std::uint16_t listen_port_;
    std::uint32_t next_isn_ = 1000;
    std::map<TcpConnectionKey, Connection> connections_;
};

} // namespace wirestack
