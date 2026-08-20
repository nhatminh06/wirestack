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
    std::uint16_t snd_wnd;
    std::size_t reassembly_fragment_count;
    std::size_t reassembly_buffered_bytes;
    std::uint16_t advertised_window;
};

struct TcpReceiveResult {
    // An immediate reply to transmit as-is: a SYN-ACK during the
    // handshake, a pure ACK for a segment that released no new
    // contiguous bytes (duplicate, still-gapped out-of-order, or an
    // invalid ACK number) or for a peer FIN that arrived with no
    // payload, or a closed-port/unknown-connection RST. Never set at the
    // same time as a non-empty accepted_payload.
    std::optional<TcpSegment> reply;

    // Non-empty only when this call made new bytes contiguous from
    // rcv_nxt -- either because the segment itself arrived in order, or
    // because it filled the last gap needed to release previously
    // buffered out-of-order bytes (possibly several fragments'
    // worth, concatenated in order). The caller is responsible for
    // turning this into an outgoing segment via makeOutgoingData -- echo
    // policy (or any other application behavior) lives outside this
    // class, which never delivers out-of-order bytes early.
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

// Wirestack never emits IPv4 or TCP options on anything it constructs
// (confirmed: outgoing segments never set `options`), so both headers
// are always exactly 20 bytes -- MSS is a fixed local constant, not
// computed from a negotiated remote value (none is negotiated this
// milestone; see docs/tcp.md).
inline constexpr std::size_t kIpv4HeaderLength = 20;
inline constexpr std::size_t kTcpHeaderLength = 20;
inline constexpr std::size_t kTcpMss = 1460; // 1500 - 20 - 20

// Bounds an atomic application send (see makeOutgoingData) -- matches the
// largest unscaled TCP window and keeps temporary segment construction
// bounded regardless of caller input.
inline constexpr std::size_t kMaxApplicationSendSize = 65535;

// Bounds the out-of-order receive buffer. The advertised window is
// derived from this and can never exceed it (the 16-bit header field
// couldn't represent more without window scaling, which isn't
// implemented).
inline constexpr std::size_t kTcpReceiveCapacity = 65535;

// Bounds the number of separately-tracked out-of-order fragments per
// connection, independent of their total byte size.
inline constexpr std::size_t kMaxReassemblyFragments = 128;

enum class TcpSendError {
    NotSendable,       // connection unknown or not Established/CloseWait
    EmptyPayload,
    TooLarge,           // exceeds kMaxApplicationSendSize
    WindowTooSmall,     // exceeds the currently available peer send window
    ConstructionFailed, // a chunk failed to serialize-size correctly
};

struct TcpSendResult {
    // Empty on rejection. In application-byte order, contiguous sequence
    // ranges, PSH set only on the last entry.
    std::vector<TcpSegment> segments;
    // 0 on rejection; otherwise equals the payload size passed in (sends
    // are atomic -- there is no partial acceptance).
    std::size_t bytes_accepted = 0;
    std::optional<TcpSendError> error;
};

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
// with no table entry is either unbound or not yet SYN'd), MSS-bounded
// outgoing segmentation within the peer's advertised send window,
// bounded out-of-order receive reassembly with duplicate/overlap
// trimming, cumulative ACK processing, timeout-based retransmission of
// sequence-consuming segments (SYN-ACK, application data, FIN -- never
// pure ACKs), passive/active/simultaneous close, deterministic
// TIME_WAIT, and acceptable inbound RST. No congestion control, no fast
// retransmit, no SACK, no window scaling, no active open.
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

    // Segments `payload` into as many MSS-bounded PSH|ACK segments as
    // needed (contiguous sequence ranges, PSH only on the last one),
    // registers each for retransmission, and advances snd_nxt once by
    // the total length. The send is atomic: on any rejection (unknown
    // connection, connection not Established/CloseWait, empty payload,
    // payload exceeding kMaxApplicationSendSize, or payload exceeding the
    // currently available peer send window) no bytes are accepted, no
    // segment is queued, and snd_nxt is unchanged. Callers must retry a
    // rejected send later, after the peer's advertised window changes --
    // there is no internal send queue or automatic retry.
    TcpSendResult makeOutgoingData(const TcpConnectionKey& key, std::vector<std::byte> payload,
                                    TcpClock::time_point now);

    // Initiates a local close: builds a FIN|ACK segment, registers it for
    // retransmission, and advances snd_nxt by one. Returns nullopt,
    // leaving connection state unchanged, unless the connection exists,
    // is Established (-> FinWait1) or CloseWait (-> LastAck), and at
    // least one byte of peer send window is currently available (a FIN
    // consumes one sequence number in the send window like any other
    // byte). Calling this again for the same connection returns nullopt
    // (state is no longer Established/CloseWait), so it cannot create a
    // second FIN.
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

    // One contiguous run of out-of-order receive bytes, owned. Fragments
    // are kept sorted by sequence_start and coalesced whenever they
    // become adjacent, so the buffer never holds two fragments that
    // touch or overlap.
    struct TcpReassemblyFragment {
        std::uint32_t sequence_start;
        std::vector<std::byte> payload;

        std::uint32_t sequenceEnd() const {
            return sequence_start + static_cast<std::uint32_t>(payload.size());
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

        // Peer-advertised send window and the sequence/ack numbers of the
        // segment that last legitimately updated it (RFC 793 SND.WL1/WL2),
        // so a stale segment can never replace a newer window advertisement.
        std::uint16_t snd_wnd = 0;
        std::uint32_t snd_wl1 = 0;
        std::uint32_t snd_wl2 = 0;

        // Bounded out-of-order receive buffer and a retained peer FIN
        // marker (its own sequence position) for a FIN that arrived
        // before all preceding bytes did.
        std::vector<TcpReassemblyFragment> out_of_order;
        std::optional<std::uint32_t> pending_fin_seq;
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

    // Total out-of-order bytes currently buffered, plus one if a peer FIN
    // is retained (task rule: an accepted out-of-order FIN counts as one
    // unit of sequence space for capacity purposes).
    static std::size_t bufferedReceiveBytes(const Connection& connection);

    // kTcpReceiveCapacity minus bufferedReceiveBytes, clamped into the
    // 16-bit header field. Used for every outgoing segment's window_size.
    static std::uint16_t advertisedWindowFor(const Connection& connection);

    // snd_wnd - flight_size (snd_nxt - snd_una), or 0 if the peer's
    // window is already fully consumed by outstanding (unacknowledged)
    // bytes.
    static std::uint32_t availableSendWindow(const Connection& connection);

    // Applies the RFC 793 SND.WL1/WL2 acceptance test so a stale segment
    // can never replace a newer window advertisement, then updates
    // snd_wnd/snd_wl1/snd_wl2 if the new segment is accepted.
    static void updateSendWindow(Connection& connection, const TcpSegment& segment);

    // Inserts `payload` (already trimmed to lie fully within the receive
    // window) at `sequence_start`, keeping only genuinely new bytes
    // (first-arrival-wins over anything already buffered), bounded by
    // kMaxReassemblyFragments, then sorts and coalesces touching
    // fragments.
    static void insertReassemblyFragment(Connection& connection, std::uint32_t sequence_start,
                                          std::vector<std::byte> payload);

    // Releases every fragment now contiguous with rcv_nxt (there may be
    // several, already coalesced into one by insertReassemblyFragment),
    // advancing rcv_nxt and returning the concatenated bytes. Does not
    // touch a retained peer FIN -- the caller consumes that separately
    // once rcv_nxt has caught up to it.
    static std::vector<std::byte> releaseContiguous(Connection& connection);

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
