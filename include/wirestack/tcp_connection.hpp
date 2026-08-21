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
    SynSent,
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

// Monotonic clock used for retransmission scheduling and RTT
// measurement. steady_clock (not system_clock) so timing is unaffected
// by wall-clock adjustments.
using TcpClock = std::chrono::steady_clock;

// Read-only snapshot of a connection's sequence-space and retransmission
// state, exposed for inspection (tests, logging) without exposing
// mutable internals.
struct TcpConnectionSnapshot {
    TcpState state;
    std::uint32_t rcv_nxt;
    std::uint32_t snd_una;
    std::uint32_t snd_nxt;
    std::size_t pending_count;
    std::uint32_t snd_wnd; // logical (already decoded by peer_window_scale)
    std::size_t reassembly_fragment_count;
    std::size_t reassembly_buffered_bytes;
    std::uint16_t advertised_window; // wire value (already encoded for the peer)

    std::uint16_t peer_mss;
    std::uint16_t effective_send_mss;
    std::uint8_t peer_window_scale;
    std::uint8_t local_window_scale;
    bool window_scaling_enabled;

    bool has_rtt_sample;
    TcpClock::duration srtt;
    TcpClock::duration rttvar;
    TcpClock::duration current_rto;

    // Reno-style congestion control (see docs/tcp.md). Byte units except
    // recovery_point, which is a sequence number.
    std::uint32_t cwnd;
    std::uint32_t ssthresh;
    int duplicate_ack_count;
    bool in_fast_recovery;
    std::uint32_t recovery_point;
    std::uint32_t congestion_avoidance_acked_bytes;

    // SACK (see docs/tcp.md). sack_permitted is fixed for the connection
    // lifetime, decided only from the peer's initial SYN.
    // sacked_pending_count/recovery_retransmitted_count are narrow
    // read-only counts over the segment-granular scoreboard, exposed for
    // tests without exposing the mutable pending entries themselves.
    bool sack_permitted;
    std::size_t sacked_pending_count;
    std::size_t recovery_retransmitted_count;

    // Bounded application send buffer (see docs/tcp.md). unsent_bytes is
    // the FIFO backlog not yet in sequence space; owned_bytes additionally
    // includes application payload still retained in pending
    // transmissions (unacknowledged, whether or not yet retransmitted),
    // the quantity actually charged against kTcpSendBufferCapacity.
    std::size_t unsent_bytes;
    std::size_t owned_bytes;
    bool close_requested;

    // Zero-window persist (see docs/tcp.md). Narrow scope: armed only
    // when unsent data exists, the peer window is zero, and no sequence
    // space is outstanding.
    bool persist_armed;
    std::optional<TcpClock::time_point> persist_deadline;
};

struct TcpReceiveResult {
    // An immediate reply to transmit as-is: a SYN-ACK during the
    // handshake, a pure ACK for a segment that released no new
    // contiguous bytes (duplicate, still-gapped out-of-order, or an
    // invalid ACK number) or for a peer FIN that arrived with no
    // payload, or a closed-port/unknown-connection RST. Normally never
    // set at the same time as a non-empty accepted_payload or a non-empty
    // `scheduled` -- except when SACK was negotiated and out-of-order
    // receive state exists: that pure ACK carries SACK metadata absent
    // from any data segment in `scheduled`, so it is not redundant and
    // may be sent alongside it (see docs/tcp.md).
    std::optional<TcpSegment> reply;

    // Set exactly on the call whose ACK triggers one immediate loss-
    // recovery retransmission (see docs/tcp.md): the third qualifying
    // duplicate ACK, an additional SACK-guided duplicate ACK while already
    // in fast recovery, or a NewReno partial ACK -- at most one such
    // retransmission per incoming ACK, distinct from `reply` and from
    // ordinary timeout-triggered retransmission. The caller sends it
    // through the same immediate-reply path as `reply`, addressed using
    // the current received frame, not the timer/ARP path.
    std::optional<TcpSegment> fast_retransmit;

    // Application-data segments scheduled from the send buffer because
    // this ACK/window-update created new peer-window or congestion-window
    // allowance (see docs/tcp.md), in ascending sequence order -- may
    // include a deferred FIN as the final entry once the unsent queue
    // empties. Distinct from `fast_retransmit` (which resends already-
    // sent bytes) and from `reply` (which `handle()` clears in favor of
    // this vector whenever it is non-empty, since the last scheduled
    // segment already carries a valid ACK and makes a separate pure ACK
    // redundant).
    std::vector<TcpSegment> scheduled;

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

    // True exactly on the call whose valid SYN-ACK completed an active
    // open (SynSent -> Established). Distinct from the passive path,
    // which the caller detects instead by observing stateOf() transition
    // through SynReceived (see main.cpp) -- this flag exists only because
    // that trick doesn't work for SynSent (a rejected/invalid segment
    // here never changes state, so there is nothing to diff against).
    bool connection_established = false;
};

// Adaptive RTO policy (RFC 6298-style SRTT/RTTVAR estimator, expressed in
// integer TcpClock::duration arithmetic -- no floating point). A fresh
// connection starts at kInitialRto; once an eligible RTT sample arrives,
// the connection's own current_rto tracks the estimator instead. Every
// per-entry timeout still doubles that entry's own timeout, capped at
// kMaxRto, independent of the connection-level estimate.
inline constexpr std::chrono::milliseconds kInitialRto{1000};
inline constexpr std::chrono::milliseconds kMinRto{1000};
inline constexpr std::chrono::milliseconds kMaxRto{60000};
inline constexpr std::chrono::milliseconds kRtoGranularity{1};
inline constexpr int kMaxRetransmits = 5;

// Educational fixed TIME_WAIT duration -- not adaptive, not based on any
// measured MSL.
inline constexpr std::chrono::seconds kTimeWaitDuration{60};

// Reno-style congestion control (see docs/tcp.md). A deterministic
// project policy, not a claim about every production TCP's defaults:
// the initial threshold is a fixed 65535 bytes rather than derived from
// the peer's initial window, and the maximum window is a fixed bound
// well under half the 32-bit sequence space so cwnd arithmetic can never
// wrap.
inline constexpr std::uint32_t kInitialSsthresh = 65535;
inline constexpr std::uint32_t kMaxCongestionWindow = 1u << 30;
// RFC 5681-style initial window floor, expressed in bytes rather than a
// segment count so it composes with the min(10*SMSS, ...) formula below.
inline constexpr std::uint32_t kInitialCongestionWindowFloor = 14600;

// Bounded per-connection application send buffer (see docs/tcp.md).
// Covers both unsent queued bytes and application payload still retained
// in pending transmissions (unacknowledged application data) -- never
// SYN/FIN sequence space or pure ACKs.
inline constexpr std::size_t kTcpSendBufferCapacity = 256 * 1024;

// Deterministic zero-window persist timer, independent of the ordinary
// retransmission timer/backoff -- see docs/tcp.md for the narrow
// eligibility scope (armed only when unsent data exists, the peer window
// is zero, and no sequence space is outstanding).
inline constexpr std::chrono::milliseconds kInitialPersistInterval{1000};
inline constexpr std::chrono::milliseconds kMaxPersistInterval{60000};

// Wirestack never emits IPv4 options, and only ever emits TCP options on
// a SYN-ACK (MSS, and Window Scale when negotiated -- see
// buildSynAckOptions), so path-MTU math still treats both headers as a
// fixed 20 bytes: MSS is Wirestack's own local constant, independent of
// whatever the peer negotiates (see docs/tcp.md).
inline constexpr std::size_t kIpv4HeaderLength = 20;
inline constexpr std::size_t kTcpHeaderLength = 20;
inline constexpr std::size_t kTcpMss = 1460; // 1500 - 20 - 20, Wirestack's own path MSS

// IPv4 default peer MSS fallback: 536 bytes when the SYN omits MSS.
inline constexpr std::uint16_t kDefaultPeerMss = 536;

// Bounds an atomic application send (see makeOutgoingData) -- matches the
// largest unscaled TCP window and keeps temporary segment construction
// bounded regardless of caller input.
inline constexpr std::size_t kMaxApplicationSendSize = 65535;

// Bounds the number of segments one atomic application send may produce
// (relevant when the peer's negotiated MSS is small); exceeding it
// rejects the whole send atomically rather than fragmenting into an
// unbounded number of tiny segments.
inline constexpr std::size_t kMaxSegmentsPerSend = 128;

// Internal out-of-order receive buffer bound. Always this size
// regardless of whether Window Scale was negotiated with a given peer --
// only the *wire encoding* of the advertised window depends on
// negotiation (see advertisedWindowFor). 65535 << 2, the largest window
// representable with local_window_scale = 2.
inline constexpr std::size_t kTcpReceiveCapacity = 65535u << 2;

// Bounds the number of separately-tracked out-of-order fragments per
// connection, independent of their total byte size.
inline constexpr std::size_t kMaxReassemblyFragments = 128;

// The shift Wirestack offers when a peer's SYN includes a Window Scale
// option. 65535 << 2 == kTcpReceiveCapacity.
inline constexpr std::uint8_t kLocalWindowScaleShift = 2;

// A received Window Scale shift greater than this is clamped -- RFC 1323
// caps the field at 14 (2^14 * 65535 already exceeds the maximum usable
// TCP sequence-space window).
inline constexpr std::uint8_t kMaxWindowScaleShift = 14;

enum class TcpSendError {
    NotSendable,       // connection unknown, not Established/CloseWait, or close already requested
    EmptyPayload,
    TooLarge,           // exceeds kMaxApplicationSendSize (a single enqueue call's own bound)
    BufferFull,         // exceeds the currently available send-buffer capacity
    ConstructionFailed, // a chunk failed to serialize-size correctly
};

struct TcpSendResult {
    // Segments actually scheduled by this call (may be empty even on
    // acceptance, if no peer-window/congestion-window allowance exists
    // yet -- the bytes are still enqueued and will be scheduled by a
    // later ACK/window update). In application-byte order, contiguous
    // sequence ranges, PSH only on the segment that drains the complete
    // send buffer.
    std::vector<TcpSegment> segments;
    // 0 on rejection; otherwise equals the payload size passed in --
    // enqueue itself is atomic (all-or-nothing into the send buffer),
    // even though scheduling onto the wire may be gradual.
    std::size_t bytes_accepted = 0;
    std::optional<TcpSendError> error;
};

// Result of requesting an application-initiated close (see docs/tcp.md).
// Idempotent: a repeated call while already accepted/pending returns
// accepted=true again without creating a second FIN.
struct TcpCloseResult {
    // False only if the connection is unknown or not currently
    // Established/CloseWait (already closing, reset, or removed).
    bool accepted = false;
    // Set only when this call itself sequenced the FIN (the send buffer
    // was already empty and the peer window allowed it). nullopt means
    // the close intent was recorded but FIN remains deferred behind
    // unsent bytes or an exhausted peer window; a later ACK/window
    // update will sequence it automatically.
    std::optional<TcpSegment> fin;
};

enum class TcpConnectError {
    InvalidPort,          // local_port == 0 or remote_port == 0
    DuplicateConnection,  // the four-tuple already has connection state
};

struct TcpConnectResult {
    bool accepted = false;
    // The active SYN to transmit, set only when accepted -- not queued
    // for retransmission by the caller; beginConnect already registered
    // it with the same PendingTransmission/timer machinery used
    // everywhere else (see docs/tcp.md).
    std::optional<TcpSegment> syn;
    std::optional<TcpConnectError> error;
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

// One zero-window persist probe due for transmission (see docs/tcp.md).
struct TcpPersistProbe {
    TcpConnectionKey key;
    TcpSegment segment;
};

struct TcpPersistPollResult {
    std::vector<TcpPersistProbe> probes;
};

// Builds a reset for a segment addressed to an unbound port, or a bound
// port with no matching connection where the segment is not a valid new
// SYN. Stateless -- needs nothing beyond the inbound segment itself.
// Never called for an incoming RST (never respond to RST with RST).
TcpSegment makeClosedPortReset(const TcpSegment& incoming);

// Handles the passive three-way handshake (LISTEN is implicit: any key
// with no table entry is either unbound or not yet SYN'd) including MSS
// and Window Scale option negotiation, MSS-bounded outgoing segmentation
// within the peer's advertised (and, once negotiated, scaled) send
// window and a Reno-style congestion window, bounded out-of-order
// receive reassembly with duplicate/overlap trimming, cumulative ACK
// processing with Slow Start/Congestion Avoidance growth, RTT-adaptive
// timeout-based retransmission of sequence-consuming segments (SYN-ACK,
// application data, FIN -- never pure ACKs), duplicate-ACK fast
// retransmit, NewReno-style partial-ACK recovery, and a bounded
// segment-granular SACK scoreboard (see docs/tcp.md), passive/active/
// simultaneous close, deterministic TIME_WAIT, acceptable inbound RST,
// and active open (beginConnect, SynSent, MSS/Window Scale/SACK-Permitted
// negotiation from a peer SYN-ACK, RST-refused connect, connect timeout).
// No DSACK, no SACK reneging recovery beyond clearing marks on RTO, no
// RFC 6675 pipe algorithm, no CUBIC/BBR, no ECN, no TCP timestamps, no
// TCP simultaneous open, no ephemeral-port allocation.
class TcpConnectionTable {
public:
    explicit TcpConnectionTable(std::uint16_t listen_port);

    // Begins an active open: creates connection state in SynSent for the
    // exact four-tuple `key` and returns the SYN to transmit. Rejected
    // atomically (no ISN consumed, no state created, no segment returned)
    // when local_port or remote_port is 0, or when `key` already has
    // connection state (a prior active or passive connection, in any
    // state) -- the caller must pick a different source port or wait for
    // the existing state to clear. Does not resolve the peer MAC or send
    // anything itself; the caller is responsible for transmitting `syn`
    // (see docs/tcp.md for the runtime demonstration's neighbor-resolution
    // limitation).
    TcpConnectResult beginConnect(const TcpConnectionKey& key, TcpClock::time_point now);

    // Updates connection state for `segment` (keyed by `key`) at time
    // `now` and returns any reply to transmit plus any newly accepted
    // application payload. Segments addressed to a port other than the
    // configured listen port never create state and never produce a
    // result.
    TcpReceiveResult handle(const TcpConnectionKey& key, const TcpSegment& segment,
                             TcpClock::time_point now);

    std::optional<TcpState> stateOf(const TcpConnectionKey& key) const;
    std::optional<TcpConnectionSnapshot> snapshotOf(const TcpConnectionKey& key) const;

    // Enqueues `payload` atomically into the connection's bounded send
    // buffer (kTcpSendBufferCapacity, covering unsent bytes plus
    // application payload still retained in pending transmissions), then
    // immediately schedules as much of the (now-larger) buffer as the
    // current min(peer window, congestion window) allowance permits,
    // MSS-bounded, in send order, PSH only on the segment that drains the
    // complete buffer. Rejected atomically (no bytes enqueued, no segment
    // scheduled, connection state unchanged) when: the connection is
    // unknown, not Established/CloseWait, or has already had close
    // requested (NotSendable); payload is empty (EmptyPayload); payload
    // exceeds kMaxApplicationSendSize in one call (TooLarge); or payload
    // would exceed the buffer's remaining capacity (BufferFull).
    // `segments` may be empty even on acceptance if no allowance exists
    // yet -- the bytes remain queued and a later ACK/window update (see
    // TcpReceiveResult::scheduled) or another enqueue call is not needed
    // to eventually send them. A retransmission (timeout or fast) is not
    // new data and does not consume additional buffer or congestion-
    // window allowance.
    TcpSendResult makeOutgoingData(const TcpConnectionKey& key, std::vector<std::byte> payload,
                                    TcpClock::time_point now);

    // Requests an application-initiated close: idempotent, and rejects
    // (accepted=false) only if the connection is unknown or not currently
    // Established/CloseWait. Once accepted, no further makeOutgoingData
    // calls are accepted for this connection. The FIN itself is deferred
    // behind any still-unsent send-buffer bytes and the peer window (see
    // TcpCloseResult); it is sequenced by this call if possible, or later
    // by TcpReceiveResult::scheduled once conditions allow. Established
    // moves to FinWait1 when the FIN is sequenced; CloseWait moves to
    // LastAck.
    TcpCloseResult beginClose(const TcpConnectionKey& key, TcpClock::time_point now);

    // Returns segments whose retransmission deadline has passed as of
    // `now`, and removes any connection that has exhausted its
    // retransmission budget. A retransmission never advances snd_nxt or
    // snd_una and never re-delivers application data.
    TcpTimeoutPollResult pollRetransmissions(TcpClock::time_point now);

    // Earliest pending-retransmission deadline across all connections,
    // or nullopt if nothing is pending. Intended to size a poll() timeout.
    std::optional<TcpClock::time_point> nextRetransmissionDeadline() const;

    // Returns zero-window persist probes whose deadline has passed as of
    // `now`, advancing each connection's persist backoff. See
    // docs/tcp.md for the exact eligibility scope and probe semantics.
    TcpPersistPollResult pollPersistProbes(TcpClock::time_point now);

    // Earliest armed persist deadline across all connections, or nullopt
    // if none is armed. Intended to size a poll() timeout alongside
    // nextRetransmissionDeadline().
    std::optional<TcpClock::time_point> nextPersistDeadline() const;

private:
    struct PendingTransmission {
        std::uint32_t sequence_start;
        bool is_syn = false; // true for the passive SYN-ACK entry OR an active SYN entry
        // true only for an active-open SYN entry (a subset of is_syn),
        // distinguishing it from a passive SYN-ACK entry -- retransmission
        // must not assume every is_syn entry carries SYN|ACK with a
        // meaningful ack number (see pollRetransmissions).
        bool is_active_syn = false;
        bool is_fin = false; // true only for a locally-initiated FIN entry
        TcpFlags flags;
        std::vector<std::byte> payload; // owned; empty when is_syn or is_fin
        // Set once at construction, never overwritten by a retransmission
        // -- this is what an RTT sample is measured against.
        TcpClock::time_point first_sent_at;
        TcpClock::time_point last_sent_at;
        TcpClock::duration timeout_interval = kInitialRto; // this entry's own backed-off timeout
        // Timeout retry budget only -- incremented solely by
        // pollRetransmissions on an actual RTO expiry. A fast
        // retransmission never touches this (see was_retransmitted).
        int timeout_retransmit_count = 0;
        // Karn ambiguity: true once this entry has been retransmitted by
        // ANY path (timeout or duplicate-ACK fast retransmit), making an
        // eventual ACK of it ineligible for an RTT sample. Deliberately
        // separate from timeout_retransmit_count -- a fast retransmission
        // sets this without consuming the timeout retry budget.
        bool was_retransmitted = false;
        // Set once an ACK has taken an RTT sample from this entry (full or
        // partial retirement). Distinct from Karn eligibility: a
        // never-retransmitted entry may still be ineligible for a *second*
        // sample after a partial ACK already sampled it once.
        bool rtt_sample_taken = false;
        // Segment-granular SACK scoreboard (see docs/tcp.md). `sacked` is
        // set once this entry's whole unacknowledged range is covered by
        // the normalized union of valid SACK blocks -- never unset except
        // by RTO (see applyTimeoutCongestionCollapse) or by ordinary
        // cumulative-ACK retirement removing the entry. `retransmitted_in_
        // recovery` is reset at the start of each fast-recovery episode
        // and prevents selecting the same entry twice within it. Both are
        // meaningless (always false) when sack_permitted is false. SYN/FIN
        // entries are never marked either.
        bool sacked = false;
        bool retransmitted_in_recovery = false;

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

    // Narrow result of retiring a valid advancing ACK, used by congestion
    // control to size Slow Start/Congestion Avoidance growth without
    // recomputing per-entry accounting a second time.
    struct TcpAckRetirementResult {
        std::uint32_t newly_acked_sequence_space = 0; // total bytes ack advanced snd_una by
        std::uint32_t newly_acked_data_bytes = 0;      // subset that was application payload
        bool ack_advanced = false;                     // false for a duplicate/stale ACK
        bool rtt_sample_taken = false;
    };

    struct Connection {
        TcpState state;
        // Meaningful only once remote_isn_known is true -- an active-open
        // connection starts in SynSent with no valid peer sequence state
        // yet (see docs/tcp.md); a passively-created connection always
        // has this true from construction (its remote_isn comes from the
        // peer's initial SYN, known immediately).
        std::uint32_t remote_isn = 0;
        bool remote_isn_known = true;
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

        // Peer-advertised send window (logical, already decoded by
        // peer_window_scale) and the sequence/ack numbers of the segment
        // that last legitimately updated it (RFC 793 SND.WL1/WL2), so a
        // stale segment can never replace a newer window advertisement.
        std::uint32_t snd_wnd = 0;
        std::uint32_t snd_wl1 = 0;
        std::uint32_t snd_wl2 = 0;

        // Bounded out-of-order receive buffer and a retained peer FIN
        // marker (its own sequence position) for a FIN that arrived
        // before all preceding bytes did.
        std::vector<TcpReassemblyFragment> out_of_order;
        std::optional<std::uint32_t> pending_fin_seq;

        // SYN option negotiation, decided once from the peer's SYN and
        // never touched again (a duplicate SYN or any later segment's
        // options never renegotiates).
        std::uint16_t peer_mss = kDefaultPeerMss;
        std::uint16_t effective_send_mss = kTcpMss;
        std::uint8_t peer_window_scale = 0;  // clamped to [0, kMaxWindowScaleShift]
        std::uint8_t local_window_scale = 0; // 0 unless negotiated; kLocalWindowScaleShift if so
        bool window_scaling_enabled = false;
        // Decided once from the peer's initial SYN (see docs/tcp.md);
        // never renegotiated by a duplicate SYN or any later segment.
        bool sack_permitted = false;

        // RFC 6298-style adaptive RTO estimator.
        bool has_rtt_sample = false;
        TcpClock::duration srtt{};
        TcpClock::duration rttvar{};
        TcpClock::duration current_rto = kInitialRto; // starting timeout_interval for new sends

        // Reno-style congestion control (see docs/tcp.md). cwnd starts at
        // 0 and is set once, right after effective_send_mss is fixed
        // above; ssthresh needs no MSS knowledge so it defaults here.
        std::uint32_t cwnd = 0;
        std::uint32_t ssthresh = kInitialSsthresh;
        int duplicate_ack_count = 0;
        bool in_fast_recovery = false;
        std::uint32_t recovery_point = 0; // snd_nxt when fast recovery began; diagnostic only
        std::uint32_t congestion_avoidance_acked_bytes = 0;

        // Bounded application send buffer (see docs/tcp.md). FIFO byte
        // queue not yet in sequence space; application payload already
        // in sequence space lives in `pending` entries instead (owned
        // once, never duplicated). Capacity (kTcpSendBufferCapacity)
        // charges unsent.size() plus every non-SYN/FIN pending entry's
        // payload size.
        std::vector<std::byte> unsent;
        // Set once by beginClose; idempotent, and blocks further
        // makeOutgoingData calls. The FIN itself is sequenced only once
        // `unsent` is empty and the peer window allows it (see
        // maybeSequenceFin), tracked separately by local_fin_seq above.
        bool close_requested = false;

        // Zero-window persist (see docs/tcp.md). nullopt when not armed.
        std::optional<TcpClock::time_point> persist_deadline;
        TcpClock::duration persist_interval = kInitialPersistInterval;
    };

    // Not a secure or RFC 6528-style initial sequence number generator --
    // a small incrementing counter, isolated here so it can be replaced
    // later without touching handshake logic.
    std::uint32_t nextIsn();

    static TcpSegment makeSynAck(const TcpConnectionKey& key, const Connection& connection);
    // The active-open SYN: SYN only (no ACK), sequence=local_isn,
    // acknowledgment=0, unscaled window (see docs/tcp.md).
    static TcpSegment makeActiveSyn(const TcpConnectionKey& key, const Connection& connection);
    // `most_recent_fragment_start`, when set, identifies the out-of-order
    // fragment (by its current sequence_start) that should occupy the
    // first SACK block position (see generateSackBlocks); nullopt falls
    // back to highest-to-lowest ordering only. Ignored when
    // !connection.sack_permitted or no out-of-order fragments remain.
    static TcpSegment makePureAck(const TcpConnectionKey& key, const Connection& connection,
                                   std::optional<std::uint32_t> most_recent_fragment_start = std::nullopt);
    static TcpSegment makeFin(const TcpConnectionKey& key, const Connection& connection);

    // MSS (always kTcpMss, never derived from the peer), SACK-Permitted
    // (only when sack_permitted), and Window Scale (only when
    // window_scaling_enabled), in that fixed order, followed by EOL/
    // padding to a 4-byte boundary -- see docs/tcp.md for the exact byte
    // layouts.
    static std::vector<std::byte> buildSynAckOptions(const Connection& connection);

    // Active SYN's own option advertisement: MSS (kTcpMss), SACK-Permitted
    // (always offered), Window Scale (always offered, kLocalWindowScaleShift)
    // -- same local capability policy as buildSynAckOptions, but offered
    // unconditionally since no peer options have been seen yet.
    static std::vector<std::byte> buildActiveSynOptions();

    // Builds a kind-5 SACK option (2 + 8*N bytes, N == blocks.size(),
    // EOL/zero-padded to a 4-byte boundary) or an empty vector if `blocks`
    // is empty.
    static std::vector<std::byte> buildSackOptions(const std::vector<TcpSackBlock>& blocks);

    // Deterministic receiver SACK block policy (see docs/tcp.md): at most
    // 4 blocks, one per retained out-of-order fragment, edges exact
    // (fragment.sequence_start, fragment.sequenceEnd()). The fragment
    // identified by `most_recent_fragment_start` (if it still exists in
    // connection.out_of_order) occupies the first position; remaining
    // fragments fill in descending sequence_start order. Empty if
    // connection.out_of_order is empty.
    static std::vector<TcpSackBlock> generateSackBlocks(
        const Connection& connection, std::optional<std::uint32_t> most_recent_fragment_start);

    // Validates each block in `blocks` against `cumulative_ack` and
    // connection.snd_nxt (see docs/tcp.md: left_edge must be strictly
    // after cumulative_ack, right_edge strictly after left_edge, and at
    // or before snd_nxt), normalizes the valid subset (sorted, overlapping
    // and touching blocks merged), then marks every pending data entry
    // (never SYN/FIN) whose full unacknowledged range is covered by that
    // union as sacked. Never advances snd_una, never removes an entry,
    // never touches cwnd/ssthresh, never takes an RTT sample. A no-op if
    // `blocks` contains nothing valid.
    static void applySackBlocks(Connection& connection, std::uint32_t cumulative_ack,
                                 const std::vector<TcpSackBlock>& blocks);

    // The oldest pending data entry (never SYN/FIN) that starts before
    // recovery_point, is not marked sacked, and has not already been
    // retransmitted in the current recovery episode -- or nullptr if none
    // qualifies. Shared by duplicate-ACK-3 entry, SACK-guided additional
    // duplicate ACKs, and NewReno partial-ACK retransmission.
    static PendingTransmission* selectRecoveryRetransmission(Connection& connection);

    // Builds an immediate retransmission of `entry` (preserving sequence
    // and payload, refreshing ack/window), marks it was_retransmitted and
    // retransmitted_in_recovery, and restarts last_sent_at from `now`
    // without touching timeout_retransmit_count, timeout_interval, or
    // connection.current_rto.
    static TcpSegment buildRecoveryRetransmission(const TcpConnectionKey& key,
                                                    Connection& connection,
                                                    PendingTransmission& entry,
                                                    TcpClock::time_point now);

    // Advances snd_una to `ack` and drains/trims the pending queue to
    // match, if `ack` is ahead of the current snd_una. A no-op (all-zero,
    // ack_advanced=false result) for a duplicate or stale ACK.
    // Precondition: `ack` already validated by the caller as not beyond
    // snd_nxt. SYN and FIN both occupy a 1-wide sequence range, so no ack
    // value can land strictly inside one -- the partial-trim branch below
    // only ever trims data, so newly_acked_data_bytes never counts a
    // SYN/FIN's own control byte. Also takes an RTT sample (see
    // recordRttSample) from the newest fully-or-partially-retired entry
    // that was never retransmitted and has not already contributed a
    // sample, if any -- Karn's rule falls out for free, since a
    // retransmitted entry (was_retransmitted) is simply never an eligible
    // candidate, and rtt_sample_taken prevents a still-partially-
    // outstanding entry from being sampled a second time by a later ACK.
    static TcpAckRetirementResult retireAcknowledged(Connection& connection, std::uint32_t ack,
                                                       TcpClock::time_point now);

    // Applies the first-sample or subsequent-sample RFC 6298-style
    // update (SRTT/RTTVAR/RTO) for one measured round-trip time `r`, then
    // clamps current_rto to [kMinRto, kMaxRto].
    static void recordRttSample(Connection& connection, TcpClock::duration r);

    // Clamps a congestion-window-sized byte count to kMaxCongestionWindow,
    // computed in a wider type so the addition producing `value` cannot
    // itself overflow uint32_t before the clamp is applied.
    static std::uint32_t clampCwnd(std::uint64_t value);

    // min(10*SMSS, max(2*SMSS, kInitialCongestionWindowFloor)) -- see
    // docs/tcp.md. Computed only once, right after effective_send_mss is
    // fixed for a connection.
    static std::uint32_t initialCongestionWindow(std::uint16_t smss);

    // cwnd - flight_size (snd_nxt - snd_una), or 0 if the congestion
    // window is already fully consumed by outstanding (unacknowledged)
    // bytes. The new-data send limit is min(availableSendWindow,
    // availableCongestionWindow) -- see makeOutgoingData.
    static std::uint32_t availableCongestionWindow(const Connection& connection);

    // Applies Slow Start (cwnd < ssthresh: increase by min(data_bytes,
    // SMSS)) or Congestion Avoidance (cwnd >= ssthresh: accumulate
    // data_bytes and add one SMSS each time the accumulator reaches the
    // current cwnd, repeating for a cumulative ACK that crosses more than
    // one window) for one advancing ACK's newly acknowledged application
    // data. A no-op for data_bytes == 0 (SYN/FIN/pure-ACK acknowledgment).
    static void applyCongestionGrowth(Connection& connection, std::uint32_t data_bytes);

    // Applies the timeout congestion-collapse response (halve flight
    // into ssthresh with a 2*SMSS floor, cwnd = SMSS, clear recovery/
    // duplicate-ACK/accumulator state) for one RTO expiry of an
    // application-data entry. Never called for a SYN-ACK or FIN timeout
    // -- see pollRetransmissions.
    static void applyTimeoutCongestionCollapse(Connection& connection);

    // Enters fast recovery on the third qualifying duplicate ACK: sets
    // ssthresh/cwnd/recovery_point per docs/tcp.md, clears every pending
    // entry's retransmitted_in_recovery (starting a fresh episode; sacked
    // marks are untouched), and returns an immediate retransmission of the
    // oldest eligible entry (see selectRecoveryRetransmission) if one
    // exists -- nullopt only if every outstanding data entry is already
    // marked sacked.
    static std::optional<TcpSegment> beginFastRecovery(const TcpConnectionKey& key,
                                                         Connection& connection,
                                                         TcpClock::time_point now);

    // Total application bytes currently charged against
    // kTcpSendBufferCapacity: unsent.size() plus every non-SYN/FIN
    // pending entry's payload size. Moving bytes from `unsent` into a
    // pending entry (scheduling) does not change this total.
    static std::size_t appOwnedBytes(const Connection& connection);

    // Converts as many FIFO bytes from `connection.unsent` into
    // MSS-bounded PSH|ACK segments as the current
    // min(availableSendWindow, availableCongestionWindow) allowance
    // permits, registers one pending entry per segment, advances
    // snd_nxt, and -- once `unsent` is fully drained by this call --
    // additionally attempts to sequence a deferred FIN (see
    // maybeSequenceFin). Returns the segments in ascending sequence
    // order (empty if no allowance exists). Never called for a
    // connection outside Established/CloseWait.
    static std::vector<TcpSegment> scheduleQueuedData(const TcpConnectionKey& key,
                                                        Connection& connection,
                                                        TcpClock::time_point now);

    // Sequences the deferred FIN and appends it to `segments` if all of:
    // close was requested, no FIN has been sequenced yet, `unsent` is
    // empty, and at least one byte of peer send window is available (a
    // FIN consumes one sequence number like any other byte; never gated
    // by cwnd). Otherwise a no-op -- the close intent is retried by the
    // next call to scheduleQueuedData. Established moves to FinWait1;
    // CloseWait moves to LastAck.
    static void maybeSequenceFin(const TcpConnectionKey& key, Connection& connection,
                                  TcpClock::time_point now, std::vector<TcpSegment>& segments);

    // True only when ALL of: state is Established/CloseWait; `unsent` is
    // non-empty; snd_wnd == 0; no sequence space is outstanding
    // (snd_nxt == snd_una); no FIN already sequenced. Deliberately
    // excludes zero-window-with-outstanding-data, which stays on
    // ordinary retransmission timing.
    static bool persistEligible(const Connection& connection);

    // Arms persist at now + kInitialPersistInterval if newly eligible and
    // not already armed; cancels (resets persist_deadline) if no longer
    // eligible; otherwise leaves the existing deadline/backoff untouched.
    static void updatePersistState(Connection& connection, TcpClock::time_point now);

    // Moves `connection` into TimeWait, arming its expiration deadline
    // and dropping any (already-acknowledged) pending entries.
    static void startTimeWait(Connection& connection, TcpClock::time_point now);

    // Total out-of-order bytes currently buffered, plus one if a peer FIN
    // is retained (task rule: an accepted out-of-order FIN counts as one
    // unit of sequence space for capacity purposes).
    static std::size_t bufferedReceiveBytes(const Connection& connection);

    // The wire-format window_size for an outgoing segment: kTcpReceiveCapacity
    // minus bufferedReceiveBytes, floor-divided by the local scale and
    // clamped into the 16-bit header field. `apply_scale` must be false
    // for a SYN-ACK (and its retransmissions) -- window scaling never
    // applies to that segment's own window field regardless of what was
    // negotiated for the rest of the connection.
    static std::uint16_t advertisedWindowFor(const Connection& connection, bool apply_scale);

    // The LOGICAL receive-window right edge actually promised to the
    // peer -- the wire value advertisedWindowFor(connection, true) would
    // produce, re-expanded by Wirestack's OWN local_window_scale (this is
    // Wirestack's own advertised window, not a peer-received one -- see
    // expandLocalAdvertisedWindow). Used only for the receive acceptance
    // test, so Wirestack never accepts bytes beyond what it actually
    // advertised even though its internal buffer is larger.
    static std::uint32_t advertisedLogicalWindowFor(const Connection& connection);

    // snd_wnd - flight_size (snd_nxt - snd_una), or 0 if the peer's
    // window is already fully consumed by outstanding (unacknowledged)
    // bytes.
    static std::uint32_t availableSendWindow(const Connection& connection);

    // Decodes a window field RECEIVED FROM THE PEER: raw << peer_window_scale
    // when scaling was negotiated, else raw unchanged. Never applied to a
    // SYN or SYN-ACK's own window field. Not to be confused with
    // expandLocalAdvertisedWindow, which uses the other (local) shift.
    static std::uint32_t decodePeerWindow(const Connection& connection, std::uint16_t raw);

    // Re-expands a WIRE VALUE WIRESTACK ITSELF ADVERTISED (produced by
    // advertisedWindowFor) back into the logical byte count it promised:
    // wire << local_window_scale when scaling was negotiated, else wire
    // unchanged. peer_window_scale plays no part here -- decoding an
    // incoming peer window and reconstructing Wirestack's own advertised
    // window are independent negotiated shifts and must never share one
    // helper implicitly.
    static std::uint32_t expandLocalAdvertisedWindow(const Connection& connection,
                                                       std::uint16_t wire);

    // Applies the RFC 793 SND.WL1/WL2 acceptance test so a stale segment
    // can never replace a newer window advertisement, then updates
    // snd_wnd/snd_wl1/snd_wl2 (via decodePeerWindow) if the new segment is
    // accepted.
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

    // Active-open SynSent: validates and processes a candidate SYN-ACK
    // (see docs/tcp.md), or drops/resets per section 9/14/16 of the
    // active-open design. Never delivers payload, never partially
    // processes a FIN, never enters a simultaneous-open state.
    static TcpReceiveResult handleSynSent(const TcpConnectionKey& key, Connection& connection,
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
