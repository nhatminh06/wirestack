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
    NotSendable,       // connection unknown or not Established/CloseWait
    EmptyPayload,
    TooLarge,                   // exceeds kMaxApplicationSendSize
    WindowTooSmall,             // exceeds the currently available peer send window
    CongestionWindowTooSmall,   // exceeds the currently available congestion window
    ConstructionFailed,         // a chunk failed to serialize-size correctly
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
// with no table entry is either unbound or not yet SYN'd) including MSS
// and Window Scale option negotiation, MSS-bounded outgoing segmentation
// within the peer's advertised (and, once negotiated, scaled) send
// window and a Reno-style congestion window, bounded out-of-order
// receive reassembly with duplicate/overlap trimming, cumulative ACK
// processing with Slow Start/Congestion Avoidance growth, RTT-adaptive
// timeout-based retransmission of sequence-consuming segments (SYN-ACK,
// application data, FIN -- never pure ACKs), passive/active/simultaneous
// close, deterministic TIME_WAIT, and acceptable inbound RST. No fast
// retransmit, no fast recovery, no SACK, no TCP timestamps, no active
// open.
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
    // payload exceeding kMaxApplicationSendSize, or payload exceeding
    // min(peer send window, congestion window) -- reported as
    // WindowTooSmall or CongestionWindowTooSmall respectively, whichever
    // is the smaller/binding limit) no bytes are accepted, no segment is
    // queued, and snd_nxt is unchanged. Callers must retry a rejected
    // send later, after the peer's advertised window or the congestion
    // window changes -- there is no internal send queue or automatic
    // retry. A timeout retransmission is not new data and does not
    // consume additional congestion-window allowance.
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
        // Set once at construction, never overwritten by a retransmission
        // -- this is what an RTT sample is measured against.
        TcpClock::time_point first_sent_at;
        TcpClock::time_point last_sent_at;
        TcpClock::duration timeout_interval = kInitialRto; // this entry's own backed-off timeout
        int retransmit_count = 0; // > 0 also means "not eligible for an RTT sample" (Karn's rule)
        // Set once an ACK has taken an RTT sample from this entry (full or
        // partial retirement). Distinct from Karn eligibility: a
        // never-retransmitted entry may still be ineligible for a *second*
        // sample after a partial ACK already sampled it once.
        bool rtt_sample_taken = false;

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
    };

    // Not a secure or RFC 6528-style initial sequence number generator --
    // a small incrementing counter, isolated here so it can be replaced
    // later without touching handshake logic.
    std::uint32_t nextIsn();

    static TcpSegment makeSynAck(const TcpConnectionKey& key, const Connection& connection);
    static TcpSegment makePureAck(const TcpConnectionKey& key, const Connection& connection);
    static TcpSegment makeFin(const TcpConnectionKey& key, const Connection& connection);

    // MSS (always kTcpMss, never derived from the peer) and, only when
    // window_scaling_enabled, NOP + Window Scale -- see docs/tcp.md for
    // the exact byte layouts. Already word-aligned; no padding needed.
    static std::vector<std::byte> buildSynAckOptions(const Connection& connection);

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
    // retransmitted entry is simply never an eligible candidate, and
    // rtt_sample_taken prevents a still-partially-outstanding entry from
    // being sampled a second time by a later ACK.
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

    // TimeWait has no payload/application events and only reacts to a
    // duplicate FIN (restarts the deadline) or an acceptable RST.
    static TcpReceiveResult handleTimeWait(const TcpConnectionKey& key, Connection& connection,
                                            const TcpSegment& segment, TcpClock::time_point now);

    std::uint16_t listen_port_;
    std::uint32_t next_isn_ = 1000;
    std::map<TcpConnectionKey, Connection> connections_;
};

} // namespace wirestack
