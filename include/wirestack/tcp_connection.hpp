#pragma once

#include <compare>
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
};

struct TcpConnectionKey {
    Ipv4Address local_ip;
    std::uint16_t local_port;
    Ipv4Address remote_ip;
    std::uint16_t remote_port;

    friend bool operator==(const TcpConnectionKey&, const TcpConnectionKey&) = default;
    friend auto operator<=>(const TcpConnectionKey&, const TcpConnectionKey&) = default;
};

// Read-only snapshot of a connection's sequence-space state, exposed for
// inspection (tests, logging) without exposing mutable internals.
struct TcpConnectionSnapshot {
    TcpState state;
    std::uint32_t rcv_nxt;
    std::uint32_t snd_una;
    std::uint32_t snd_nxt;
};

struct TcpReceiveResult {
    // An immediate reply to transmit as-is: a SYN-ACK during the
    // handshake, or a pure ACK for a duplicate/out-of-order/overlapping
    // established-state segment or an invalid ACK number. Never set at
    // the same time as a non-empty accepted_payload.
    std::optional<TcpSegment> reply;

    // Non-empty only when new in-order application data was accepted by
    // this call. The caller is responsible for turning this into an
    // outgoing segment via makeOutgoingData -- echo policy (or any other
    // application behavior) lives outside this class.
    std::vector<std::byte> accepted_payload;
};

// Handles the passive three-way handshake (LISTEN is implicit: any key
// with no table entry is either unbound or not yet SYN'd) and, for an
// Established connection, single in-order-segment receive with
// duplicate/out-of-order/overlap rejection and cumulative ACK processing.
// No retransmission, no segmentation/reassembly, no FIN/close.
class TcpConnectionTable {
public:
    explicit TcpConnectionTable(std::uint16_t listen_port);

    // Updates connection state for `segment` (keyed by `key`) and returns
    // any reply to transmit plus any newly accepted application payload.
    // Segments addressed to a port other than the configured listen port
    // never create state and never produce a result.
    TcpReceiveResult handle(const TcpConnectionKey& key, const TcpSegment& segment);

    std::optional<TcpState> stateOf(const TcpConnectionKey& key) const;
    std::optional<TcpConnectionSnapshot> snapshotOf(const TcpConnectionKey& key) const;

    // Builds one PSH|ACK segment carrying `payload` for an Established
    // connection and advances snd_nxt by payload.size(). Returns nullopt,
    // leaving connection state unchanged, for an unknown connection, a
    // connection not yet Established, an empty payload, or a payload that
    // would make the segment exceed kMaxTcpSegmentLength.
    std::optional<TcpSegment> makeOutgoingData(const TcpConnectionKey& key,
                                                std::vector<std::byte> payload);

private:
    struct Connection {
        TcpState state;
        std::uint32_t remote_isn;
        std::uint32_t local_isn;
        std::uint32_t rcv_nxt = 0;
        std::uint32_t snd_una = 0;
        std::uint32_t snd_nxt = 0;
    };

    // Not a secure or RFC 6528-style initial sequence number generator --
    // a small incrementing counter, isolated here so it can be replaced
    // later without touching handshake logic.
    std::uint32_t nextIsn();

    static TcpSegment makeSynAck(const TcpConnectionKey& key, const Connection& connection);
    static TcpSegment makePureAck(const TcpConnectionKey& key, const Connection& connection);

    TcpReceiveResult handleEstablished(const TcpConnectionKey& key, Connection& connection,
                                        const TcpSegment& segment);

    std::uint16_t listen_port_;
    std::uint32_t next_isn_ = 1000;
    std::map<TcpConnectionKey, Connection> connections_;
};

} // namespace wirestack
