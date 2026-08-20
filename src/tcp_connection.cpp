#include "wirestack/tcp_connection.hpp"

namespace wirestack {

namespace {

// Wraparound-safe 32-bit sequence-number comparisons. Assumes the tracked
// sequence-space window (the distance between the oldest unacknowledged
// byte and the next byte to send/receive) stays under half of the full
// 32-bit space, which holds for any traffic this milestone generates.
bool sequenceGreater(std::uint32_t a, std::uint32_t b) {
    return static_cast<std::int32_t>(a - b) > 0;
}

bool sequenceLessOrEqual(std::uint32_t a, std::uint32_t b) {
    return static_cast<std::int32_t>(b - a) >= 0;
}

} // namespace

TcpConnectionTable::TcpConnectionTable(std::uint16_t listen_port) : listen_port_(listen_port) {}

std::uint32_t TcpConnectionTable::nextIsn() {
    std::uint32_t isn = next_isn_;
    next_isn_ += 1000;
    return isn;
}

TcpSegment TcpConnectionTable::makeSynAck(const TcpConnectionKey& key,
                                           const Connection& connection) {
    TcpSegment reply;
    reply.source_port = key.local_port;
    reply.destination_port = key.remote_port;
    reply.sequence_number = connection.local_isn;
    reply.acknowledgment_number = connection.remote_isn + 1;
    reply.flags.syn = true;
    reply.flags.ack = true;
    reply.window_size = 65535;
    reply.urgent_pointer = 0;
    return reply;
}

TcpSegment TcpConnectionTable::makePureAck(const TcpConnectionKey& key,
                                            const Connection& connection) {
    TcpSegment reply;
    reply.source_port = key.local_port;
    reply.destination_port = key.remote_port;
    reply.sequence_number = connection.snd_nxt;
    reply.acknowledgment_number = connection.rcv_nxt;
    reply.flags.ack = true;
    reply.window_size = 65535;
    reply.urgent_pointer = 0;
    return reply;
}

TcpReceiveResult TcpConnectionTable::handleEstablished(const TcpConnectionKey& key,
                                                         Connection& connection,
                                                         const TcpSegment& segment) {
    // FIN/RST/SYN are unsupported in Established; a payload attached to
    // one of these is not partially processed -- the whole segment is
    // dropped.
    if (segment.flags.syn || segment.flags.fin || segment.flags.rst) {
        return {};
    }
    if (!segment.flags.ack) {
        return {};
    }

    // An ACK acknowledging sequence space beyond what has been sent is
    // invalid: no state change, no payload delivery, no reply.
    if (!sequenceLessOrEqual(segment.acknowledgment_number, connection.snd_nxt)) {
        return {};
    }
    // A stale ACK (behind snd_una) never moves state backward; a
    // duplicate ACK (== snd_una) leaves it unchanged too. Only an
    // acknowledgment strictly ahead of snd_una advances it.
    if (sequenceGreater(segment.acknowledgment_number, connection.snd_una)) {
        connection.snd_una = segment.acknowledgment_number;
    }

    if (segment.payload.empty()) {
        // Ack information already processed above; an ordinary ACK-only
        // segment does not itself warrant a reply (that would create an
        // ACK loop).
        return {};
    }

    if (segment.sequence_number == connection.rcv_nxt) {
        TcpReceiveResult result;
        result.accepted_payload = segment.payload;
        connection.rcv_nxt += static_cast<std::uint32_t>(segment.payload.size());
        return result;
    }

    // Duplicate, out-of-order, or overlapping data -- all resolve to the
    // same behavior: nothing is delivered, rcv_nxt is unchanged, and a
    // duplicate ACK for the current rcv_nxt is sent. No reassembly.
    TcpReceiveResult result;
    result.reply = makePureAck(key, connection);
    return result;
}

TcpReceiveResult TcpConnectionTable::handle(const TcpConnectionKey& key,
                                             const TcpSegment& segment) {
    if (key.local_port != listen_port_) {
        return {};
    }

    auto it = connections_.find(key);

    if (it == connections_.end()) {
        // No existing connection: only a bare SYN (no ACK) can start one.
        if (!segment.flags.syn || segment.flags.ack) {
            return {};
        }
        Connection connection;
        connection.state = TcpState::SynReceived;
        connection.remote_isn = segment.sequence_number;
        connection.local_isn = nextIsn();
        auto [inserted_it, _] = connections_.emplace(key, connection);
        TcpReceiveResult result;
        result.reply = makeSynAck(key, inserted_it->second);
        return result;
    }

    Connection& connection = it->second;

    if (connection.state == TcpState::Established) {
        return handleEstablished(key, connection, segment);
    }

    // SynReceived.
    if (segment.flags.syn && !segment.flags.ack) {
        // Duplicate SYN: retransmit the same SYN-ACK from stored state,
        // not a freshly drawn ISN.
        if (segment.sequence_number == connection.remote_isn) {
            TcpReceiveResult result;
            result.reply = makeSynAck(key, connection);
            return result;
        }
        return {};
    }

    if (segment.flags.ack && !segment.flags.syn) {
        if (segment.acknowledgment_number == connection.local_isn + 1 &&
            segment.sequence_number == connection.remote_isn + 1) {
            connection.state = TcpState::Established;
            // SYN consumed one sequence number in each direction.
            connection.rcv_nxt = connection.remote_isn + 1;
            connection.snd_una = connection.local_isn + 1;
            connection.snd_nxt = connection.local_isn + 1;
        }
        return {};
    }

    return {};
}

std::optional<TcpState> TcpConnectionTable::stateOf(const TcpConnectionKey& key) const {
    auto it = connections_.find(key);
    if (it == connections_.end()) {
        return std::nullopt;
    }
    return it->second.state;
}

std::optional<TcpConnectionSnapshot> TcpConnectionTable::snapshotOf(
    const TcpConnectionKey& key) const {
    auto it = connections_.find(key);
    if (it == connections_.end()) {
        return std::nullopt;
    }
    const Connection& connection = it->second;
    return TcpConnectionSnapshot{connection.state, connection.rcv_nxt, connection.snd_una,
                                  connection.snd_nxt};
}

std::optional<TcpSegment> TcpConnectionTable::makeOutgoingData(const TcpConnectionKey& key,
                                                                 std::vector<std::byte> payload) {
    if (payload.empty() || payload.size() > kMaxTcpSegmentLength - 20) {
        return std::nullopt;
    }

    auto it = connections_.find(key);
    if (it == connections_.end() || it->second.state != TcpState::Established) {
        return std::nullopt;
    }
    Connection& connection = it->second;

    TcpSegment segment;
    segment.source_port = key.local_port;
    segment.destination_port = key.remote_port;
    segment.sequence_number = connection.snd_nxt;
    segment.acknowledgment_number = connection.rcv_nxt;
    segment.flags.psh = true;
    segment.flags.ack = true;
    segment.window_size = 65535;
    segment.urgent_pointer = 0;
    segment.payload = std::move(payload);

    connection.snd_nxt += static_cast<std::uint32_t>(segment.payload.size());

    return segment;
}

} // namespace wirestack
