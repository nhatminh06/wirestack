#include "wirestack/tcp_connection.hpp"

#include <algorithm>

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

TcpSegment makeClosedPortReset(const TcpSegment& incoming) {
    TcpSegment reset;
    reset.source_port = incoming.destination_port;
    reset.destination_port = incoming.source_port;
    reset.flags.rst = true;
    reset.window_size = 0;
    reset.urgent_pointer = 0;

    if (incoming.flags.ack) {
        reset.sequence_number = incoming.acknowledgment_number;
    } else {
        reset.sequence_number = 0;
        std::uint32_t consumed = static_cast<std::uint32_t>(incoming.payload.size()) +
                                  (incoming.flags.syn ? 1u : 0u) + (incoming.flags.fin ? 1u : 0u);
        reset.acknowledgment_number = incoming.sequence_number + consumed;
        reset.flags.ack = true;
    }

    return reset;
}

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

TcpSegment TcpConnectionTable::makeFin(const TcpConnectionKey& key, const Connection& connection) {
    TcpSegment reply;
    reply.source_port = key.local_port;
    reply.destination_port = key.remote_port;
    reply.sequence_number = connection.snd_nxt;
    reply.acknowledgment_number = connection.rcv_nxt;
    reply.flags.fin = true;
    reply.flags.ack = true;
    reply.window_size = 65535;
    reply.urgent_pointer = 0;
    return reply;
}

void TcpConnectionTable::retireAcknowledged(Connection& connection, std::uint32_t ack) {
    if (!sequenceGreater(ack, connection.snd_una)) {
        return; // duplicate or stale ACK -- queue and snd_una both unchanged
    }
    connection.snd_una = ack;

    auto& pending = connection.pending;
    while (!pending.empty()) {
        auto& entry = pending.front();
        if (sequenceLessOrEqual(entry.sequenceEnd(), ack)) {
            pending.erase(pending.begin());
            continue;
        }
        if (sequenceGreater(ack, entry.sequence_start)) {
            // Partial ACK lands inside this entry. SYN's 1-byte range
            // can never satisfy this (no integer lies strictly between
            // sequence_start and sequence_start + 1), so this only ever
            // trims a data entry's payload.
            std::uint32_t trimmed = ack - entry.sequence_start;
            entry.payload.erase(entry.payload.begin(),
                                 entry.payload.begin() + trimmed);
            entry.sequence_start = ack;
        }
        break; // TCP is send-ordered: no later entry can be (partially) acked yet
    }
}

void TcpConnectionTable::startTimeWait(Connection& connection, TcpClock::time_point now) {
    connection.state = TcpState::TimeWait;
    connection.time_wait_deadline = now + kTimeWaitDuration;
    // Both FINs are acknowledged by construction at every call site of
    // this function, so nothing should remain pending -- cleared
    // explicitly anyway rather than relying on that invariant.
    connection.pending.clear();
}

TcpReceiveResult TcpConnectionTable::handleSynchronized(const TcpConnectionKey& key,
                                                          Connection& connection,
                                                          const TcpSegment& segment,
                                                          TcpClock::time_point now) {
    // A SYN is invalid in every synchronized state; the whole segment is
    // dropped, not partially processed.
    if (segment.flags.syn) {
        return {};
    }

    if (segment.flags.rst) {
        // Acceptable only if it lands exactly at the next expected byte.
        if (segment.sequence_number == connection.rcv_nxt) {
            TcpReceiveResult result;
            result.connection_reset = true;
            connection.pending_removal = true;
            return result;
        }
        return {};
    }

    if (!segment.flags.ack) {
        return {};
    }

    // An ACK acknowledging sequence space beyond what has been sent is
    // invalid: no state change, no payload delivery, no FIN consumption.
    if (!sequenceLessOrEqual(segment.acknowledgment_number, connection.snd_nxt)) {
        return {};
    }
    retireAcknowledged(connection, segment.acknowledgment_number);

    bool local_fin_acked = connection.local_fin_seq.has_value() &&
                            sequenceLessOrEqual(*connection.local_fin_seq + 1, connection.snd_una);

    if (connection.state == TcpState::FinWait1 && local_fin_acked) {
        connection.state = TcpState::FinWait2;
    } else if (connection.state == TcpState::Closing && local_fin_acked) {
        startTimeWait(connection, now);
    } else if (connection.state == TcpState::LastAck && local_fin_acked) {
        connection.pending_removal = true;
    }

    if (segment.payload.empty() && !segment.flags.fin) {
        // Ack information already processed above; an ordinary ACK-only
        // segment does not itself warrant a reply (that would create an
        // ACK loop). This is also exactly where a LastAck connection's
        // final ACK lands, so pending_removal (just possibly set above)
        // is surfaced here.
        TcpReceiveResult result;
        result.connection_closed = connection.pending_removal;
        return result;
    }

    if (segment.sequence_number == connection.rcv_nxt) {
        TcpReceiveResult result;
        if (!segment.payload.empty()) {
            result.accepted_payload = segment.payload;
            connection.rcv_nxt += static_cast<std::uint32_t>(segment.payload.size());
        }

        if (segment.flags.fin) {
            connection.rcv_nxt += 1;
            result.peer_closed = true;

            if (connection.state == TcpState::Established) {
                connection.state = TcpState::CloseWait;
            } else if (connection.state == TcpState::FinWait1) {
                connection.state = TcpState::Closing;
            } else if (connection.state == TcpState::FinWait2) {
                startTimeWait(connection, now);
            }

            // Only ACK the FIN directly when no payload was also
            // delivered -- an echo built from accepted_payload already
            // ACKs the post-FIN rcv_nxt, making a separate pure ACK
            // redundant.
            if (result.accepted_payload.empty()) {
                result.reply = makePureAck(key, connection);
            }
        }

        return result;
    }

    // Duplicate, out-of-order, or overlapping data (including a
    // retransmitted FIN already consumed) -- all resolve to the same
    // behavior: nothing is delivered, rcv_nxt is unchanged, no
    // peer_closed, and a duplicate ACK for the current rcv_nxt is sent.
    // No reassembly.
    TcpReceiveResult result;
    result.reply = makePureAck(key, connection);
    return result;
}

TcpReceiveResult TcpConnectionTable::handleTimeWait(const TcpConnectionKey& key,
                                                      Connection& connection,
                                                      const TcpSegment& segment,
                                                      TcpClock::time_point now) {
    if (segment.flags.rst) {
        if (segment.sequence_number == connection.rcv_nxt) {
            connection.pending_removal = true;
        }
        return {};
    }

    if (segment.flags.syn || !segment.payload.empty()) {
        return {};
    }

    // A retransmitted FIN carries the same sequence number it originally
    // did, i.e. one behind the current rcv_nxt. Plain unsigned equality
    // is wraparound-correct here (unlike ordering comparisons).
    if (segment.flags.fin && segment.sequence_number + 1 == connection.rcv_nxt) {
        connection.time_wait_deadline = now + kTimeWaitDuration;
        TcpReceiveResult result;
        result.reply = makePureAck(key, connection);
        return result;
    }

    return {};
}

TcpReceiveResult TcpConnectionTable::handle(const TcpConnectionKey& key,
                                             const TcpSegment& segment,
                                             TcpClock::time_point now) {
    if (key.local_port != listen_port_) {
        // Unbound port: never respond to an incoming RST; everything
        // else gets a closed-port reset.
        if (segment.flags.rst) {
            return {};
        }
        TcpReceiveResult result;
        result.reply = makeClosedPortReset(segment);
        return result;
    }

    auto it = connections_.find(key);

    if (it == connections_.end()) {
        if (segment.flags.rst) {
            return {}; // never respond to an incoming RST
        }
        // No existing connection: only a bare SYN (no ACK) can start one;
        // anything else (ACK, payload, FIN, SYN|ACK) for this bound port
        // with no matching connection gets a closed-port reset.
        if (!segment.flags.syn || segment.flags.ack) {
            TcpReceiveResult result;
            result.reply = makeClosedPortReset(segment);
            return result;
        }
        Connection connection;
        connection.state = TcpState::SynReceived;
        connection.remote_isn = segment.sequence_number;
        connection.local_isn = nextIsn();
        auto [inserted_it, _] = connections_.emplace(key, connection);

        TcpReceiveResult result;
        result.reply = makeSynAck(key, inserted_it->second);

        PendingTransmission pending;
        pending.sequence_start = inserted_it->second.local_isn;
        pending.is_syn = true;
        pending.flags = result.reply->flags;
        pending.last_sent = now;
        inserted_it->second.pending.push_back(std::move(pending));

        return result;
    }

    Connection& connection = it->second;

    if (connection.state == TcpState::TimeWait) {
        auto result = handleTimeWait(key, connection, segment, now);
        if (connection.pending_removal) {
            connections_.erase(it);
        }
        return result;
    }

    if (connection.state != TcpState::SynReceived) {
        auto result = handleSynchronized(key, connection, segment, now);
        if (connection.pending_removal) {
            connections_.erase(it);
        }
        return result;
    }

    // SynReceived.
    if (segment.flags.rst) {
        // Acceptable only if it acknowledges the outstanding SYN-ACK.
        if (segment.sequence_number == connection.remote_isn + 1) {
            connections_.erase(it);
        }
        return {};
    }

    if (segment.flags.syn && !segment.flags.ack) {
        // Duplicate SYN: retransmit the same SYN-ACK from stored state,
        // not a freshly drawn ISN. Re-arm the pending deadline from this
        // response without consuming the retry budget -- the peer
        // retransmitting its SYN is not a Wirestack timeout.
        if (segment.sequence_number == connection.remote_isn) {
            if (!connection.pending.empty()) {
                connection.pending.front().last_sent = now;
            }
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
            connection.snd_una = connection.local_isn; // pre-ack; retireAcknowledged advances it
            connection.snd_nxt = connection.local_isn + 1;
            retireAcknowledged(connection, connection.local_isn + 1); // drains the pending SYN-ACK
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
                                  connection.snd_nxt, connection.pending.size()};
}

std::optional<TcpSegment> TcpConnectionTable::makeOutgoingData(const TcpConnectionKey& key,
                                                                 std::vector<std::byte> payload,
                                                                 TcpClock::time_point now) {
    if (payload.empty() || payload.size() > kMaxTcpSegmentLength - 20) {
        return std::nullopt;
    }

    auto it = connections_.find(key);
    if (it == connections_.end() || (it->second.state != TcpState::Established &&
                                      it->second.state != TcpState::CloseWait)) {
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

    PendingTransmission pending;
    pending.sequence_start = connection.snd_nxt;
    pending.is_syn = false;
    pending.flags = segment.flags;
    pending.payload = segment.payload; // owns an independent copy
    pending.last_sent = now;
    connection.pending.push_back(std::move(pending));

    connection.snd_nxt += static_cast<std::uint32_t>(segment.payload.size());

    return segment;
}

std::optional<TcpSegment> TcpConnectionTable::beginClose(const TcpConnectionKey& key,
                                                           TcpClock::time_point now) {
    auto it = connections_.find(key);
    if (it == connections_.end()) {
        return std::nullopt;
    }
    Connection& connection = it->second;
    if (connection.state != TcpState::Established && connection.state != TcpState::CloseWait) {
        return std::nullopt;
    }

    TcpSegment segment = makeFin(key, connection);

    PendingTransmission pending;
    pending.sequence_start = connection.snd_nxt;
    pending.is_fin = true;
    pending.flags = segment.flags;
    pending.last_sent = now;
    connection.pending.push_back(std::move(pending));

    connection.local_fin_seq = connection.snd_nxt;
    connection.snd_nxt += 1;
    connection.state =
        connection.state == TcpState::Established ? TcpState::FinWait1 : TcpState::LastAck;

    return segment;
}

TcpTimeoutPollResult TcpConnectionTable::pollRetransmissions(TcpClock::time_point now) {
    TcpTimeoutPollResult result;

    for (auto it = connections_.begin(); it != connections_.end();) {
        Connection& connection = it->second;

        if (connection.state == TcpState::TimeWait) {
            if (connection.time_wait_deadline && now >= *connection.time_wait_deadline) {
                result.time_wait_expired.push_back(it->first);
                it = connections_.erase(it);
            } else {
                ++it;
            }
            continue;
        }

        if (connection.pending.empty()) {
            ++it;
            continue;
        }

        PendingTransmission& oldest = connection.pending.front();
        if (now < oldest.last_sent + oldest.rto) {
            ++it;
            continue;
        }

        if (oldest.retransmit_count >= kMaxRetransmits) {
            result.timed_out.push_back(it->first);
            it = connections_.erase(it);
            continue;
        }

        TcpSegment segment;
        segment.source_port = it->first.local_port;
        segment.destination_port = it->first.remote_port;
        segment.sequence_number = oldest.sequence_start;
        segment.acknowledgment_number =
            oldest.is_syn ? connection.remote_isn + 1 : connection.rcv_nxt;
        segment.flags = oldest.flags;
        segment.window_size = 65535;
        segment.urgent_pointer = 0;
        segment.payload = oldest.payload;

        oldest.retransmit_count += 1;
        oldest.last_sent = now;
        oldest.rto = std::min<TcpClock::duration>(oldest.rto * 2, kMaxRto);

        result.retransmissions.push_back({it->first, std::move(segment)});
        ++it;
    }

    return result;
}

std::optional<TcpClock::time_point> TcpConnectionTable::nextRetransmissionDeadline() const {
    std::optional<TcpClock::time_point> earliest;
    for (const auto& [key, connection] : connections_) {
        std::optional<TcpClock::time_point> deadline;
        if (connection.state == TcpState::TimeWait) {
            deadline = connection.time_wait_deadline;
        } else if (!connection.pending.empty()) {
            deadline = connection.pending.front().last_sent + connection.pending.front().rto;
        }
        if (deadline && (!earliest || *deadline < *earliest)) {
            earliest = deadline;
        }
    }
    return earliest;
}

} // namespace wirestack
