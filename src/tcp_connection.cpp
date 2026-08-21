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

std::uint32_t sequenceMax(std::uint32_t a, std::uint32_t b) {
    return sequenceGreater(a, b) ? a : b;
}

std::uint32_t sequenceMin(std::uint32_t a, std::uint32_t b) {
    return sequenceGreater(a, b) ? b : a;
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

std::size_t TcpConnectionTable::bufferedReceiveBytes(const Connection& connection) {
    std::size_t total = 0;
    for (const auto& fragment : connection.out_of_order) {
        total += fragment.payload.size();
    }
    if (connection.pending_fin_seq) {
        total += 1;
    }
    return total;
}

std::uint16_t TcpConnectionTable::advertisedWindowFor(const Connection& connection,
                                                        bool apply_scale) {
    std::size_t buffered = bufferedReceiveBytes(connection);
    std::size_t available = buffered >= kTcpReceiveCapacity ? 0 : kTcpReceiveCapacity - buffered;
    std::size_t wire;
    if (apply_scale && connection.window_scaling_enabled) {
        wire = available >> connection.local_window_scale; // floor division, exact
    } else {
        wire = std::min<std::size_t>(available, 65535);
    }
    return static_cast<std::uint16_t>(std::min<std::size_t>(wire, 65535));
}

std::uint32_t TcpConnectionTable::advertisedLogicalWindowFor(const Connection& connection) {
    std::uint16_t wire = advertisedWindowFor(connection, connection.window_scaling_enabled);
    return expandLocalAdvertisedWindow(connection, wire);
}

std::uint32_t TcpConnectionTable::availableSendWindow(const Connection& connection) {
    std::uint32_t flight = connection.snd_nxt - connection.snd_una;
    if (flight >= connection.snd_wnd) {
        return 0;
    }
    return connection.snd_wnd - flight;
}

std::uint32_t TcpConnectionTable::availableCongestionWindow(const Connection& connection) {
    std::uint32_t flight = connection.snd_nxt - connection.snd_una;
    if (flight >= connection.cwnd) {
        return 0;
    }
    return connection.cwnd - flight;
}

std::uint32_t TcpConnectionTable::clampCwnd(std::uint64_t value) {
    return static_cast<std::uint32_t>(std::min<std::uint64_t>(value, kMaxCongestionWindow));
}

std::uint32_t TcpConnectionTable::initialCongestionWindow(std::uint16_t smss) {
    std::uint64_t ten_smss = std::uint64_t{10} * smss;
    std::uint64_t two_smss = std::uint64_t{2} * smss;
    std::uint64_t floor_value = std::max<std::uint64_t>(two_smss, kInitialCongestionWindowFloor);
    return clampCwnd(std::min(ten_smss, floor_value));
}

void TcpConnectionTable::applyCongestionGrowth(Connection& connection, std::uint32_t data_bytes) {
    if (data_bytes == 0) {
        return; // SYN/FIN/pure-ACK acknowledgment carries no application data
    }
    std::uint32_t smss = connection.effective_send_mss;
    if (connection.cwnd < connection.ssthresh) {
        // Slow Start: one ACK grows cwnd by at most one SMSS, regardless
        // of how many bytes it cumulatively acknowledges.
        std::uint32_t increase = std::min(data_bytes, smss);
        connection.cwnd = clampCwnd(std::uint64_t{connection.cwnd} + increase);
    } else {
        // Congestion Avoidance: one SMSS of growth per cwnd of
        // acknowledged data, applied repeatedly if a single cumulative
        // ACK crosses more than one window's worth.
        connection.congestion_avoidance_acked_bytes += data_bytes;
        while (connection.cwnd > 0 &&
               connection.congestion_avoidance_acked_bytes >= connection.cwnd) {
            connection.congestion_avoidance_acked_bytes -= connection.cwnd;
            connection.cwnd = clampCwnd(std::uint64_t{connection.cwnd} + smss);
        }
    }
}

void TcpConnectionTable::applyTimeoutCongestionCollapse(Connection& connection) {
    std::uint32_t flight = connection.snd_nxt - connection.snd_una;
    std::uint32_t smss = connection.effective_send_mss;
    connection.ssthresh = clampCwnd(std::max<std::uint64_t>(flight / 2, std::uint64_t{2} * smss));
    connection.cwnd = smss;
    connection.duplicate_ack_count = 0;
    connection.in_fast_recovery = false;
    connection.congestion_avoidance_acked_bytes = 0;
}

std::uint32_t TcpConnectionTable::decodePeerWindow(const Connection& connection,
                                                     std::uint16_t raw) {
    if (!connection.window_scaling_enabled) {
        return raw;
    }
    return static_cast<std::uint32_t>(raw) << connection.peer_window_scale;
}

std::uint32_t TcpConnectionTable::expandLocalAdvertisedWindow(const Connection& connection,
                                                                 std::uint16_t wire) {
    if (!connection.window_scaling_enabled) {
        return wire;
    }
    return static_cast<std::uint32_t>(wire) << connection.local_window_scale;
}

void TcpConnectionTable::updateSendWindow(Connection& connection, const TcpSegment& segment) {
    bool accept = sequenceGreater(segment.sequence_number, connection.snd_wl1) ||
                  (segment.sequence_number == connection.snd_wl1 &&
                   sequenceLessOrEqual(connection.snd_wl2, segment.acknowledgment_number));
    if (!accept) {
        return; // stale segment -- keep the newer window advertisement
    }
    connection.snd_wnd = decodePeerWindow(connection, segment.window_size);
    connection.snd_wl1 = segment.sequence_number;
    connection.snd_wl2 = segment.acknowledgment_number;
}

std::vector<std::byte> TcpConnectionTable::buildSynAckOptions(const Connection& connection) {
    std::vector<std::byte> out;
    out.push_back(std::byte{2}); // kind: MSS
    out.push_back(std::byte{4}); // length
    out.push_back(static_cast<std::byte>((kTcpMss >> 8) & 0xff));
    out.push_back(static_cast<std::byte>(kTcpMss & 0xff));
    if (connection.window_scaling_enabled) {
        out.push_back(std::byte{1}); // NOP (pads to a 4-byte boundary)
        out.push_back(std::byte{3}); // kind: Window Scale
        out.push_back(std::byte{3}); // length
        out.push_back(static_cast<std::byte>(connection.local_window_scale));
    }
    return out;
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
    reply.window_size = advertisedWindowFor(connection, /*apply_scale=*/false);
    reply.urgent_pointer = 0;
    reply.options = buildSynAckOptions(connection);
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
    reply.window_size = advertisedWindowFor(connection, connection.window_scaling_enabled);
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
    reply.window_size = advertisedWindowFor(connection, connection.window_scaling_enabled);
    reply.urgent_pointer = 0;
    return reply;
}

void TcpConnectionTable::recordRttSample(Connection& connection, TcpClock::duration r) {
    if (!connection.has_rtt_sample) {
        connection.srtt = r;
        connection.rttvar = r / 2;
        connection.has_rtt_sample = true;
    } else {
        // Uses the OLD srtt for the RTTVAR update, per RFC 6298 -- the
        // reassignment below happens only after this line runs.
        auto diff = std::chrono::abs(connection.srtt - r);
        connection.rttvar = (connection.rttvar * 3 + diff) / 4;
        connection.srtt = (connection.srtt * 7 + r) / 8;
    }
    auto rto = connection.srtt + std::max<TcpClock::duration>(kRtoGranularity, connection.rttvar * 4);
    connection.current_rto = std::clamp<TcpClock::duration>(rto, kMinRto, kMaxRto);
}

TcpConnectionTable::TcpAckRetirementResult TcpConnectionTable::retireAcknowledged(
    Connection& connection, std::uint32_t ack, TcpClock::time_point now) {
    TcpAckRetirementResult result;
    if (!sequenceGreater(ack, connection.snd_una)) {
        return result; // duplicate or stale ACK -- queue and snd_una both unchanged
    }
    result.ack_advanced = true;
    std::uint32_t old_snd_una = connection.snd_una;
    connection.snd_una = ack;
    result.newly_acked_sequence_space = ack - old_snd_una;

    // Newest (last-processed, since entries are in send order) entry
    // covered -- fully or partially -- by this ack that was never
    // retransmitted AND has not already contributed a sample. Karn's rule
    // falls out for free: a retransmitted entry is simply never a
    // candidate. rtt_sample_taken separately prevents one transmission
    // from producing more than one sample across successive partial ACKs
    // of its still-outstanding remainder.
    std::optional<TcpClock::time_point> sample_first_sent;
    PendingTransmission* sample_entry = nullptr; // set only if it survives (partial trim)

    auto& pending = connection.pending;
    while (!pending.empty()) {
        auto& entry = pending.front();
        if (sequenceLessOrEqual(entry.sequenceEnd(), ack)) {
            result.newly_acked_data_bytes += static_cast<std::uint32_t>(entry.payload.size());
            if (entry.retransmit_count == 0 && !entry.rtt_sample_taken) {
                sample_first_sent = entry.first_sent_at;
                sample_entry = nullptr; // this entry is about to be erased
            }
            pending.erase(pending.begin());
            continue;
        }
        if (sequenceGreater(ack, entry.sequence_start)) {
            // Partial ACK lands inside this entry. SYN's 1-byte range
            // can never satisfy this (no integer lies strictly between
            // sequence_start and sequence_start + 1), so this only ever
            // trims a data entry's payload -- newly_acked_data_bytes below
            // is exactly the trimmed span, never a SYN/FIN control byte.
            std::uint32_t trimmed = ack - entry.sequence_start;
            result.newly_acked_data_bytes += trimmed;
            if (entry.retransmit_count == 0 && !entry.rtt_sample_taken) {
                sample_first_sent = entry.first_sent_at;
                sample_entry = &entry; // survives, trimmed -- mark below
            }
            entry.payload.erase(entry.payload.begin(),
                                 entry.payload.begin() + trimmed);
            entry.sequence_start = ack;
        }
        break; // TCP is send-ordered: no later entry can be (partially) acked yet
    }

    if (sample_first_sent && *sample_first_sent <= now) {
        recordRttSample(connection, now - *sample_first_sent);
        result.rtt_sample_taken = true;
        if (sample_entry) {
            sample_entry->rtt_sample_taken = true;
        }
    }

    return result;
}

void TcpConnectionTable::startTimeWait(Connection& connection, TcpClock::time_point now) {
    connection.state = TcpState::TimeWait;
    connection.time_wait_deadline = now + kTimeWaitDuration;
    // Both FINs are acknowledged by construction at every call site of
    // this function, so nothing should remain pending -- cleared
    // explicitly anyway rather than relying on that invariant.
    connection.pending.clear();
}

void TcpConnectionTable::insertReassemblyFragment(Connection& connection,
                                                    std::uint32_t sequence_start,
                                                    std::vector<std::byte> payload) {
    // Normalize to offsets from rcv_nxt: by construction (the caller
    // already trimmed to the receive window) these are small plain
    // numbers bounded by the window, so ordinary integer comparisons are
    // correct here with no wraparound-specific handling needed -- the
    // wraparound-aware work already happened in the caller's window
    // acceptance test.
    std::uint32_t base = connection.rcv_nxt;
    std::uint32_t new_start = sequence_start - base;
    std::uint32_t new_end = new_start + static_cast<std::uint32_t>(payload.size());

    // First-arrival-wins: subtract every existing fragment's range from
    // the new range, so already-buffered bytes are never overwritten.
    std::vector<std::pair<std::uint32_t, std::uint32_t>> gaps = {{new_start, new_end}};
    for (const auto& fragment : connection.out_of_order) {
        std::uint32_t f_start = fragment.sequence_start - base;
        std::uint32_t f_end = f_start + static_cast<std::uint32_t>(fragment.payload.size());
        std::vector<std::pair<std::uint32_t, std::uint32_t>> next_gaps;
        for (auto [s, e] : gaps) {
            if (f_end <= s || f_start >= e) {
                next_gaps.push_back({s, e}); // no overlap with this fragment
                continue;
            }
            if (f_start > s) next_gaps.push_back({s, f_start}); // new bytes before it
            if (f_end < e) next_gaps.push_back({f_end, e});     // new bytes after it
        }
        gaps = std::move(next_gaps);
    }

    for (auto [gap_start, gap_end] : gaps) {
        if (gap_start >= gap_end) continue;
        if (connection.out_of_order.size() >= kMaxReassemblyFragments) {
            break; // bounded: remaining genuinely-new bytes are dropped
        }
        std::vector<std::byte> piece(payload.begin() + (gap_start - new_start),
                                      payload.begin() + (gap_end - new_start));
        connection.out_of_order.push_back(
            TcpReassemblyFragment{base + gap_start, std::move(piece)});
    }

    std::sort(connection.out_of_order.begin(), connection.out_of_order.end(),
              [base](const TcpReassemblyFragment& a, const TcpReassemblyFragment& b) {
                  return (a.sequence_start - base) < (b.sequence_start - base);
              });

    // Coalesce fragments that now touch, keeping the steady-state
    // fragment count low.
    std::vector<TcpReassemblyFragment> merged;
    merged.reserve(connection.out_of_order.size());
    for (auto& fragment : connection.out_of_order) {
        if (!merged.empty() && merged.back().sequenceEnd() == fragment.sequence_start) {
            merged.back().payload.insert(merged.back().payload.end(), fragment.payload.begin(),
                                          fragment.payload.end());
        } else {
            merged.push_back(std::move(fragment));
        }
    }
    connection.out_of_order = std::move(merged);
}

std::vector<std::byte> TcpConnectionTable::releaseContiguous(Connection& connection) {
    std::vector<std::byte> released;
    auto it = connection.out_of_order.begin();
    while (it != connection.out_of_order.end() && it->sequence_start == connection.rcv_nxt) {
        released.insert(released.end(), it->payload.begin(), it->payload.end());
        connection.rcv_nxt += static_cast<std::uint32_t>(it->payload.size());
        it = connection.out_of_order.erase(it);
    }
    return released;
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
    TcpAckRetirementResult ack_result =
        retireAcknowledged(connection, segment.acknowledgment_number, now);
    updateSendWindow(connection, segment);

    // Reno-style congestion control (see docs/tcp.md): an advancing ACK
    // applies Slow Start/Congestion Avoidance growth to its newly
    // acknowledged application-data bytes (a no-op for a SYN/FIN/pure-ACK
    // acknowledgment, which carries none).
    if (ack_result.ack_advanced) {
        applyCongestionGrowth(connection, ack_result.newly_acked_data_bytes);
    }

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

    // Window acceptance test, using the LOGICAL window as advertised
    // before this segment's own bytes are considered -- Wirestack must
    // never accept bytes beyond what it actually promised the peer, even
    // though its internal buffer may hold more.
    std::uint32_t window = advertisedLogicalWindowFor(connection);
    std::uint32_t window_end = connection.rcv_nxt + window;
    std::uint32_t seg_start = segment.sequence_number;
    std::uint32_t seg_end = seg_start + static_cast<std::uint32_t>(segment.payload.size());

    std::uint32_t usable_start = sequenceMax(connection.rcv_nxt, seg_start);
    std::uint32_t usable_end = sequenceMin(seg_end, window_end);
    bool any_payload_in_window = sequenceGreater(usable_end, usable_start);

    // A peer FIN can only be newly retained while the peer's FIN hasn't
    // already been consumed -- Established/FinWait1/FinWait2. In every
    // other synchronized state, a FIN flag here is necessarily a
    // retransmission of one already consumed and is handled by the
    // duplicate-ACK fallback below.
    bool fin_events_open = connection.state == TcpState::Established ||
                            connection.state == TcpState::FinWait1 ||
                            connection.state == TcpState::FinWait2;
    // The FIN's own sequence position must itself lie within the window;
    // a FIN whose preceding payload was right-edge-trimmed away is never
    // retained (its position is already >= window_end).
    bool fin_in_window = fin_events_open && segment.flags.fin &&
                          sequenceLessOrEqual(connection.rcv_nxt, seg_end) &&
                          sequenceGreater(window_end, seg_end);

    if (!any_payload_in_window && !fin_in_window) {
        // Nothing of this segment lies in the receive window: store
        // nothing, deliver nothing, rcv_nxt unchanged, duplicate ACK.
        TcpReceiveResult result;
        result.reply = makePureAck(key, connection);
        return result;
    }

    if (any_payload_in_window) {
        std::uint32_t prefix_trim = usable_start - seg_start;
        std::uint32_t usable_len = usable_end - usable_start;
        std::vector<std::byte> usable_payload(
            segment.payload.begin() + prefix_trim,
            segment.payload.begin() + prefix_trim + usable_len);
        insertReassemblyFragment(connection, usable_start, std::move(usable_payload));
    }
    if (fin_in_window) {
        connection.pending_fin_seq = seg_end;
    }

    TcpReceiveResult result;
    result.accepted_payload = releaseContiguous(connection);

    if (connection.pending_fin_seq && *connection.pending_fin_seq == connection.rcv_nxt) {
        connection.rcv_nxt += 1;
        connection.pending_fin_seq.reset();
        result.peer_closed = true;

        if (connection.state == TcpState::Established) {
            connection.state = TcpState::CloseWait;
        } else if (connection.state == TcpState::FinWait1) {
            connection.state = TcpState::Closing;
        } else if (connection.state == TcpState::FinWait2) {
            startTimeWait(connection, now);
        }
    }

    // Only reply directly when nothing was released -- an out-of-order
    // arrival (still gapped) gets a duplicate ACK; a released payload is
    // ACKed by whatever the caller builds from accepted_payload instead
    // (an echo/response), avoiding a redundant separate ACK.
    if (result.accepted_payload.empty()) {
        result.reply = makePureAck(key, connection);
    }
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

        // Malformed SYN options: no SYN-ACK, no connection state, no RST
        // -- an ordinary packet rejection, not a protocol error response.
        auto parsed_options = parseTcpOptions(segment.options);
        if (std::holds_alternative<TcpOptionParseError>(parsed_options)) {
            return {};
        }
        const auto& options = std::get<TcpParsedOptions>(parsed_options);

        Connection connection;
        connection.state = TcpState::SynReceived;
        connection.remote_isn = segment.sequence_number;
        connection.local_isn = nextIsn();

        connection.peer_mss = options.maximum_segment_size.value_or(kDefaultPeerMss);
        connection.effective_send_mss = std::min<std::uint16_t>(
            static_cast<std::uint16_t>(kTcpMss), connection.peer_mss);
        // Congestion state is initialized only now, once the negotiated
        // MSS this connection will actually use is fixed; ssthresh needs
        // no MSS knowledge and is already defaulted in the struct. SYN
        // and SYN-ACK are never gated by cwnd.
        connection.cwnd = initialCongestionWindow(connection.effective_send_mss);
        if (options.window_scale) {
            connection.window_scaling_enabled = true;
            connection.peer_window_scale =
                std::min<std::uint8_t>(*options.window_scale, kMaxWindowScaleShift);
            connection.local_window_scale = kLocalWindowScaleShift;
        }

        auto [inserted_it, _] = connections_.emplace(key, connection);

        TcpReceiveResult result;
        result.reply = makeSynAck(key, inserted_it->second);

        PendingTransmission pending;
        pending.sequence_start = inserted_it->second.local_isn;
        pending.is_syn = true;
        pending.flags = result.reply->flags;
        pending.first_sent_at = now;
        pending.last_sent_at = now;
        pending.timeout_interval = inserted_it->second.current_rto;
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
                connection.pending.front().last_sent_at = now;
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
            // Drains the pending SYN-ACK; also this connection's first
            // RTT sample when the SYN-ACK was never retransmitted.
            retireAcknowledged(connection, connection.local_isn + 1, now);
            // Initialize the peer send window directly from the
            // handshake-completing ACK -- the first advertisement, so no
            // staleness test is needed. This ACK is not itself a SYN or
            // SYN-ACK, so window scaling (if negotiated) already applies.
            connection.snd_wnd = decodePeerWindow(connection, segment.window_size);
            connection.snd_wl1 = segment.sequence_number;
            connection.snd_wl2 = segment.acknowledgment_number;
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
    return TcpConnectionSnapshot{
        connection.state,
        connection.rcv_nxt,
        connection.snd_una,
        connection.snd_nxt,
        connection.pending.size(),
        connection.snd_wnd,
        connection.out_of_order.size(),
        bufferedReceiveBytes(connection),
        advertisedWindowFor(connection, connection.window_scaling_enabled),
        connection.peer_mss,
        connection.effective_send_mss,
        connection.peer_window_scale,
        connection.local_window_scale,
        connection.window_scaling_enabled,
        connection.has_rtt_sample,
        connection.srtt,
        connection.rttvar,
        connection.current_rto,
        connection.cwnd,
        connection.ssthresh,
        connection.duplicate_ack_count,
        connection.in_fast_recovery,
        connection.recovery_point,
        connection.congestion_avoidance_acked_bytes,
    };
}

TcpSendResult TcpConnectionTable::makeOutgoingData(const TcpConnectionKey& key,
                                                     std::vector<std::byte> payload,
                                                     TcpClock::time_point now) {
    TcpSendResult result;
    if (payload.empty()) {
        result.error = TcpSendError::EmptyPayload;
        return result;
    }
    if (payload.size() > kMaxApplicationSendSize) {
        result.error = TcpSendError::TooLarge;
        return result;
    }

    auto it = connections_.find(key);
    if (it == connections_.end() || (it->second.state != TcpState::Established &&
                                      it->second.state != TcpState::CloseWait)) {
        result.error = TcpSendError::NotSendable;
        return result;
    }
    Connection& connection = it->second;

    // New application data is gated by both limits; whichever is smaller
    // is reported as the rejection reason. A tie (equal availability)
    // reports WindowTooSmall -- an arbitrary but documented tie-break,
    // since either is equally true and only one error value can be
    // returned.
    std::uint32_t rwnd_available = availableSendWindow(connection);
    std::uint32_t cwnd_available = availableCongestionWindow(connection);
    if (payload.size() > rwnd_available || payload.size() > cwnd_available) {
        result.error = (cwnd_available < rwnd_available) ? TcpSendError::CongestionWindowTooSmall
                                                           : TcpSendError::WindowTooSmall;
        return result;
    }

    std::size_t total = payload.size();
    std::size_t mss = connection.effective_send_mss;
    std::size_t segment_count = (total + mss - 1) / mss;
    if (segment_count > kMaxSegmentsPerSend) {
        // A tiny negotiated peer MSS could otherwise fragment this send
        // into an unbounded number of segments; reject atomically.
        result.error = TcpSendError::TooLarge;
        return result;
    }
    std::vector<TcpSegment> segments;
    segments.reserve(segment_count);

    std::uint32_t seq = connection.snd_nxt;
    std::size_t offset = 0;
    while (offset < total) {
        std::size_t chunk = std::min(mss, total - offset);
        bool is_last = offset + chunk == total;

        TcpSegment segment;
        segment.source_port = key.local_port;
        segment.destination_port = key.remote_port;
        segment.sequence_number = seq;
        segment.acknowledgment_number = connection.rcv_nxt;
        segment.flags.ack = true;
        segment.flags.psh = is_last;
        segment.window_size = advertisedWindowFor(connection, connection.window_scaling_enabled);
        segment.urgent_pointer = 0;
        segment.payload.assign(payload.begin() + static_cast<std::ptrdiff_t>(offset),
                                payload.begin() + static_cast<std::ptrdiff_t>(offset + chunk));
        segments.push_back(segment);

        seq += static_cast<std::uint32_t>(chunk);
        offset += chunk;
    }

    for (const auto& segment : segments) {
        PendingTransmission pending;
        pending.sequence_start = segment.sequence_number;
        pending.is_syn = false;
        pending.flags = segment.flags;
        pending.payload = segment.payload; // owns an independent copy
        pending.first_sent_at = now;
        pending.last_sent_at = now;
        pending.timeout_interval = connection.current_rto;
        connection.pending.push_back(std::move(pending));
    }

    connection.snd_nxt += static_cast<std::uint32_t>(total);

    result.segments = std::move(segments);
    result.bytes_accepted = total;
    return result;
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
    if (availableSendWindow(connection) < 1) {
        return std::nullopt; // a FIN consumes one send-window sequence number too
    }

    TcpSegment segment = makeFin(key, connection);

    PendingTransmission pending;
    pending.sequence_start = connection.snd_nxt;
    pending.is_fin = true;
    pending.flags = segment.flags;
    pending.first_sent_at = now;
    pending.last_sent_at = now;
    pending.timeout_interval = connection.current_rto;
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
        if (now < oldest.last_sent_at + oldest.timeout_interval) {
            ++it;
            continue;
        }

        if (oldest.retransmit_count >= kMaxRetransmits) {
            result.timed_out.push_back(it->first);
            it = connections_.erase(it);
            continue;
        }

        if (!oldest.is_syn && !oldest.is_fin) {
            // Congestion collapse applies once per timeout event, only
            // for an established application-data segment -- SYN-ACK and
            // FIN timeouts preserve existing retransmission behavior
            // without touching application-data congestion state. Safe
            // against a second poll at the same instant: last_sent_at is
            // set to `now` below, so the entry's deadline cannot be due
            // again until strictly later.
            applyTimeoutCongestionCollapse(connection);
        }

        TcpSegment segment;
        segment.source_port = it->first.local_port;
        segment.destination_port = it->first.remote_port;
        segment.sequence_number = oldest.sequence_start;
        segment.acknowledgment_number =
            oldest.is_syn ? connection.remote_isn + 1 : connection.rcv_nxt;
        segment.flags = oldest.flags;
        // Refreshed to the current advertised window, same as the
        // acknowledgment number just above, before checksum serialization.
        // A retransmitted SYN-ACK stays unscaled, same as the original.
        segment.window_size =
            advertisedWindowFor(connection, !oldest.is_syn && connection.window_scaling_enabled);
        segment.urgent_pointer = 0;
        segment.payload = oldest.payload;
        if (oldest.is_syn) {
            // A timeout-retransmitted SYN-ACK must carry the same
            // negotiated options (MSS, Window Scale) as the original --
            // otherwise a retransmission silently drops Data Offset bytes
            // the peer already parsed from the first copy.
            segment.options = buildSynAckOptions(connection);
        }

        oldest.retransmit_count += 1;
        oldest.last_sent_at = now;
        oldest.timeout_interval = std::min<TcpClock::duration>(oldest.timeout_interval * 2, kMaxRto);
        // The connection's own RTO reflects this backed-off value too, so
        // a later new send starts from the more conservative point rather
        // than resetting to the pre-loss estimate -- but a timeout must
        // never make the connection-level estimate LESS conservative than
        // it already was (a different, still-outstanding entry may have a
        // smaller per-entry interval than the connection has already
        // backed off to).
        connection.current_rto =
            std::max<TcpClock::duration>(connection.current_rto, oldest.timeout_interval);

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
            deadline = connection.pending.front().last_sent_at +
                       connection.pending.front().timeout_interval;
        }
        if (deadline && (!earliest || *deadline < *earliest)) {
            earliest = deadline;
        }
    }
    return earliest;
}

} // namespace wirestack
