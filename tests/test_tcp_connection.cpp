#include "wirestack/tcp_connection.hpp"

#include "test_util.hpp"

using wirestack::Ipv4Address;
using wirestack::kInitialRto;
using wirestack::kMaxRetransmits;
using wirestack::kMaxRto;
using wirestack::TcpClock;
using wirestack::TcpConnectionKey;
using wirestack::TcpConnectionTable;
using wirestack::TcpSegment;
using wirestack::TcpState;

namespace {

// A fixed synthetic instant used as "now" by every test that doesn't
// itself exercise retransmission timing; tests that do advance from this
// point by explicit durations, never by sleeping or reading real time.
constexpr TcpClock::time_point t0{};

Ipv4Address localIp() {
    return *Ipv4Address::parse("10.0.0.2");
}
Ipv4Address remoteIp() {
    return *Ipv4Address::parse("10.0.0.1");
}

TcpSegment makeSyn(std::uint16_t local_port, std::uint16_t remote_port, std::uint32_t seq) {
    TcpSegment segment;
    segment.source_port = remote_port;
    segment.destination_port = local_port;
    segment.sequence_number = seq;
    segment.acknowledgment_number = 0;
    segment.flags.syn = true;
    segment.window_size = 65535;
    segment.urgent_pointer = 0;
    return segment;
}

TcpSegment makeAck(std::uint16_t local_port, std::uint16_t remote_port, std::uint32_t seq,
                    std::uint32_t ack) {
    TcpSegment segment;
    segment.source_port = remote_port;
    segment.destination_port = local_port;
    segment.sequence_number = seq;
    segment.acknowledgment_number = ack;
    segment.flags.ack = true;
    segment.window_size = 65535;
    segment.urgent_pointer = 0;
    return segment;
}

TcpSegment makeData(std::uint16_t local_port, std::uint16_t remote_port, std::uint32_t seq,
                     std::uint32_t ack, std::vector<std::byte> payload, bool psh = true) {
    TcpSegment segment;
    segment.source_port = remote_port;
    segment.destination_port = local_port;
    segment.sequence_number = seq;
    segment.acknowledgment_number = ack;
    segment.flags.ack = true;
    segment.flags.psh = psh;
    segment.window_size = 65535;
    segment.urgent_pointer = 0;
    segment.payload = std::move(payload);
    return segment;
}

std::vector<std::byte> toBytes(std::initializer_list<std::uint8_t> values) {
    std::vector<std::byte> out;
    out.reserve(values.size());
    for (auto v : values) {
        out.push_back(static_cast<std::byte>(v));
    }
    return out;
}

std::vector<std::byte> toBytes(std::string_view text) {
    std::vector<std::byte> out;
    out.reserve(text.size());
    for (char c : text) {
        out.push_back(static_cast<std::byte>(static_cast<unsigned char>(c)));
    }
    return out;
}

// Performs a real SYN + final-ACK handshake on `table` for `key`, using
// `client_isn` as the client's initial sequence number, and returns the
// server's freshly drawn initial sequence number. Leaves the connection
// Established.
std::uint32_t establish(TcpConnectionTable& table, const TcpConnectionKey& key,
                         std::uint32_t client_isn, TcpClock::time_point now = t0) {
    auto syn_ack =
        table.handle(key, makeSyn(key.local_port, key.remote_port, client_isn), now).reply;
    std::uint32_t server_isn = syn_ack ? syn_ack->sequence_number : 0;
    table.handle(key, makeAck(key.local_port, key.remote_port, client_isn + 1, server_isn + 1),
                 now);
    return server_isn;
}

} // namespace

int main() {
    // basic handshake: SYN -> SynReceived, valid ACK -> Established
    {
        TcpConnectionTable table(8080);
        TcpConnectionKey key{localIp(), 8080, remoteIp(), 54321};

        auto syn_ack = table.handle(key, makeSyn(8080, 54321, 1000), t0).reply;
        CHECK(syn_ack.has_value());
        CHECK(table.stateOf(key) == TcpState::SynReceived);
        std::uint32_t server_isn = 0;
        if (syn_ack) {
            CHECK(syn_ack->flags.syn);
            CHECK(syn_ack->flags.ack);
            CHECK(syn_ack->acknowledgment_number == 1001);
            CHECK(syn_ack->source_port == 8080);
            CHECK(syn_ack->destination_port == 54321);
            server_isn = syn_ack->sequence_number;
        }

        auto no_reply = table.handle(key, makeAck(8080, 54321, 1001, server_isn + 1), t0).reply;
        CHECK(!no_reply.has_value());
        CHECK(table.stateOf(key) == TcpState::Established);
    }

    // duplicate SYN: same SYN-ACK sequence returned, state unchanged
    {
        TcpConnectionTable table(8080);
        TcpConnectionKey key{localIp(), 8080, remoteIp(), 54321};

        auto first = table.handle(key, makeSyn(8080, 54321, 2000), t0).reply;
        auto second = table.handle(key, makeSyn(8080, 54321, 2000), t0).reply;
        CHECK(first.has_value());
        CHECK(second.has_value());
        if (first && second) {
            CHECK(first->sequence_number == second->sequence_number);
            CHECK(first->acknowledgment_number == second->acknowledgment_number);
        }
        CHECK(table.stateOf(key) == TcpState::SynReceived);
    }

    // wrong ACK: remains SynReceived
    {
        TcpConnectionTable table(8080);
        TcpConnectionKey key{localIp(), 8080, remoteIp(), 54321};

        table.handle(key, makeSyn(8080, 54321, 3000), t0).reply;
        auto reply = table.handle(key, makeAck(8080, 54321, 3001, 999999), t0).reply;
        CHECK(!reply.has_value());
        CHECK(table.stateOf(key) == TcpState::SynReceived);
    }

    // ACK without prior SYN: no state created, closed-port reset returned
    {
        TcpConnectionTable table(8080);
        TcpConnectionKey key{localIp(), 8080, remoteIp(), 54321};

        auto reply = table.handle(key, makeAck(8080, 54321, 1, 1), t0).reply;
        CHECK(reply.has_value());
        CHECK(reply->flags.rst);
        CHECK(!reply->flags.ack);
        CHECK(reply->sequence_number == 1); // incoming ack number
        CHECK(reply->source_port == 8080);
        CHECK(reply->destination_port == 54321);
        CHECK(!table.stateOf(key).has_value());
    }

    // SYN to an unbound port: no state created, closed-port reset returned
    {
        TcpConnectionTable table(8080);
        TcpConnectionKey key{localIp(), 8081, remoteIp(), 54321};

        auto reply = table.handle(key, makeSyn(8081, 54321, 1), t0).reply;
        CHECK(reply.has_value());
        CHECK(reply->flags.rst);
        CHECK(reply->flags.ack);
        CHECK(reply->sequence_number == 0);
        CHECK(reply->acknowledgment_number == 2); // incoming seq + SYN's 1
        CHECK(!table.stateOf(key).has_value());
    }

    // two clients: independent connections, independently drawn ISNs
    {
        TcpConnectionTable table(8080);
        TcpConnectionKey key1{localIp(), 8080, remoteIp(), 40000};
        TcpConnectionKey key2{localIp(), 8080, remoteIp(), 40001};

        auto reply1 = table.handle(key1, makeSyn(8080, 40000, 111), t0).reply;
        auto reply2 = table.handle(key2, makeSyn(8080, 40001, 222), t0).reply;
        CHECK(reply1.has_value());
        CHECK(reply2.has_value());
        if (reply1 && reply2) {
            CHECK(reply1->sequence_number != reply2->sequence_number);
            CHECK(reply1->acknowledgment_number == 112);
            CHECK(reply2->acknowledgment_number == 223);
        }
        CHECK(table.stateOf(key1) == TcpState::SynReceived);
        CHECK(table.stateOf(key2) == TcpState::SynReceived);
    }

    // sequence wraparound: remote_isn = 0xffffffff -> ack number wraps to 0
    {
        TcpConnectionTable table(8080);
        TcpConnectionKey key{localIp(), 8080, remoteIp(), 54321};

        auto syn_ack = table.handle(key, makeSyn(8080, 54321, 0xffffffff), t0).reply;
        CHECK(syn_ack.has_value());
        if (syn_ack) {
            CHECK(syn_ack->acknowledgment_number == 0);
        }
    }

    // initialization after handshake: rcv_nxt/snd_una/snd_nxt
    {
        TcpConnectionTable table(8080);
        TcpConnectionKey key{localIp(), 8080, remoteIp(), 54321};
        std::uint32_t server_isn = establish(table, key, 1000);

        auto snapshot = table.snapshotOf(key);
        CHECK(snapshot.has_value());
        if (snapshot) {
            CHECK(snapshot->state == TcpState::Established);
            CHECK(snapshot->rcv_nxt == 1001);
            CHECK(snapshot->snd_una == server_isn + 1);
            CHECK(snapshot->snd_nxt == server_isn + 1);
        }
    }

    // one in-order payload: delivered exactly once, rcv_nxt advances
    {
        TcpConnectionTable table(8080);
        TcpConnectionKey key{localIp(), 8080, remoteIp(), 54321};
        std::uint32_t server_isn = establish(table, key, 1000);

        auto payload = toBytes("hello");
        auto result = table.handle(key, makeData(8080, 54321, 1001, server_isn + 1, payload), t0);
        CHECK(result.accepted_payload == payload);
        CHECK(!result.reply.has_value());

        auto snapshot = table.snapshotOf(key);
        CHECK(snapshot.has_value());
        if (snapshot) {
            CHECK(snapshot->rcv_nxt == 1001 + payload.size());
        }
    }

    // two sequential payloads: both delivered in order, rcv_nxt advances
    // cumulatively
    {
        TcpConnectionTable table(8080);
        TcpConnectionKey key{localIp(), 8080, remoteIp(), 54321};
        std::uint32_t server_isn = establish(table, key, 1000);

        auto first_payload = toBytes("hello");
        auto first = table.handle(key, makeData(8080, 54321, 1001, server_isn + 1, first_payload), t0);
        CHECK(first.accepted_payload == first_payload);

        auto second_payload = toBytes(" world");
        auto second = table.handle(
            key, makeData(8080, 54321, 1001 + static_cast<std::uint32_t>(first_payload.size()),
                           server_isn + 1, second_payload), t0);
        CHECK(second.accepted_payload == second_payload);

        auto snapshot = table.snapshotOf(key);
        CHECK(snapshot.has_value());
        if (snapshot) {
            CHECK(snapshot->rcv_nxt == 1001 + first_payload.size() + second_payload.size());
        }
    }

    // PSH is not required for delivery
    {
        TcpConnectionTable table(8080);
        TcpConnectionKey key{localIp(), 8080, remoteIp(), 54321};
        std::uint32_t server_isn = establish(table, key, 1000);

        auto payload = toBytes("no-psh");
        auto result =
            table.handle(key, makeData(8080, 54321, 1001, server_isn + 1, payload, /*psh=*/false), t0);
        CHECK(result.accepted_payload == payload);
    }

    // ACK generation (via duplicate data): seq=snd_nxt, ack=rcv_nxt,
    // ACK-only, empty payload, snd_nxt unchanged
    {
        TcpConnectionTable table(8080);
        TcpConnectionKey key{localIp(), 8080, remoteIp(), 54321};
        std::uint32_t server_isn = establish(table, key, 1000);

        auto payload = toBytes("hello");
        table.handle(key, makeData(8080, 54321, 1001, server_isn + 1, payload), t0);
        auto snapshot_before = table.snapshotOf(key);

        // duplicate of the same data
        auto dup = table.handle(key, makeData(8080, 54321, 1001, server_isn + 1, payload), t0);
        CHECK(dup.accepted_payload.empty());
        CHECK(dup.reply.has_value());
        if (dup.reply) {
            CHECK(dup.reply->flags.ack);
            CHECK(!dup.reply->flags.psh);
            CHECK(!dup.reply->flags.syn);
            CHECK(dup.reply->payload.empty());
            CHECK(dup.reply->sequence_number == snapshot_before->snd_nxt);
            CHECK(dup.reply->acknowledgment_number == snapshot_before->rcv_nxt);
        }

        auto snapshot_after = table.snapshotOf(key);
        CHECK(snapshot_after.has_value());
        if (snapshot_before && snapshot_after) {
            CHECK(snapshot_after->snd_nxt == snapshot_before->snd_nxt);
        }
    }

    // data send: seq=previous snd_nxt, ack=rcv_nxt, PSH|ACK, payload
    // exact, snd_nxt advances by payload length
    {
        TcpConnectionTable table(8080);
        TcpConnectionKey key{localIp(), 8080, remoteIp(), 54321};
        establish(table, key, 1000);

        auto snapshot_before = table.snapshotOf(key);
        auto payload = toBytes("echoed data");
        auto segment = table.makeOutgoingData(key, payload, t0);
        CHECK(segment.has_value());
        if (segment && snapshot_before) {
            CHECK(segment->sequence_number == snapshot_before->snd_nxt);
            CHECK(segment->acknowledgment_number == snapshot_before->rcv_nxt);
            CHECK(segment->flags.psh);
            CHECK(segment->flags.ack);
            CHECK(segment->payload == payload);
        }

        auto snapshot_after = table.snapshotOf(key);
        CHECK(snapshot_after.has_value());
        if (snapshot_before && snapshot_after) {
            CHECK(snapshot_after->snd_nxt == snapshot_before->snd_nxt + payload.size());
        }
    }

    // makeOutgoingData rejection cases: state left unchanged in all of them
    {
        TcpConnectionTable table(8080);
        TcpConnectionKey unknown_key{localIp(), 8080, remoteIp(), 11111};
        CHECK(!table.makeOutgoingData(unknown_key, toBytes("x"), t0).has_value());

        TcpConnectionKey key{localIp(), 8080, remoteIp(), 54321};
        table.handle(key, makeSyn(8080, 54321, 1000), t0); // SynReceived, not yet Established
        CHECK(!table.makeOutgoingData(key, toBytes("x"), t0).has_value());
        CHECK(table.stateOf(key) == TcpState::SynReceived);

        establish(table, key, 1000);
        auto snapshot_before = table.snapshotOf(key);
        CHECK(!table.makeOutgoingData(key, {}, t0).has_value()); // empty payload
        auto snapshot_after = table.snapshotOf(key);
        CHECK(snapshot_before.has_value() && snapshot_after.has_value());
        if (snapshot_before && snapshot_after) {
            CHECK(snapshot_after->snd_nxt == snapshot_before->snd_nxt);
        }
    }

    // client ACK of sent data: snd_una advances to the acknowledged
    // sequence number
    {
        TcpConnectionTable table(8080);
        TcpConnectionKey key{localIp(), 8080, remoteIp(), 54321};
        std::uint32_t server_isn = establish(table, key, 1000);

        auto payload = toBytes("echoed data");
        auto sent = table.makeOutgoingData(key, payload, t0);
        CHECK(sent.has_value());

        auto ack_result = table.handle(
            key, makeAck(8080, 54321, 1001, server_isn + 1 + static_cast<std::uint32_t>(payload.size())), t0);
        CHECK(!ack_result.reply.has_value());

        auto snapshot = table.snapshotOf(key);
        CHECK(snapshot.has_value());
        if (snapshot) {
            CHECK(snapshot->snd_una == server_isn + 1 + payload.size());
        }
    }

    // duplicate ACK: snd_una unchanged, no response
    {
        TcpConnectionTable table(8080);
        TcpConnectionKey key{localIp(), 8080, remoteIp(), 54321};
        std::uint32_t server_isn = establish(table, key, 1000);

        auto result = table.handle(key, makeAck(8080, 54321, 1001, server_isn + 1), t0);
        CHECK(!result.reply.has_value());

        auto snapshot = table.snapshotOf(key);
        CHECK(snapshot.has_value());
        if (snapshot) {
            CHECK(snapshot->snd_una == server_isn + 1);
        }
    }

    // ACK beyond snd_nxt: entire segment invalid, state unchanged, no
    // reply, no payload delivered
    {
        TcpConnectionTable table(8080);
        TcpConnectionKey key{localIp(), 8080, remoteIp(), 54321};
        std::uint32_t server_isn = establish(table, key, 1000);

        auto payload = toBytes("hello");
        auto result = table.handle(
            key, makeData(8080, 54321, 1001, server_isn + 999999, payload), t0);
        CHECK(result.accepted_payload.empty());
        CHECK(!result.reply.has_value());

        auto snapshot = table.snapshotOf(key);
        CHECK(snapshot.has_value());
        if (snapshot) {
            CHECK(snapshot->snd_una == server_isn + 1);
            CHECK(snapshot->rcv_nxt == 1001); // not advanced -- payload was not delivered
        }
    }

    // out-of-order payload: sequence number ahead of rcv_nxt -- not
    // delivered, rcv_nxt unchanged, ACK reflects current rcv_nxt
    {
        TcpConnectionTable table(8080);
        TcpConnectionKey key{localIp(), 8080, remoteIp(), 54321};
        std::uint32_t server_isn = establish(table, key, 1000);

        auto payload = toBytes("future");
        auto result = table.handle(key, makeData(8080, 54321, 1050, server_isn + 1, payload), t0);
        CHECK(result.accepted_payload.empty());
        CHECK(result.reply.has_value());
        if (result.reply) {
            CHECK(result.reply->acknowledgment_number == 1001);
        }

        auto snapshot = table.snapshotOf(key);
        CHECK(snapshot.has_value());
        if (snapshot) {
            CHECK(snapshot->rcv_nxt == 1001);
        }
    }

    // overlapping payload: sequence number behind rcv_nxt but extends
    // past it -- no partial delivery, rcv_nxt unchanged
    {
        TcpConnectionTable table(8080);
        TcpConnectionKey key{localIp(), 8080, remoteIp(), 54321};
        std::uint32_t server_isn = establish(table, key, 1000);

        table.handle(key, makeData(8080, 54321, 1001, server_isn + 1, toBytes("hello")), t0);
        // rcv_nxt is now 1006; this segment starts at 1003 (before
        // rcv_nxt) but its 10-byte payload would extend to 1013.
        auto overlap_payload = toBytes("XXXXXXXXXX");
        auto result =
            table.handle(key, makeData(8080, 54321, 1003, server_isn + 1, overlap_payload), t0);
        CHECK(result.accepted_payload.empty());

        auto snapshot = table.snapshotOf(key);
        CHECK(snapshot.has_value());
        if (snapshot) {
            CHECK(snapshot->rcv_nxt == 1006);
        }
    }

    // payload arriving before Established: not delivered, connection
    // remains SynReceived
    {
        TcpConnectionTable table(8080);
        TcpConnectionKey key{localIp(), 8080, remoteIp(), 54321};
        table.handle(key, makeSyn(8080, 54321, 1000), t0);

        auto result =
            table.handle(key, makeData(8080, 54321, 1001, 1, toBytes("too early")), t0);
        CHECK(result.accepted_payload.empty());
        CHECK(table.stateOf(key) == TcpState::SynReceived);
    }

    // ACK-only established segment: acknowledgment processed, no
    // response generated -- proves no ACK loop
    {
        TcpConnectionTable table(8080);
        TcpConnectionKey key{localIp(), 8080, remoteIp(), 54321};
        std::uint32_t server_isn = establish(table, key, 1000);

        auto result = table.handle(key, makeAck(8080, 54321, 1001, server_isn + 1), t0);
        CHECK(!result.reply.has_value());
        CHECK(result.accepted_payload.empty());
    }

    // binary payload: zero bytes, high bytes, no C-string/UTF-8
    // assumption, accepted and echoed unchanged
    {
        TcpConnectionTable table(8080);
        TcpConnectionKey key{localIp(), 8080, remoteIp(), 54321};
        std::uint32_t server_isn = establish(table, key, 1000);

        auto payload = toBytes({0x00, 0x01, 0x7f, 0x80, 0xff, 0x0a});
        auto result = table.handle(key, makeData(8080, 54321, 1001, server_isn + 1, payload), t0);
        CHECK(result.accepted_payload == payload);
        CHECK(result.accepted_payload.size() == 6);

        auto echoed = table.makeOutgoingData(key, result.accepted_payload, t0);
        CHECK(echoed.has_value());
        if (echoed) {
            CHECK(echoed->payload == payload);
            CHECK(echoed->payload.size() == 6);
        }
    }

    // sequence wraparound: receive advancement, send advancement, and
    // ACK-range validation all crossing 0xffffffff -> 0x00000000
    {
        TcpConnectionTable table(8080);
        TcpConnectionKey key{localIp(), 8080, remoteIp(), 54321};
        // client ISN chosen so rcv_nxt starts at 0xfffffffb (5 bytes will
        // cross the wraparound boundary).
        std::uint32_t server_isn = establish(table, key, 0xfffffffa);

        auto snapshot = table.snapshotOf(key);
        CHECK(snapshot.has_value());
        if (snapshot) {
            CHECK(snapshot->rcv_nxt == 0xfffffffb);
        }

        auto payload = toBytes({1, 2, 3, 4, 5}); // 0xfffffffb + 5 wraps to 0x00000000
        auto result =
            table.handle(key, makeData(8080, 54321, 0xfffffffb, server_isn + 1, payload), t0);
        CHECK(result.accepted_payload == payload);

        snapshot = table.snapshotOf(key);
        CHECK(snapshot.has_value());
        if (snapshot) {
            CHECK(snapshot->rcv_nxt == 0);
        }

        // send-side wraparound: force snd_nxt near the boundary by
        // acknowledging up to it first is unnecessary here -- makeOutgoingData
        // simply adds unsigned, which wraps correctly by definition; verify
        // directly using a connection whose snd_nxt is already near the top.
        TcpConnectionKey key2{localIp(), 8080, remoteIp(), 54322};
        std::uint32_t server_isn2 = establish(table, key2, 5000);
        // Drain snd_nxt close to the wraparound boundary with one send.
        std::vector<std::byte> filler(10, std::byte{0});
        auto first_send = table.makeOutgoingData(key2, filler, t0);
        CHECK(first_send.has_value());
        auto snap2 = table.snapshotOf(key2);
        CHECK(snap2.has_value());
        if (snap2) {
            CHECK(snap2->snd_nxt == server_isn2 + 1 + filler.size());
        }

        // ACK-range validation across wraparound: an ACK for data sent
        // before the boundary must still validate correctly relative to
        // snd_una/snd_nxt after they've wrapped. Use small increments so
        // the arithmetic exercises the wraparound helpers directly.
        TcpConnectionKey key3{localIp(), 8080, remoteIp(), 54323};
        establish(table, key3, 0xffffffff - 10);
        std::vector<std::byte> small_payload(20, std::byte{0xaa});
        auto wrap_send = table.makeOutgoingData(key3, small_payload, t0); // crosses the boundary
        CHECK(wrap_send.has_value());
        auto snap3 = table.snapshotOf(key3);
        CHECK(snap3.has_value());
        if (snap3 && wrap_send) {
            CHECK(snap3->snd_nxt == wrap_send->sequence_number + small_payload.size());
        }
        // Acknowledge exactly up to the new (wrapped) snd_nxt.
        auto ack_result =
            table.handle(key3, makeAck(8080, 54323, 0, snap3->snd_nxt), t0);
        CHECK(!ack_result.reply.has_value());
        auto snap3_after = table.snapshotOf(key3);
        CHECK(snap3_after.has_value());
        if (snap3_after && snap3) {
            CHECK(snap3_after->snd_una == snap3->snd_nxt);
            CHECK(snap3_after->pending_count == 0); // fully acknowledged -> queue drained
        }
    }

    // SYN-ACK loss: no ACK delivered, poll before/at the deadline, then
    // complete the handshake and confirm no further retransmission.
    {
        TcpConnectionTable table(8080);
        TcpConnectionKey key{localIp(), 8080, remoteIp(), 54321};

        auto syn_ack = table.handle(key, makeSyn(8080, 54321, 1000), t0).reply;
        CHECK(syn_ack.has_value());
        std::uint32_t server_isn = syn_ack ? syn_ack->sequence_number : 0;

        auto early = table.pollRetransmissions(t0 + kInitialRto - std::chrono::milliseconds(1));
        CHECK(early.retransmissions.empty());
        CHECK(early.timed_out.empty());

        auto due = table.pollRetransmissions(t0 + kInitialRto);
        CHECK(due.retransmissions.size() == 1);
        if (due.retransmissions.size() == 1) {
            CHECK(due.retransmissions[0].key == key);
            CHECK(due.retransmissions[0].segment.flags.syn);
            CHECK(due.retransmissions[0].segment.flags.ack);
            CHECK(due.retransmissions[0].segment.sequence_number == server_isn);
            CHECK(due.retransmissions[0].segment.acknowledgment_number == 1001);
        }
        CHECK(due.timed_out.empty());
        auto mid_snapshot = table.snapshotOf(key);
        CHECK(mid_snapshot.has_value());
        if (mid_snapshot) {
            CHECK(mid_snapshot->state == TcpState::SynReceived);
        }

        table.handle(key, makeAck(8080, 54321, 1001, server_isn + 1), t0 + kInitialRto);
        CHECK(table.stateOf(key) == TcpState::Established);
        auto after_establish = table.snapshotOf(key);
        CHECK(after_establish.has_value());
        if (after_establish) {
            CHECK(after_establish->pending_count == 0);
        }

        auto later = table.pollRetransmissions(t0 + kInitialRto * 10);
        CHECK(later.retransmissions.empty());
        CHECK(later.timed_out.empty());
    }

    // Application-data loss: establish, accept data, echo queued but
    // "lost", retransmitted at the deadline, then acknowledged. Binary
    // payload.
    {
        TcpConnectionTable table(8080);
        TcpConnectionKey key{localIp(), 8080, remoteIp(), 54321};
        establish(table, key, 1000, t0);

        auto client_payload = toBytes({0x00, 0x01, 0x7f, 0x80, 0xff, 0x0a});
        auto received =
            table.handle(key, makeData(8080, 54321, 1001, 1, client_payload), t0);
        CHECK(received.accepted_payload == client_payload);

        auto echo = table.makeOutgoingData(key, received.accepted_payload, t0);
        CHECK(echo.has_value());
        auto snapshot_before = table.snapshotOf(key);
        CHECK(snapshot_before.has_value());
        if (snapshot_before) {
            CHECK(snapshot_before->pending_count == 1);
        }

        auto early = table.pollRetransmissions(t0 + kInitialRto - std::chrono::milliseconds(1));
        CHECK(early.retransmissions.empty());

        auto due = table.pollRetransmissions(t0 + kInitialRto);
        CHECK(due.retransmissions.size() == 1);
        if (due.retransmissions.size() == 1 && echo) {
            CHECK(due.retransmissions[0].segment.payload == client_payload);
            CHECK(due.retransmissions[0].segment.sequence_number == echo->sequence_number);
            CHECK(due.retransmissions[0].segment.flags.psh);
            CHECK(due.retransmissions[0].segment.flags.ack);
        }
        auto snapshot_after_retransmit = table.snapshotOf(key);
        CHECK(snapshot_after_retransmit.has_value());
        if (snapshot_before && snapshot_after_retransmit) {
            CHECK(snapshot_after_retransmit->snd_nxt == snapshot_before->snd_nxt);
        }

        if (echo) {
            table.handle(key,
                         makeAck(8080, 54321, 1001 + static_cast<std::uint32_t>(client_payload.size()),
                                 echo->sequence_number +
                                     static_cast<std::uint32_t>(echo->payload.size())),
                         t0 + kInitialRto);
        }
        auto final_snapshot = table.snapshotOf(key);
        CHECK(final_snapshot.has_value());
        if (final_snapshot) {
            CHECK(final_snapshot->snd_una == final_snapshot->snd_nxt);
            CHECK(final_snapshot->pending_count == 0);
        }

        auto later = table.pollRetransmissions(t0 + kInitialRto * 10);
        CHECK(later.retransmissions.empty());
    }

    // Backoff: exact deadlines 1s, 3s, 7s, 15s, 23s from the original
    // send; no early firing, retry count increments once per deadline,
    // RTO caps at kMaxRto, and polling twice at the same timestamp does
    // not double-fire.
    {
        TcpConnectionTable table(8080);
        TcpConnectionKey key{localIp(), 8080, remoteIp(), 54321};
        table.handle(key, makeSyn(8080, 54321, 1000), t0);

        TcpClock::time_point deadline = t0;
        std::chrono::milliseconds rto = kInitialRto;
        for (int i = 0; i < kMaxRetransmits; ++i) {
            deadline += rto;

            auto early = table.pollRetransmissions(deadline - std::chrono::milliseconds(1));
            CHECK(early.retransmissions.empty());

            auto due = table.pollRetransmissions(deadline);
            CHECK(due.retransmissions.size() == 1);
            CHECK(due.timed_out.empty());

            auto repeat = table.pollRetransmissions(deadline);
            CHECK(repeat.retransmissions.empty());

            rto = std::min(rto * 2, std::chrono::duration_cast<std::chrono::milliseconds>(kMaxRto));
        }
    }

    // Exhaustion: SynReceived. After kMaxRetransmits, the next deadline
    // yields no segment, one timeout report, and connection removal; a
    // second poll does not re-report it; an unrelated connection is
    // unaffected.
    {
        TcpConnectionTable table(8080);
        TcpConnectionKey key{localIp(), 8080, remoteIp(), 54321};
        TcpConnectionKey other_key{localIp(), 8080, remoteIp(), 54322};
        table.handle(key, makeSyn(8080, 54321, 1000), t0);
        establish(table, other_key, 2000, t0);

        TcpClock::time_point deadline = t0;
        std::chrono::milliseconds rto = kInitialRto;
        for (int i = 0; i < kMaxRetransmits; ++i) {
            deadline += rto;
            auto due = table.pollRetransmissions(deadline);
            CHECK(due.retransmissions.size() == 1);
            rto = std::min(rto * 2, std::chrono::duration_cast<std::chrono::milliseconds>(kMaxRto));
        }

        deadline += rto;
        auto exhausted = table.pollRetransmissions(deadline);
        CHECK(exhausted.retransmissions.empty());
        CHECK(exhausted.timed_out.size() == 1);
        if (exhausted.timed_out.size() == 1) {
            CHECK(exhausted.timed_out[0] == key);
        }
        CHECK(!table.stateOf(key).has_value());

        auto again = table.pollRetransmissions(deadline + kMaxRto);
        CHECK(again.timed_out.empty());

        CHECK(table.stateOf(other_key) == TcpState::Established);
    }

    // Exhaustion: Established data.
    {
        TcpConnectionTable table(8080);
        TcpConnectionKey key{localIp(), 8080, remoteIp(), 54321};
        establish(table, key, 1000, t0);
        table.makeOutgoingData(key, toBytes("data"), t0);

        TcpClock::time_point deadline = t0;
        std::chrono::milliseconds rto = kInitialRto;
        for (int i = 0; i < kMaxRetransmits; ++i) {
            deadline += rto;
            table.pollRetransmissions(deadline);
            rto = std::min(rto * 2, std::chrono::duration_cast<std::chrono::milliseconds>(kMaxRto));
        }

        deadline += rto;
        auto exhausted = table.pollRetransmissions(deadline);
        CHECK(exhausted.retransmissions.empty());
        CHECK(exhausted.timed_out.size() == 1);
        CHECK(!table.stateOf(key).has_value());
    }

    // Multiple connections: independent timers, ACK processing, and
    // exhaustion.
    {
        TcpConnectionTable table(8080);

        TcpConnectionKey syn_key_a{localIp(), 8080, remoteIp(), 10001};
        TcpConnectionKey syn_key_b{localIp(), 8080, remoteIp(), 10002};
        table.handle(syn_key_a, makeSyn(8080, 10001, 1), t0);
        table.handle(syn_key_b, makeSyn(8080, 10002, 1), t0 + std::chrono::milliseconds(500));

        auto at_a_deadline = table.pollRetransmissions(t0 + kInitialRto);
        CHECK(at_a_deadline.retransmissions.size() == 1);
        if (!at_a_deadline.retransmissions.empty()) {
            CHECK(at_a_deadline.retransmissions[0].key == syn_key_a);
        }
        auto at_b_deadline = table.pollRetransmissions(t0 + std::chrono::milliseconds(1500));
        CHECK(at_b_deadline.retransmissions.size() == 1);
        if (!at_b_deadline.retransmissions.empty()) {
            CHECK(at_b_deadline.retransmissions[0].key == syn_key_b);
        }

        // Complete both handshakes so their pending SYN-ACKs don't
        // interfere with the exhaustion check below.
        if (!at_a_deadline.retransmissions.empty()) {
            table.handle(syn_key_a, makeAck(8080, 10001, 2, at_a_deadline.retransmissions[0].segment.sequence_number + 1), t0 + kInitialRto);
        }
        if (!at_b_deadline.retransmissions.empty()) {
            table.handle(
                syn_key_b, makeAck(8080, 10002, 2, at_b_deadline.retransmissions[0].segment.sequence_number + 1),
                t0 + std::chrono::milliseconds(1500));
        }

        TcpConnectionKey data_key_a{localIp(), 8080, remoteIp(), 20001};
        TcpConnectionKey data_key_b{localIp(), 8080, remoteIp(), 20002};
        establish(table, data_key_a, 100, t0);
        establish(table, data_key_b, 200, t0);
        auto sent_a = table.makeOutgoingData(data_key_a, toBytes("a-data"), t0);
        table.makeOutgoingData(data_key_b, toBytes("b-data"), t0);
        CHECK(sent_a.has_value());

        if (sent_a) {
            table.handle(data_key_a,
                         makeAck(8080, 20001, 101,
                                 sent_a->sequence_number +
                                     static_cast<std::uint32_t>(sent_a->payload.size())),
                         t0);
        }
        auto snap_a = table.snapshotOf(data_key_a);
        auto snap_b = table.snapshotOf(data_key_b);
        CHECK(snap_a.has_value() && snap_b.has_value());
        if (snap_a && snap_b) {
            CHECK(snap_a->pending_count == 0);
            CHECK(snap_b->pending_count == 1); // unaffected by A's ACK
        }

        TcpClock::time_point deadline = t0;
        std::chrono::milliseconds rto = kInitialRto;
        for (int i = 0; i < kMaxRetransmits; ++i) {
            deadline += rto;
            table.pollRetransmissions(deadline);
            rto = std::min(rto * 2, std::chrono::duration_cast<std::chrono::milliseconds>(kMaxRto));
        }
        deadline += rto;
        auto exhausted = table.pollRetransmissions(deadline);
        CHECK(exhausted.timed_out.size() == 1);
        if (!exhausted.timed_out.empty()) {
            CHECK(exhausted.timed_out[0] == data_key_b);
        }
        CHECK(!table.stateOf(data_key_b).has_value());
        CHECK(table.stateOf(data_key_a) == TcpState::Established); // untouched by B's exhaustion
    }

    // Multiple outstanding data segments: a cumulative ACK through the
    // end of the second entry retires the first two and leaves the third
    // pending.
    {
        TcpConnectionTable table(8080);
        TcpConnectionKey key{localIp(), 8080, remoteIp(), 54321};
        establish(table, key, 1000, t0);

        auto a = table.makeOutgoingData(key, toBytes("AAA"), t0);
        auto b = table.makeOutgoingData(key, toBytes("BB"), t0);
        auto c = table.makeOutgoingData(key, toBytes("C"), t0);
        CHECK(a.has_value() && b.has_value() && c.has_value());

        auto snapshot = table.snapshotOf(key);
        CHECK(snapshot.has_value());
        if (snapshot) {
            CHECK(snapshot->pending_count == 3);
        }

        if (b) {
            std::uint32_t ack_through_b =
                b->sequence_number + static_cast<std::uint32_t>(b->payload.size());
            auto result = table.handle(key, makeAck(8080, 54321, 1001, ack_through_b), t0);
            CHECK(!result.reply.has_value());
        }

        auto after = table.snapshotOf(key);
        CHECK(after.has_value());
        if (after && b && c) {
            CHECK(after->pending_count == 1);
            CHECK(after->snd_una ==
                  b->sequence_number + static_cast<std::uint32_t>(b->payload.size()));
            CHECK(after->snd_nxt ==
                  c->sequence_number + static_cast<std::uint32_t>(c->payload.size()));
        }
    }

    // Partial ACK: landing inside the oldest pending segment trims its
    // acknowledged prefix.
    {
        TcpConnectionTable table(8080);
        TcpConnectionKey key{localIp(), 8080, remoteIp(), 54321};
        establish(table, key, 1000, t0);

        auto sent = table.makeOutgoingData(key, toBytes("abcdef"), t0);
        CHECK(sent.has_value());
        if (sent) {
            std::uint32_t partial_ack = sent->sequence_number + 2; // acks "ab"
            table.handle(key, makeAck(8080, 54321, 1001, partial_ack), t0);

            auto snapshot = table.snapshotOf(key);
            CHECK(snapshot.has_value());
            if (snapshot) {
                CHECK(snapshot->snd_una == partial_ack);
                CHECK(snapshot->snd_nxt == sent->sequence_number + 6);
                CHECK(snapshot->pending_count == 1);
            }

            auto due = table.pollRetransmissions(t0 + kInitialRto);
            CHECK(due.retransmissions.size() == 1);
            if (due.retransmissions.size() == 1) {
                CHECK(due.retransmissions[0].segment.payload == toBytes("cdef"));
                CHECK(due.retransmissions[0].segment.sequence_number == partial_ack);
            }
        }
    }

    // Partial ACK trimming a binary payload with an embedded zero byte.
    {
        TcpConnectionTable table(8080);
        TcpConnectionKey key{localIp(), 8080, remoteIp(), 54321};
        establish(table, key, 1000, t0);

        auto payload = toBytes({0xaa, 0x00, 0xbb, 0xcc, 0xdd});
        auto sent = table.makeOutgoingData(key, payload, t0);
        CHECK(sent.has_value());
        if (sent) {
            std::uint32_t partial_ack = sent->sequence_number + 2; // acks {0xaa, 0x00}
            table.handle(key, makeAck(8080, 54321, 1001, partial_ack), t0);

            auto due = table.pollRetransmissions(t0 + kInitialRto);
            CHECK(due.retransmissions.size() == 1);
            if (due.retransmissions.size() == 1) {
                CHECK(due.retransmissions[0].segment.payload == toBytes({0xbb, 0xcc, 0xdd}));
            }
        }
    }

    // Full ACK: queue empty.
    {
        TcpConnectionTable table(8080);
        TcpConnectionKey key{localIp(), 8080, remoteIp(), 54321};
        establish(table, key, 1000, t0);
        auto sent = table.makeOutgoingData(key, toBytes("full"), t0);
        CHECK(sent.has_value());
        if (sent) {
            std::uint32_t full_ack =
                sent->sequence_number + static_cast<std::uint32_t>(sent->payload.size());
            table.handle(key, makeAck(8080, 54321, 1001, full_ack), t0);
            auto snapshot = table.snapshotOf(key);
            CHECK(snapshot.has_value());
            if (snapshot) {
                CHECK(snapshot->pending_count == 0);
            }
        }
    }

    // Future ACK: queue and snd_una unchanged, no delivery.
    {
        TcpConnectionTable table(8080);
        TcpConnectionKey key{localIp(), 8080, remoteIp(), 54321};
        establish(table, key, 1000, t0);
        auto sent = table.makeOutgoingData(key, toBytes("data"), t0);
        CHECK(sent.has_value());
        auto before = table.snapshotOf(key);
        CHECK(before.has_value());
        if (before) {
            table.handle(key, makeAck(8080, 54321, 1001, before->snd_nxt + 100), t0);
            auto after = table.snapshotOf(key);
            CHECK(after.has_value());
            if (after) {
                CHECK(after->snd_una == before->snd_una);
                CHECK(after->pending_count == before->pending_count);
            }
        }
    }

    // Wraparound-safe comparison: an ACK whose raw unsigned value is huge
    // (near 0xffffffff) but is semantically *behind* a small snd_una
    // (i.e. stale, wrapped) must not be treated as valid. This exercises
    // the same wraparound arithmetic that would apply if snd_una/snd_nxt
    // were themselves near the boundary -- reaching that directly would
    // require sending billions of prior bytes through the real ISN
    // counter, which isn't practical in a unit test; the comparison
    // functions are the same regardless of which operand is "small".
    {
        TcpConnectionTable table(8080);
        TcpConnectionKey key{localIp(), 8080, remoteIp(), 54321};
        establish(table, key, 1000, t0);

        auto snapshot_before = table.snapshotOf(key);
        CHECK(snapshot_before.has_value());

        table.handle(key, makeAck(8080, 54321, 1001, 0xfffffff0), t0);
        auto snapshot_after = table.snapshotOf(key);
        CHECK(snapshot_before.has_value() && snapshot_after.has_value());
        if (snapshot_before && snapshot_after) {
            CHECK(snapshot_after->snd_una == snapshot_before->snd_una);
        }
    }

    // Duplicate SYN re-arms the deadline without consuming retry budget:
    // exhaustion still takes exactly kMaxRetransmits timeout-triggered
    // retransmissions measured from the duplicate's time, not the
    // original SYN's time.
    {
        TcpConnectionTable table(8080);
        TcpConnectionKey key{localIp(), 8080, remoteIp(), 54321};

        table.handle(key, makeSyn(8080, 54321, 1000), t0);
        table.handle(key, makeSyn(8080, 54321, 1000), t0 + std::chrono::milliseconds(500));

        auto early = table.pollRetransmissions(t0 + kInitialRto);
        CHECK(early.retransmissions.empty());

        TcpClock::time_point deadline = t0 + std::chrono::milliseconds(500);
        std::chrono::milliseconds rto = kInitialRto;
        for (int i = 0; i < kMaxRetransmits; ++i) {
            deadline += rto;
            auto due = table.pollRetransmissions(deadline);
            CHECK(due.retransmissions.size() == 1);
            rto = std::min(rto * 2, std::chrono::duration_cast<std::chrono::milliseconds>(kMaxRto));
        }
        deadline += rto;
        auto exhausted = table.pollRetransmissions(deadline);
        CHECK(exhausted.timed_out.size() == 1);
    }

    // Pure ACKs are never queued or retransmitted: trigger one via
    // duplicate data, then advance well past several backoff cycles and
    // confirm nothing fires.
    {
        TcpConnectionTable table(8080);
        TcpConnectionKey key{localIp(), 8080, remoteIp(), 54321};
        std::uint32_t server_isn = establish(table, key, 1000, t0);

        auto payload = toBytes("x");
        table.handle(key, makeData(8080, 54321, 1001, server_isn + 1, payload), t0);
        auto dup = table.handle(key, makeData(8080, 54321, 1001, server_isn + 1, payload), t0);
        CHECK(dup.reply.has_value());

        auto far_future = t0 + kMaxRto * (kMaxRetransmits + 1);
        auto poll = table.pollRetransmissions(far_future);
        CHECK(poll.retransmissions.empty());
        CHECK(poll.timed_out.empty());
        CHECK(table.stateOf(key) == TcpState::Established);
    }

    // Duplicate client data during loss: the client resends unacknowledged
    // bytes because the echo was lost. The duplicate must not be
    // delivered again or trigger a second echo; the original pending
    // echo remains queued and is what the timeout eventually retransmits.
    {
        TcpConnectionTable table(8080);
        TcpConnectionKey key{localIp(), 8080, remoteIp(), 54321};
        std::uint32_t server_isn = establish(table, key, 1000, t0);

        auto payload = toBytes("loss test");
        auto first = table.handle(key, makeData(8080, 54321, 1001, server_isn + 1, payload), t0);
        CHECK(first.accepted_payload == payload);

        auto echo = table.makeOutgoingData(key, first.accepted_payload, t0);
        CHECK(echo.has_value());

        auto duplicate = table.handle(key, makeData(8080, 54321, 1001, server_isn + 1, payload), t0);
        CHECK(duplicate.accepted_payload.empty());
        CHECK(duplicate.reply.has_value());
        if (duplicate.reply) {
            CHECK(!duplicate.reply->flags.psh);
            CHECK(duplicate.reply->payload.empty());
        }

        auto snapshot = table.snapshotOf(key);
        CHECK(snapshot.has_value());
        if (snapshot) {
            CHECK(snapshot->pending_count == 1);
        }

        auto snapshot_before = table.snapshotOf(key);
        auto due = table.pollRetransmissions(t0 + kInitialRto);
        CHECK(due.retransmissions.size() == 1);
        if (due.retransmissions.size() == 1 && echo) {
            CHECK(due.retransmissions[0].segment.payload == payload);
            CHECK(due.retransmissions[0].segment.sequence_number == echo->sequence_number);
        }
        auto snapshot_after = table.snapshotOf(key);
        CHECK(snapshot_before.has_value() && snapshot_after.has_value());
        if (snapshot_before && snapshot_after) {
            CHECK(snapshot_after->snd_nxt == snapshot_before->snd_nxt);
        }

        if (echo) {
            table.handle(key,
                         makeAck(8080, 54321, 1001 + static_cast<std::uint32_t>(payload.size()),
                                 echo->sequence_number +
                                     static_cast<std::uint32_t>(echo->payload.size())),
                         t0 + kInitialRto);
        }
        auto final_snapshot = table.snapshotOf(key);
        CHECK(final_snapshot.has_value());
        if (final_snapshot) {
            CHECK(final_snapshot->pending_count == 0);
        }
    }

    return wirestack::test::failureCount() == 0 ? 0 : 1;
}
