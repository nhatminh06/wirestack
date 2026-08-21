#include "wirestack/tcp_connection.hpp"

#include "test_util.hpp"

using wirestack::Ipv4Address;
using wirestack::kInitialRto;
using wirestack::kInitialPersistInterval;
using wirestack::kInitialSsthresh;
using wirestack::kMaxApplicationSendSize;
using wirestack::kMaxCongestionWindow;
using wirestack::kMaxRetransmits;
using wirestack::kMaxPersistInterval;
using wirestack::kMaxReassemblyFragments;
using wirestack::kMaxRto;
using wirestack::kMaxSegmentsPerSend;
using wirestack::kMinRto;
using wirestack::kTcpMss;
using wirestack::kTcpReceiveCapacity;
using wirestack::kTcpSendBufferCapacity;
using wirestack::kTimeWaitDuration;
using wirestack::parseTcpSegment;
using wirestack::serializeTcpSegment;
using wirestack::TcpClock;
using wirestack::TcpConnectionKey;
using wirestack::TcpConnectionTable;
using wirestack::TcpSegment;
using wirestack::TcpSendError;
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

// Carries an MSS=1460 option by default, matching a well-behaved peer --
// this keeps every pre-Milestone-11 test's effective_send_mss at 1460
// exactly as before option negotiation existed, with zero assertion
// changes. Tests that specifically exercise negotiation (other peer MSS
// values, Window Scale, malformed options) use makeSynWithOptions below.
TcpSegment makeSyn(std::uint16_t local_port, std::uint16_t remote_port, std::uint32_t seq) {
    TcpSegment segment;
    segment.source_port = remote_port;
    segment.destination_port = local_port;
    segment.sequence_number = seq;
    segment.acknowledgment_number = 0;
    segment.flags.syn = true;
    segment.window_size = 65535;
    segment.urgent_pointer = 0;
    segment.options = {std::byte{2}, std::byte{4}, std::byte{0x05}, std::byte{0xb4}};
    return segment;
}

// Same as makeSyn, but with explicit raw option bytes -- for tests that
// need a specific peer MSS, Window Scale, no options at all, or a
// malformed options blob.
TcpSegment makeSynWithOptions(std::uint16_t local_port, std::uint16_t remote_port,
                               std::uint32_t seq, std::vector<std::byte> options) {
    TcpSegment segment = makeSyn(local_port, remote_port, seq);
    segment.options = std::move(options);
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

TcpSegment makeFin(std::uint16_t local_port, std::uint16_t remote_port, std::uint32_t seq,
                    std::uint32_t ack, std::vector<std::byte> payload = {}) {
    TcpSegment segment;
    segment.source_port = remote_port;
    segment.destination_port = local_port;
    segment.sequence_number = seq;
    segment.acknowledgment_number = ack;
    segment.flags.ack = true;
    segment.flags.fin = true;
    segment.window_size = 65535;
    segment.urgent_pointer = 0;
    segment.payload = std::move(payload);
    return segment;
}

TcpSegment makeRst(std::uint16_t local_port, std::uint16_t remote_port, std::uint32_t seq) {
    TcpSegment segment;
    segment.source_port = remote_port;
    segment.destination_port = local_port;
    segment.sequence_number = seq;
    segment.flags.rst = true;
    segment.window_size = 65535;
    segment.urgent_pointer = 0;
    return segment;
}

// An ACK-only segment that advertises an explicit window, for tests that
// need to control the peer's advertised send window directly (makeAck
// always advertises the fixed 65535 used elsewhere).
TcpSegment makeWindowUpdate(std::uint16_t local_port, std::uint16_t remote_port,
                             std::uint32_t seq, std::uint32_t ack, std::uint16_t window) {
    TcpSegment segment;
    segment.source_port = remote_port;
    segment.destination_port = local_port;
    segment.sequence_number = seq;
    segment.acknowledgment_number = ack;
    segment.flags.ack = true;
    segment.window_size = window;
    segment.urgent_pointer = 0;
    return segment;
}

std::vector<std::byte> makeFilledPayload(std::size_t length, std::byte value = std::byte{'x'}) {
    return std::vector<std::byte>(length, value);
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

// Same as establish(), but the handshake-completing ACK advertises
// `window` instead of the fixed 65535 makeAck() always uses -- needed for
// send-window tests that must control the peer's advertised window from
// the start.
std::uint32_t establishWithWindow(TcpConnectionTable& table, const TcpConnectionKey& key,
                                   std::uint32_t client_isn, std::uint16_t window,
                                   TcpClock::time_point now = t0) {
    auto syn_ack =
        table.handle(key, makeSyn(key.local_port, key.remote_port, client_isn), now).reply;
    std::uint32_t server_isn = syn_ack ? syn_ack->sequence_number : 0;
    table.handle(key,
                 makeWindowUpdate(key.local_port, key.remote_port, client_isn + 1,
                                  server_isn + 1, window),
                 now);
    return server_isn;
}

// Negotiates Window Scale (MSS=1460 + Window Scale=`peer_scale` on the
// SYN) and completes the handshake, leaving the connection Established
// with window_scaling_enabled/local_window_scale set.
std::uint32_t establishWithWindowScale(TcpConnectionTable& table, const TcpConnectionKey& key,
                                        std::uint32_t client_isn, std::uint8_t peer_scale,
                                        TcpClock::time_point now = t0) {
    std::vector<std::byte> options = {std::byte{2}, std::byte{4}, std::byte{0x05}, std::byte{0xb4},
                                       std::byte{1}, std::byte{3}, std::byte{3},
                                       static_cast<std::byte>(peer_scale)};
    auto syn_ack = table
                       .handle(key,
                               makeSynWithOptions(key.local_port, key.remote_port, client_isn,
                                                   options),
                               now)
                       .reply;
    std::uint32_t server_isn = syn_ack ? syn_ack->sequence_number : 0;
    table.handle(key, makeAck(key.local_port, key.remote_port, client_isn + 1, server_isn + 1),
                 now);
    return server_isn;
}

// Negotiates the given peer MSS (or none, if `peer_mss` is nullopt) and
// completes the handshake.
std::uint32_t establishWithPeerMss(TcpConnectionTable& table, const TcpConnectionKey& key,
                                    std::uint32_t client_isn, std::optional<std::uint16_t> peer_mss,
                                    TcpClock::time_point now = t0) {
    std::vector<std::byte> options;
    if (peer_mss) {
        options = {std::byte{2}, std::byte{4}, static_cast<std::byte>((*peer_mss >> 8) & 0xff),
                    static_cast<std::byte>(*peer_mss & 0xff)};
    }
    auto syn_ack = table
                       .handle(key,
                               makeSynWithOptions(key.local_port, key.remote_port, client_isn,
                                                   options),
                               now)
                       .reply;
    std::uint32_t server_isn = syn_ack ? syn_ack->sequence_number : 0;
    table.handle(key, makeAck(key.local_port, key.remote_port, client_isn + 1, server_isn + 1),
                 now);
    return server_isn;
}

// SYN carrying MSS + SACK-Permitted (in that order, matching
// buildSynAckOptions' fixed layout), and completes the handshake.
std::uint32_t establishWithSack(TcpConnectionTable& table, const TcpConnectionKey& key,
                                 std::uint32_t client_isn, TcpClock::time_point now = t0) {
    std::vector<std::byte> options = {std::byte{2}, std::byte{4}, std::byte{0x05}, std::byte{0xb4},
                                       std::byte{4}, std::byte{2}};
    auto syn_ack = table
                       .handle(key,
                               makeSynWithOptions(key.local_port, key.remote_port, client_isn,
                                                   options),
                               now)
                       .reply;
    std::uint32_t server_isn = syn_ack ? syn_ack->sequence_number : 0;
    table.handle(key, makeAck(key.local_port, key.remote_port, client_isn + 1, server_isn + 1),
                 now);
    return server_isn;
}

void appendUint32(std::vector<std::byte>& out, std::uint32_t value) {
    out.push_back(static_cast<std::byte>((value >> 24) & 0xff));
    out.push_back(static_cast<std::byte>((value >> 16) & 0xff));
    out.push_back(static_cast<std::byte>((value >> 8) & 0xff));
    out.push_back(static_cast<std::byte>(value & 0xff));
}

// An ACK carrying a SACK option built from `blocks` (left/right sequence
// number pairs), zero-padded to a 4-byte boundary like the real encoder.
TcpSegment makeAckWithSack(std::uint16_t local_port, std::uint16_t remote_port, std::uint32_t seq,
                            std::uint32_t ack,
                            const std::vector<std::pair<std::uint32_t, std::uint32_t>>& blocks) {
    TcpSegment segment = makeAck(local_port, remote_port, seq, ack);
    if (blocks.empty()) {
        return segment;
    }
    std::vector<std::byte> options;
    options.push_back(std::byte{5});
    options.push_back(static_cast<std::byte>(2 + 8 * blocks.size()));
    for (auto [left, right] : blocks) {
        appendUint32(options, left);
        appendUint32(options, right);
    }
    while (options.size() % 4 != 0) {
        options.push_back(std::byte{0});
    }
    segment.options = std::move(options);
    return segment;
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
        auto sent = table.makeOutgoingData(key, payload, t0);
        CHECK(!sent.segments.empty());
        if (!sent.segments.empty() && snapshot_before) {
            const auto& segment = sent.segments.front();
            CHECK(segment.sequence_number == snapshot_before->snd_nxt);
            CHECK(segment.acknowledgment_number == snapshot_before->rcv_nxt);
            CHECK(segment.flags.psh);
            CHECK(segment.flags.ack);
            CHECK(segment.payload == payload);
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
        CHECK(table.makeOutgoingData(unknown_key, toBytes("x"), t0).segments.empty());

        TcpConnectionKey key{localIp(), 8080, remoteIp(), 54321};
        table.handle(key, makeSyn(8080, 54321, 1000), t0); // SynReceived, not yet Established
        CHECK(table.makeOutgoingData(key, toBytes("x"), t0).segments.empty());
        CHECK(table.stateOf(key) == TcpState::SynReceived);

        establish(table, key, 1000);
        auto snapshot_before = table.snapshotOf(key);
        CHECK(table.makeOutgoingData(key, {}, t0).segments.empty()); // empty payload
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
        CHECK(!sent.segments.empty());

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
    // past it -- the already-delivered prefix is trimmed and discarded,
    // and the new suffix (starting exactly at rcv_nxt) is delivered
    // immediately since nothing precedes it. Milestone 10 replaces the
    // earlier whole-segment overlap rejection with this prefix-trimming
    // policy (see docs/tcp.md).
    {
        TcpConnectionTable table(8080);
        TcpConnectionKey key{localIp(), 8080, remoteIp(), 54321};
        std::uint32_t server_isn = establish(table, key, 1000);

        table.handle(key, makeData(8080, 54321, 1001, server_isn + 1, toBytes("hello")), t0);
        // rcv_nxt is now 1006; this segment starts at 1003 (before
        // rcv_nxt) but its 10-byte payload extends to 1013 -- bytes
        // 1003..1005 are already-delivered duplicates (trimmed away),
        // bytes 1006..1012 are new and delivered.
        auto overlap_payload = toBytes("XXXXXXXXXX");
        auto result =
            table.handle(key, makeData(8080, 54321, 1003, server_isn + 1, overlap_payload), t0);
        CHECK(result.accepted_payload == toBytes("XXXXXXX")); // 7 trailing bytes, prefix trimmed

        auto snapshot = table.snapshotOf(key);
        CHECK(snapshot.has_value());
        if (snapshot) {
            CHECK(snapshot->rcv_nxt == 1013);
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
        CHECK(!echoed.segments.empty());
        if (!echoed.segments.empty()) {
            CHECK(echoed.segments.front().payload == payload);
            CHECK(echoed.segments.front().payload.size() == 6);
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
        CHECK(!first_send.segments.empty());
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
        CHECK(!wrap_send.segments.empty());
        auto snap3 = table.snapshotOf(key3);
        CHECK(snap3.has_value());
        if (snap3 && !wrap_send.segments.empty()) {
            CHECK(snap3->snd_nxt == wrap_send.segments.front().sequence_number + small_payload.size());
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
        CHECK(!echo.segments.empty());
        auto snapshot_before = table.snapshotOf(key);
        CHECK(snapshot_before.has_value());
        if (snapshot_before) {
            CHECK(snapshot_before->pending_count == 1);
        }

        auto early = table.pollRetransmissions(t0 + kInitialRto - std::chrono::milliseconds(1));
        CHECK(early.retransmissions.empty());

        auto due = table.pollRetransmissions(t0 + kInitialRto);
        CHECK(due.retransmissions.size() == 1);
        if (due.retransmissions.size() == 1 && !echo.segments.empty()) {
            CHECK(due.retransmissions[0].segment.payload == client_payload);
            CHECK(due.retransmissions[0].segment.sequence_number ==
                  echo.segments.front().sequence_number);
            CHECK(due.retransmissions[0].segment.flags.psh);
            CHECK(due.retransmissions[0].segment.flags.ack);
        }
        auto snapshot_after_retransmit = table.snapshotOf(key);
        CHECK(snapshot_after_retransmit.has_value());
        if (snapshot_before && snapshot_after_retransmit) {
            CHECK(snapshot_after_retransmit->snd_nxt == snapshot_before->snd_nxt);
        }

        if (!echo.segments.empty()) {
            const auto& echo_segment = echo.segments.front();
            table.handle(key,
                         makeAck(8080, 54321, 1001 + static_cast<std::uint32_t>(client_payload.size()),
                                 echo_segment.sequence_number +
                                     static_cast<std::uint32_t>(echo_segment.payload.size())),
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
        CHECK(!sent_a.segments.empty());

        if (!sent_a.segments.empty()) {
            const auto& sent_a_segment = sent_a.segments.front();
            table.handle(data_key_a,
                         makeAck(8080, 20001, 101,
                                 sent_a_segment.sequence_number +
                                     static_cast<std::uint32_t>(sent_a_segment.payload.size())),
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
        CHECK(!a.segments.empty() && !b.segments.empty() && !c.segments.empty());

        auto snapshot = table.snapshotOf(key);
        CHECK(snapshot.has_value());
        if (snapshot) {
            CHECK(snapshot->pending_count == 3);
        }

        if (!b.segments.empty()) {
            const auto& b_segment = b.segments.front();
            std::uint32_t ack_through_b =
                b_segment.sequence_number + static_cast<std::uint32_t>(b_segment.payload.size());
            auto result = table.handle(key, makeAck(8080, 54321, 1001, ack_through_b), t0);
            CHECK(!result.reply.has_value());
        }

        auto after = table.snapshotOf(key);
        CHECK(after.has_value());
        if (after && !b.segments.empty() && !c.segments.empty()) {
            const auto& b_segment = b.segments.front();
            const auto& c_segment = c.segments.front();
            CHECK(after->pending_count == 1);
            CHECK(after->snd_una ==
                  b_segment.sequence_number + static_cast<std::uint32_t>(b_segment.payload.size()));
            CHECK(after->snd_nxt ==
                  c_segment.sequence_number + static_cast<std::uint32_t>(c_segment.payload.size()));
        }
    }

    // Partial ACK: landing inside the oldest pending segment trims its
    // acknowledged prefix.
    {
        TcpConnectionTable table(8080);
        TcpConnectionKey key{localIp(), 8080, remoteIp(), 54321};
        establish(table, key, 1000, t0);

        auto sent = table.makeOutgoingData(key, toBytes("abcdef"), t0);
        CHECK(!sent.segments.empty());
        if (!sent.segments.empty()) {
            const auto& sent_segment = sent.segments.front();
            std::uint32_t partial_ack = sent_segment.sequence_number + 2; // acks "ab"
            table.handle(key, makeAck(8080, 54321, 1001, partial_ack), t0);

            auto snapshot = table.snapshotOf(key);
            CHECK(snapshot.has_value());
            if (snapshot) {
                CHECK(snapshot->snd_una == partial_ack);
                CHECK(snapshot->snd_nxt == sent_segment.sequence_number + 6);
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
        CHECK(!sent.segments.empty());
        if (!sent.segments.empty()) {
            std::uint32_t partial_ack = sent.segments.front().sequence_number + 2; // acks {0xaa, 0x00}
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
        CHECK(!sent.segments.empty());
        if (!sent.segments.empty()) {
            const auto& sent_segment = sent.segments.front();
            std::uint32_t full_ack =
                sent_segment.sequence_number + static_cast<std::uint32_t>(sent_segment.payload.size());
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
        CHECK(!sent.segments.empty());
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
        CHECK(!echo.segments.empty());

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
        if (due.retransmissions.size() == 1 && !echo.segments.empty()) {
            CHECK(due.retransmissions[0].segment.payload == payload);
            CHECK(due.retransmissions[0].segment.sequence_number ==
                  echo.segments.front().sequence_number);
        }
        auto snapshot_after = table.snapshotOf(key);
        CHECK(snapshot_before.has_value() && snapshot_after.has_value());
        if (snapshot_before && snapshot_after) {
            CHECK(snapshot_after->snd_nxt == snapshot_before->snd_nxt);
        }

        if (!echo.segments.empty()) {
            const auto& echo_segment = echo.segments.front();
            table.handle(key,
                         makeAck(8080, 54321, 1001 + static_cast<std::uint32_t>(payload.size()),
                                 echo_segment.sequence_number +
                                     static_cast<std::uint32_t>(echo_segment.payload.size())),
                         t0 + kInitialRto);
        }
        auto final_snapshot = table.snapshotOf(key);
        CHECK(final_snapshot.has_value());
        if (final_snapshot) {
            CHECK(final_snapshot->pending_count == 0);
        }
    }

    // --- FIN accounting ---

    // peer FIN advances rcv_nxt by exactly one
    {
        TcpConnectionTable table(8080);
        TcpConnectionKey key{localIp(), 8080, remoteIp(), 54321};
        std::uint32_t server_isn = establish(table, key, 1000);

        auto before = table.snapshotOf(key);
        auto result = table.handle(key, makeFin(8080, 54321, 1001, server_isn + 1), t0);
        auto after = table.snapshotOf(key);
        CHECK(before.has_value() && after.has_value());
        if (before && after) {
            CHECK(after->rcv_nxt == before->rcv_nxt + 1);
        }
        CHECK(result.peer_closed);
        CHECK(table.stateOf(key) == TcpState::CloseWait);
    }

    // outgoing FIN advances snd_nxt by exactly one
    {
        TcpConnectionTable table(8080);
        TcpConnectionKey key{localIp(), 8080, remoteIp(), 54321};
        establish(table, key, 1000);

        auto before = table.snapshotOf(key);
        auto fin_result = table.beginClose(key, t0);
        auto fin = fin_result.fin;
        auto after = table.snapshotOf(key);
        CHECK(fin.has_value());
        CHECK(before.has_value() && after.has_value());
        if (fin) {
            CHECK(fin->flags.fin);
            CHECK(fin->flags.ack);
            CHECK(fin->payload.empty());
        }
        if (before && after) {
            CHECK(after->snd_nxt == before->snd_nxt + 1);
        }
    }

    // FIN retransmission does not advance snd_nxt again
    {
        TcpConnectionTable table(8080);
        TcpConnectionKey key{localIp(), 8080, remoteIp(), 54321};
        establish(table, key, 1000);

        auto fin_result = table.beginClose(key, t0);
        auto fin = fin_result.fin;
        auto before = table.snapshotOf(key);
        auto due = table.pollRetransmissions(t0 + kInitialRto);
        auto after = table.snapshotOf(key);
        CHECK(due.retransmissions.size() == 1);
        if (due.retransmissions.size() == 1 && fin) {
            CHECK(due.retransmissions[0].segment.sequence_number == fin->sequence_number);
            CHECK(due.retransmissions[0].segment.flags.fin);
        }
        CHECK(before.has_value() && after.has_value());
        if (before && after) {
            CHECK(after->snd_nxt == before->snd_nxt);
        }
    }

    // FIN wraparound: rcv_nxt wraps from 0xffffffff to 0. local_isn is
    // drawn from a small internal counter, so a send-side snd_nxt near
    // the wrap point cannot be reached directly through the public API;
    // client_isn, however, is caller-supplied, so the wraparound is
    // exercised on the receive side instead -- the same 32-bit unsigned
    // arithmetic governs both directions.
    {
        TcpConnectionTable table(8080);
        TcpConnectionKey key{localIp(), 8080, remoteIp(), 54321};
        establish(table, key, 0xfffffffe);

        auto snapshot = table.snapshotOf(key);
        CHECK(snapshot.has_value());
        if (snapshot) {
            CHECK(snapshot->rcv_nxt == 0xffffffff);
        }

        auto result = table.handle(key, makeFin(8080, 54321, 0xffffffff, snapshot->snd_nxt), t0);
        CHECK(result.peer_closed);
        auto after = table.snapshotOf(key);
        CHECK(after.has_value());
        if (after) {
            CHECK(after->rcv_nxt == 0);
        }
    }

    // --- Peer close ---

    // Established -> CloseWait, EOF signaled exactly once, ACK uses
    // updated rcv_nxt, duplicate FIN does not re-signal EOF
    {
        TcpConnectionTable table(8080);
        TcpConnectionKey key{localIp(), 8080, remoteIp(), 54321};
        std::uint32_t server_isn = establish(table, key, 1000);

        auto result = table.handle(key, makeFin(8080, 54321, 1001, server_isn + 1), t0);
        CHECK(result.peer_closed);
        CHECK(table.stateOf(key) == TcpState::CloseWait);
        CHECK(result.reply.has_value());
        if (result.reply) {
            CHECK(result.reply->flags.ack);
            CHECK(!result.reply->flags.fin);
            CHECK(result.reply->acknowledgment_number == 1002);
        }

        auto duplicate = table.handle(key, makeFin(8080, 54321, 1001, server_isn + 1), t0);
        CHECK(!duplicate.peer_closed);
        CHECK(table.stateOf(key) == TcpState::CloseWait);
        CHECK(duplicate.reply.has_value()); // still ACKed, just not as new EOF
    }

    // --- FIN with payload ---

    // payload delivered exactly once, bytes preserved, both consume
    // sequence space, state becomes CloseWait
    {
        TcpConnectionTable table(8080);
        TcpConnectionKey key{localIp(), 8080, remoteIp(), 54321};
        std::uint32_t server_isn = establish(table, key, 1000);

        auto payload = toBytes("bye");
        auto before = table.snapshotOf(key);
        auto result =
            table.handle(key, makeFin(8080, 54321, 1001, server_isn + 1, payload), t0);
        auto after = table.snapshotOf(key);

        CHECK(result.accepted_payload == payload);
        CHECK(result.peer_closed);
        CHECK(!result.reply.has_value()); // redundant ACK avoided: echo will ACK it
        CHECK(table.stateOf(key) == TcpState::CloseWait);
        CHECK(before.has_value() && after.has_value());
        if (before && after) {
            CHECK(after->rcv_nxt ==
                  before->rcv_nxt + static_cast<std::uint32_t>(payload.size()) + 1);
        }
    }

    // invalid ACK on a FIN+payload segment: entire segment rejected
    {
        TcpConnectionTable table(8080);
        TcpConnectionKey key{localIp(), 8080, remoteIp(), 54321};
        std::uint32_t server_isn = establish(table, key, 1000);
        (void)server_isn;

        auto before = table.snapshotOf(key);
        auto result = table.handle(key, makeFin(8080, 54321, 1001, 999999999, toBytes("x")), t0);
        auto after = table.snapshotOf(key);

        CHECK(result.accepted_payload.empty());
        CHECK(!result.peer_closed);
        CHECK(table.stateOf(key) == TcpState::Established);
        CHECK(before.has_value() && after.has_value());
        if (before && after) {
            CHECK(after->rcv_nxt == before->rcv_nxt);
        }
    }

    // --- CloseWait send ---

    // application data allowed in CloseWait, queued, ACKed normally
    {
        TcpConnectionTable table(8080);
        TcpConnectionKey key{localIp(), 8080, remoteIp(), 54321};
        std::uint32_t server_isn = establish(table, key, 1000);
        table.handle(key, makeFin(8080, 54321, 1001, server_isn + 1), t0); // -> CloseWait

        auto payload = toBytes("still here");
        auto sent = table.makeOutgoingData(key, payload, t0);
        CHECK(!sent.segments.empty());
        auto snapshot = table.snapshotOf(key);
        CHECK(snapshot.has_value());
        if (snapshot) {
            CHECK(snapshot->pending_count == 1);
        }

        if (!sent.segments.empty()) {
            const auto& sent_segment = sent.segments.front();
            table.handle(key,
                         makeAck(8080, 54321, 1002,
                                 sent_segment.sequence_number +
                                     static_cast<std::uint32_t>(sent_segment.payload.size())),
                         t0);
        }
        auto after = table.snapshotOf(key);
        CHECK(after.has_value());
        if (after) {
            CHECK(after->pending_count == 0);
        }
    }

    // --- Passive close ---

    // CloseWait -> LastAck, FIN queued, valid ACK removes the connection,
    // wrong ACK does not
    {
        TcpConnectionTable table(8080);
        TcpConnectionKey key{localIp(), 8080, remoteIp(), 54321};
        std::uint32_t server_isn = establish(table, key, 1000);
        table.handle(key, makeFin(8080, 54321, 1001, server_isn + 1), t0); // -> CloseWait

        auto fin_result = table.beginClose(key, t0);
        auto fin = fin_result.fin;
        CHECK(fin.has_value());
        CHECK(table.stateOf(key) == TcpState::LastAck);
        auto snapshot = table.snapshotOf(key);
        CHECK(snapshot.has_value());
        if (snapshot) {
            CHECK(snapshot->pending_count == 1);
        }

        if (fin) {
            // Wrong ACK: connection survives.
            auto wrong = table.handle(key, makeAck(8080, 54321, 1002, fin->sequence_number), t0);
            CHECK(table.stateOf(key).has_value());
            CHECK(table.stateOf(key) == TcpState::LastAck);
            (void)wrong;

            // Valid ACK of the FIN: connection removed, no reply, no event.
            auto final_ack =
                table.handle(key, makeAck(8080, 54321, 1002, fin->sequence_number + 1), t0);
            CHECK(!final_ack.reply.has_value());
            CHECK(final_ack.accepted_payload.empty());
            CHECK(!table.stateOf(key).has_value());
        }
    }

    // --- Active close ---

    // Established -> FinWait1 -> FinWait2 (ACK of local FIN) -> TimeWait
    // (peer FIN)
    {
        TcpConnectionTable table(8080);
        TcpConnectionKey key{localIp(), 8080, remoteIp(), 54321};
        std::uint32_t server_isn = establish(table, key, 1000);

        auto fin_result = table.beginClose(key, t0);
        auto fin = fin_result.fin;
        CHECK(fin.has_value());
        CHECK(table.stateOf(key) == TcpState::FinWait1);

        if (fin) {
            table.handle(key, makeAck(8080, 54321, 1001, fin->sequence_number + 1), t0);
            CHECK(table.stateOf(key) == TcpState::FinWait2);

            auto result =
                table.handle(key, makeFin(8080, 54321, 1001, fin->sequence_number + 1), t0);
            CHECK(result.peer_closed);
            CHECK(table.stateOf(key) == TcpState::TimeWait);
            CHECK(result.reply.has_value());
        }
        (void)server_isn;
    }

    // --- Simultaneous close ---

    // FinWait1 -- peer FIN not ACKing local FIN --> Closing --ACK--> TimeWait
    {
        TcpConnectionTable table(8080);
        TcpConnectionKey key{localIp(), 8080, remoteIp(), 54321};
        std::uint32_t server_isn = establish(table, key, 1000);
        (void)server_isn;

        auto fin_result = table.beginClose(key, t0);
        auto fin = fin_result.fin;
        CHECK(fin.has_value());
        CHECK(table.stateOf(key) == TcpState::FinWait1);

        if (fin) {
            // Peer's FIN arrives without acknowledging our FIN.
            auto result = table.handle(key, makeFin(8080, 54321, 1001, fin->sequence_number), t0);
            CHECK(result.peer_closed);
            CHECK(table.stateOf(key) == TcpState::Closing);

            table.handle(key, makeAck(8080, 54321, 1002, fin->sequence_number + 1), t0);
            CHECK(table.stateOf(key) == TcpState::TimeWait);
        }
    }

    // FinWait1 -- a single segment carrying both an acceptable FIN and a
    // valid ACK of the local FIN --> TimeWait directly
    {
        TcpConnectionTable table(8080);
        TcpConnectionKey key{localIp(), 8080, remoteIp(), 54321};
        establish(table, key, 1000);

        auto fin_result = table.beginClose(key, t0);
        auto fin = fin_result.fin;
        CHECK(fin.has_value());
        CHECK(table.stateOf(key) == TcpState::FinWait1);

        if (fin) {
            auto result = table.handle(
                key, makeFin(8080, 54321, 1001, fin->sequence_number + 1), t0);
            CHECK(result.peer_closed);
            CHECK(table.stateOf(key) == TcpState::TimeWait);
        }
    }

    // --- TIME_WAIT ---

    // no expiration before 60s, expiration exactly at the deadline
    {
        TcpConnectionTable table(8080);
        TcpConnectionKey key{localIp(), 8080, remoteIp(), 54321};
        establish(table, key, 1000);
        auto fin_result = table.beginClose(key, t0);
        auto fin = fin_result.fin;
        CHECK(fin.has_value());
        if (fin) {
            table.handle(key, makeAck(8080, 54321, 1001, fin->sequence_number + 1), t0);
            table.handle(key, makeFin(8080, 54321, 1001, fin->sequence_number + 1), t0);
        }
        CHECK(table.stateOf(key) == TcpState::TimeWait);

        auto too_early = table.pollRetransmissions(t0 + kTimeWaitDuration - std::chrono::milliseconds(1));
        CHECK(too_early.time_wait_expired.empty());
        CHECK(table.stateOf(key).has_value());

        auto at_deadline = table.pollRetransmissions(t0 + kTimeWaitDuration);
        CHECK(at_deadline.time_wait_expired.size() == 1);
        CHECK(!table.stateOf(key).has_value());
    }

    // duplicate FIN in TimeWait restarts the deadline, sends the current
    // pure ACK, and is never queued
    {
        TcpConnectionTable table(8080);
        TcpConnectionKey key{localIp(), 8080, remoteIp(), 54321};
        establish(table, key, 1000);
        auto fin_result = table.beginClose(key, t0);
        auto fin = fin_result.fin;
        CHECK(fin.has_value());
        std::uint32_t local_fin_seq = fin ? fin->sequence_number : 0;
        if (fin) {
            table.handle(key, makeAck(8080, 54321, 1001, local_fin_seq + 1), t0);
            table.handle(key, makeFin(8080, 54321, 1001, local_fin_seq + 1), t0);
        }
        CHECK(table.stateOf(key) == TcpState::TimeWait);

        auto restart_time = t0 + kTimeWaitDuration - std::chrono::seconds(1);
        auto duplicate =
            table.handle(key, makeFin(8080, 54321, 1001, local_fin_seq + 1), restart_time);
        CHECK(!duplicate.peer_closed);
        CHECK(duplicate.reply.has_value());
        auto snapshot = table.snapshotOf(key);
        CHECK(snapshot.has_value());
        if (snapshot) {
            CHECK(snapshot->pending_count == 0);
        }

        // Original deadline (t0 + kTimeWaitDuration) has now passed, but
        // the restart pushed it to restart_time + kTimeWaitDuration.
        auto not_yet = table.pollRetransmissions(t0 + kTimeWaitDuration);
        CHECK(not_yet.time_wait_expired.empty());
        CHECK(table.stateOf(key).has_value());

        auto expired = table.pollRetransmissions(restart_time + kTimeWaitDuration);
        CHECK(expired.time_wait_expired.size() == 1);
    }

    // --- Inbound RST ---

    // valid RST removes a synchronized connection, no response, no
    // pending transmissions survive
    {
        TcpConnectionTable table(8080);
        TcpConnectionKey key{localIp(), 8080, remoteIp(), 54321};
        std::uint32_t server_isn = establish(table, key, 1000);
        table.makeOutgoingData(key, toBytes("data"), t0); // leaves a pending entry

        auto result = table.handle(key, makeRst(8080, 54321, 1001), t0);
        CHECK(result.connection_reset);
        CHECK(!result.reply.has_value());
        CHECK(!table.stateOf(key).has_value());

        auto due = table.pollRetransmissions(t0 + kMaxRto * kMaxRetransmits);
        CHECK(due.retransmissions.empty());
        (void)server_isn;
    }

    // invalid-sequence RST is ignored: connection survives unchanged
    {
        TcpConnectionTable table(8080);
        TcpConnectionKey key{localIp(), 8080, remoteIp(), 54321};
        establish(table, key, 1000);

        auto result = table.handle(key, makeRst(8080, 54321, 999999), t0);
        CHECK(!result.connection_reset);
        CHECK(!result.reply.has_value());
        CHECK(table.stateOf(key) == TcpState::Established);
    }

    // RST accepted during SynReceived only when it acknowledges the
    // outstanding SYN-ACK
    {
        TcpConnectionTable table(8080);
        TcpConnectionKey key{localIp(), 8080, remoteIp(), 54321};
        auto syn_ack = table.handle(key, makeSyn(8080, 54321, 5000), t0).reply;
        CHECK(syn_ack.has_value());

        auto wrong = table.handle(key, makeRst(8080, 54321, 1), t0);
        CHECK(!wrong.reply.has_value());
        CHECK(table.stateOf(key) == TcpState::SynReceived);

        auto accepted = table.handle(key, makeRst(8080, 54321, 5001), t0);
        CHECK(!accepted.reply.has_value());
        CHECK(!table.stateOf(key).has_value());
    }

    // an incoming RST for an unknown connection is silently ignored (no
    // response, no state created)
    {
        TcpConnectionTable table(8080);
        TcpConnectionKey key{localIp(), 8080, remoteIp(), 54321};

        auto result = table.handle(key, makeRst(8080, 54321, 1), t0);
        CHECK(!result.reply.has_value());
        CHECK(!table.stateOf(key).has_value());
    }

    // --- Closed-port RST: wraparound ---

    {
        TcpConnectionTable table(8080);
        TcpConnectionKey key{localIp(), 8080, remoteIp(), 54321};

        TcpSegment incoming;
        incoming.source_port = 54321;
        incoming.destination_port = 8080;
        incoming.sequence_number = 0xffffffff;
        incoming.payload = toBytes({1, 2, 3, 4});
        incoming.flags.ack = false;
        incoming.window_size = 65535;

        auto reply = table.handle(key, incoming, t0).reply;
        CHECK(reply.has_value());
        if (reply) {
            CHECK(reply->flags.rst);
            CHECK(reply->flags.ack);
            CHECK(reply->sequence_number == 0);
            CHECK(reply->acknowledgment_number == 3); // 0xffffffff + 4 wraps to 3
        }
        CHECK(!table.stateOf(key).has_value());
    }

    // --- FIN retransmission regression: backoff, ACK retirement, exhaustion ---

    // backoff sequence identical to data's: 1s, 2s, 4s, 8s, 16s. Under
    // the 60s cap (task rule 26, replacing the earlier 8s cap), five
    // retransmits of a 1s-starting entry never actually reach the cap.
    {
        TcpConnectionTable table(8080);
        TcpConnectionKey key{localIp(), 8080, remoteIp(), 54321};
        establish(table, key, 1000);
        auto fin_result = table.beginClose(key, t0);
        auto fin = fin_result.fin;
        CHECK(fin.has_value());

        auto t = t0;
        std::vector<TcpClock::duration> offsets = {kInitialRto, std::chrono::milliseconds(2000),
                                                     std::chrono::milliseconds(4000),
                                                     std::chrono::milliseconds(8000),
                                                     std::chrono::milliseconds(16000)};
        for (std::size_t i = 0; i < offsets.size(); ++i) {
            t += offsets[i];
            auto due = table.pollRetransmissions(t);
            CHECK(due.retransmissions.size() == 1);
            if (due.retransmissions.size() == 1 && fin) {
                CHECK(due.retransmissions[0].segment.sequence_number == fin->sequence_number);
                CHECK(due.retransmissions[0].segment.flags.fin);
            }
        }
    }

    // ACK retires the pending FIN; no further retransmission occurs
    {
        TcpConnectionTable table(8080);
        TcpConnectionKey key{localIp(), 8080, remoteIp(), 54321};
        establish(table, key, 1000);
        auto fin_result = table.beginClose(key, t0);
        auto fin = fin_result.fin;
        CHECK(fin.has_value());
        if (fin) {
            table.handle(key, makeAck(8080, 54321, 1001, fin->sequence_number + 1), t0);
        }
        auto snapshot = table.snapshotOf(key);
        CHECK(snapshot.has_value());
        if (snapshot) {
            CHECK(snapshot->pending_count == 0);
        }

        auto due = table.pollRetransmissions(t0 + kMaxRto * kMaxRetransmits);
        CHECK(due.retransmissions.empty());
    }

    // exhaustion removes the connection; a second, unrelated connection
    // is unaffected
    {
        TcpConnectionTable table(8080);
        TcpConnectionKey key_a{localIp(), 8080, remoteIp(), 11111};
        TcpConnectionKey key_b{localIp(), 8080, remoteIp(), 22222};
        establish(table, key_a, 1000);
        establish(table, key_b, 2000);

        auto fin_a_result = table.beginClose(key_a, t0);
        auto fin_a = fin_a_result.fin;
        CHECK(fin_a.has_value());

        auto t = t0;
        std::vector<TcpClock::duration> offsets = {kInitialRto, std::chrono::milliseconds(2000),
                                                     std::chrono::milliseconds(4000),
                                                     std::chrono::milliseconds(8000),
                                                     std::chrono::milliseconds(16000)};
        for (auto offset : offsets) {
            t += offset;
            table.pollRetransmissions(t);
        }
        t += std::chrono::milliseconds(32000); // the 6th deadline, at the now-32s-backed-off timeout
        auto exhausted = table.pollRetransmissions(t);
        CHECK(exhausted.timed_out.size() == 1);
        if (exhausted.timed_out.size() == 1) {
            CHECK(exhausted.timed_out[0] == key_a);
        }
        CHECK(!table.stateOf(key_a).has_value());
        CHECK(table.stateOf(key_b) == TcpState::Established);
    }

    // ================= Milestone 10: segmentation =================

    // exact MSS: one segment
    {
        TcpConnectionTable table(8080);
        TcpConnectionKey key{localIp(), 8080, remoteIp(), 54321};
        establish(table, key, 1000);
        auto payload = makeFilledPayload(kTcpMss);
        auto sent = table.makeOutgoingData(key, payload, t0);
        CHECK(sent.segments.size() == 1);
        if (sent.segments.size() == 1) {
            CHECK(sent.segments[0].payload.size() == kTcpMss);
            CHECK(sent.segments[0].flags.psh);
            CHECK(sent.segments[0].flags.ack);
        }
        auto snapshot = table.snapshotOf(key);
        CHECK(snapshot.has_value());
        if (snapshot) CHECK(snapshot->pending_count == 1);
    }

    // MSS + 1: two segments, MSS then 1, PSH only on the final one
    {
        TcpConnectionTable table(8080);
        TcpConnectionKey key{localIp(), 8080, remoteIp(), 54321};
        auto server_isn = establish(table, key, 1000);
        auto payload = makeFilledPayload(kTcpMss + 1);
        auto sent = table.makeOutgoingData(key, payload, t0);
        CHECK(sent.segments.size() == 2);
        if (sent.segments.size() == 2) {
            CHECK(sent.segments[0].payload.size() == kTcpMss);
            CHECK(sent.segments[1].payload.size() == 1);
            CHECK(!sent.segments[0].flags.psh);
            CHECK(sent.segments[1].flags.psh);
            CHECK(sent.segments[0].flags.ack && sent.segments[1].flags.ack);
            CHECK(sent.segments[0].sequence_number == server_isn + 1);
            CHECK(sent.segments[1].sequence_number == server_isn + 1 + kTcpMss);
        }
        auto snapshot = table.snapshotOf(key);
        CHECK(snapshot.has_value());
        if (snapshot) {
            CHECK(snapshot->pending_count == 2);
            CHECK(snapshot->snd_nxt == server_isn + 1 + kTcpMss + 1);
        }
    }

    // multiple segments: 3*MSS + 17 bytes -> 4 segments, exact reconstruction
    {
        TcpConnectionTable table(8080);
        TcpConnectionKey key{localIp(), 8080, remoteIp(), 54321};
        auto server_isn = establish(table, key, 1000);
        std::size_t total = 3 * kTcpMss + 17;
        std::vector<std::byte> payload;
        payload.reserve(total);
        for (std::size_t i = 0; i < total; ++i) {
            payload.push_back(static_cast<std::byte>(i % 256));
        }
        auto sent = table.makeOutgoingData(key, payload, t0);
        CHECK(sent.segments.size() == 4);
        if (sent.segments.size() == 4) {
            CHECK(sent.segments[0].payload.size() == kTcpMss);
            CHECK(sent.segments[1].payload.size() == kTcpMss);
            CHECK(sent.segments[2].payload.size() == kTcpMss);
            CHECK(sent.segments[3].payload.size() == 17);
            for (std::size_t i = 0; i < 3; ++i) CHECK(!sent.segments[i].flags.psh);
            CHECK(sent.segments[3].flags.psh);

            std::uint32_t expected_seq = server_isn + 1;
            std::vector<std::byte> reconstructed;
            for (const auto& seg : sent.segments) {
                CHECK(seg.sequence_number == expected_seq);
                CHECK(seg.flags.ack);
                CHECK(seg.payload.size() <= kTcpMss);
                expected_seq += static_cast<std::uint32_t>(seg.payload.size());
                reconstructed.insert(reconstructed.end(), seg.payload.begin(), seg.payload.end());
            }
            CHECK(reconstructed == payload);
        }
        auto snapshot = table.snapshotOf(key);
        CHECK(snapshot.has_value());
        if (snapshot) {
            CHECK(snapshot->pending_count == 4);
            CHECK(snapshot->snd_nxt == server_isn + 1 + static_cast<std::uint32_t>(total));
        }
    }

    // no empty trailing segment for an exact multiple of MSS
    {
        TcpConnectionTable table(8080);
        TcpConnectionKey key{localIp(), 8080, remoteIp(), 54321};
        establish(table, key, 1000);
        auto payload = makeFilledPayload(2 * kTcpMss);
        auto sent = table.makeOutgoingData(key, payload, t0);
        CHECK(sent.segments.size() == 2);
        for (const auto& seg : sent.segments) CHECK(!seg.payload.empty());
    }

    // ================= Milestone 10: send window =================

    // payload exactly fills the available window
    {
        TcpConnectionTable table(8080);
        TcpConnectionKey key{localIp(), 8080, remoteIp(), 54321};
        establishWithWindow(table, key, 1000, 100);
        auto sent = table.makeOutgoingData(key, makeFilledPayload(100), t0);
        CHECK(sent.segments.size() == 1);
        CHECK(sent.bytes_accepted == 100);
    }

    // payload exceeds the window by one: enqueue accepts all of it, but
    // only the window's worth is scheduled immediately -- the remaining
    // byte stays queued in the send buffer.
    {
        TcpConnectionTable table(8080);
        TcpConnectionKey key{localIp(), 8080, remoteIp(), 54321};
        establishWithWindow(table, key, 1000, 100);
        auto before = table.snapshotOf(key);
        auto sent = table.makeOutgoingData(key, makeFilledPayload(101), t0);
        CHECK(!sent.error);
        CHECK(sent.bytes_accepted == 101);
        std::size_t sent_bytes = 0;
        for (const auto& seg : sent.segments) sent_bytes += seg.payload.size();
        CHECK(sent_bytes == 100);
        auto after = table.snapshotOf(key);
        CHECK(before.has_value() && after.has_value());
        if (before && after) {
            CHECK(after->snd_nxt == before->snd_nxt + 100);
            CHECK(after->unsent_bytes == 1);
        }
    }

    // zero window: enqueue still succeeds, but nothing is scheduled yet
    {
        TcpConnectionTable table(8080);
        TcpConnectionKey key{localIp(), 8080, remoteIp(), 54321};
        establishWithWindow(table, key, 1000, 0);
        auto sent = table.makeOutgoingData(key, toBytes("x"), t0);
        CHECK(!sent.error);
        CHECK(sent.segments.empty());
        CHECK(sent.bytes_accepted == 1);
        auto snapshot = table.snapshotOf(key);
        CHECK(snapshot.has_value());
        if (snapshot) CHECK(snapshot->unsent_bytes == 1);
    }

    // window below MSS: one smaller segment when the payload fits
    {
        TcpConnectionTable table(8080);
        TcpConnectionKey key{localIp(), 8080, remoteIp(), 54321};
        establishWithWindow(table, key, 1000, 50);
        auto sent = table.makeOutgoingData(key, makeFilledPayload(50), t0);
        CHECK(sent.segments.size() == 1);
        if (sent.segments.size() == 1) CHECK(sent.segments[0].payload.size() == 50);
    }

    // a larger window fits several MSS-sized segments
    {
        TcpConnectionTable table(8080);
        TcpConnectionKey key{localIp(), 8080, remoteIp(), 54321};
        establishWithWindow(table, key, 1000, 5000);
        auto sent = table.makeOutgoingData(key, makeFilledPayload(3000), t0);
        CHECK(sent.segments.size() == 3); // 1460 + 1460 + 80
    }

    // ACK opens additional window
    {
        TcpConnectionTable table(8080);
        TcpConnectionKey key{localIp(), 8080, remoteIp(), 54321};
        auto server_isn = establishWithWindow(table, key, 1000, 100);
        auto sent = table.makeOutgoingData(key, makeFilledPayload(100), t0);
        CHECK(!sent.segments.empty());

        auto blocked = table.makeOutgoingData(key, toBytes("x"), t0); // no window left
        CHECK(blocked.segments.empty());

        table.handle(key, makeWindowUpdate(8080, 54321, 1001, server_isn + 1 + 100, 200), t0);
        auto reopened = table.makeOutgoingData(key, makeFilledPayload(200), t0);
        CHECK(!reopened.segments.empty());
    }

    // a stale (earlier-sequence) window update cannot replace a newer one
    {
        TcpConnectionTable table(8080);
        TcpConnectionKey key{localIp(), 8080, remoteIp(), 54321};
        auto server_isn = establishWithWindow(table, key, 1000, 1000);
        table.handle(key, makeWindowUpdate(8080, 54321, 1001, server_isn + 1, 2000), t0);
        table.handle(key, makeWindowUpdate(8080, 54321, 1000, server_isn + 1, 10), t0); // stale
        auto snapshot = table.snapshotOf(key);
        CHECK(snapshot.has_value());
        if (snapshot) CHECK(snapshot->snd_wnd == 2000);
    }

    // retransmission of already-outstanding data remains possible during
    // a zero window
    {
        TcpConnectionTable table(8080);
        TcpConnectionKey key{localIp(), 8080, remoteIp(), 54321};
        auto server_isn = establishWithWindow(table, key, 1000, 100);
        auto sent = table.makeOutgoingData(key, makeFilledPayload(100), t0);
        CHECK(!sent.segments.empty());
        table.handle(key, makeWindowUpdate(8080, 54321, 1001, server_isn + 1, 0), t0);
        CHECK(table.makeOutgoingData(key, toBytes("x"), t0).segments.empty());

        auto due = table.pollRetransmissions(t0 + kInitialRto);
        CHECK(due.retransmissions.size() == 1);
        if (due.retransmissions.size() == 1) {
            CHECK(due.retransmissions[0].segment.payload.size() == 100);
        }
    }

    // FIN deferred without one byte of window; the close intent is
    // retained and the window-reopening ACK schedules the FIN
    // automatically (no second beginClose call needed).
    {
        TcpConnectionTable table(8080);
        TcpConnectionKey key{localIp(), 8080, remoteIp(), 54321};
        auto server_isn = establishWithWindow(table, key, 1000, 0);
        auto close_result = table.beginClose(key, t0);
        CHECK(close_result.accepted);
        CHECK(!close_result.fin.has_value());
        auto window_result =
            table.handle(key, makeWindowUpdate(8080, 54321, 1001, server_isn + 1, 10), t0);
        CHECK(!window_result.scheduled.empty());
        if (!window_result.scheduled.empty()) {
            CHECK(window_result.scheduled.back().flags.fin);
        }
    }

    // ================= Milestone 10: out-of-order reassembly =================

    // two segments in order: each delivered immediately, no buffering
    {
        TcpConnectionTable table(8080);
        TcpConnectionKey key{localIp(), 8080, remoteIp(), 54321};
        std::uint32_t server_isn = establish(table, key, 1000);
        auto r1 = table.handle(key, makeData(8080, 54321, 1001, server_isn + 1, toBytes("AAA")), t0);
        CHECK(r1.accepted_payload == toBytes("AAA"));
        auto r2 = table.handle(key, makeData(8080, 54321, 1004, server_isn + 1, toBytes("BBB")), t0);
        CHECK(r2.accepted_payload == toBytes("BBB"));
        auto snapshot = table.snapshotOf(key);
        CHECK(snapshot.has_value());
        if (snapshot) {
            CHECK(snapshot->rcv_nxt == 1007);
            CHECK(snapshot->reassembly_fragment_count == 0);
        }
    }

    // two segments in reverse order: the second arrival is buffered, not
    // delivered; the first arrival releases both concatenated in order
    {
        TcpConnectionTable table(8080);
        TcpConnectionKey key{localIp(), 8080, remoteIp(), 54321};
        std::uint32_t server_isn = establish(table, key, 1000);
        auto late = table.handle(key, makeData(8080, 54321, 1004, server_isn + 1, toBytes("BBB")), t0);
        CHECK(late.accepted_payload.empty());
        CHECK(late.reply.has_value());
        auto snapshot = table.snapshotOf(key);
        CHECK(snapshot.has_value());
        if (snapshot) {
            CHECK(snapshot->reassembly_fragment_count == 1);
            CHECK(snapshot->reassembly_buffered_bytes == 3);
            // Wire-clamped: this connection never negotiated Window
            // Scale, so the advertised window is pinned at 65535 as long
            // as the true available space (capacity - buffered, still
            // far above 65535 here) exceeds that clamp.
            CHECK(snapshot->advertised_window == 65535);
        }

        auto gap_fill = table.handle(key, makeData(8080, 54321, 1001, server_isn + 1, toBytes("AAA")), t0);
        CHECK(gap_fill.accepted_payload == toBytes("AAABBB"));
        auto after = table.snapshotOf(key);
        CHECK(after.has_value());
        if (after) {
            CHECK(after->rcv_nxt == 1007);
            CHECK(after->reassembly_fragment_count == 0);
            CHECK(after->advertised_window == 65535);
        }
    }

    // three segments in reverse order (C, B, A)
    {
        TcpConnectionTable table(8080);
        TcpConnectionKey key{localIp(), 8080, remoteIp(), 54321};
        std::uint32_t server_isn = establish(table, key, 1000);
        CHECK(table.handle(key, makeData(8080, 54321, 1007, server_isn + 1, toBytes("CCC")), t0)
                  .accepted_payload.empty());
        CHECK(table.handle(key, makeData(8080, 54321, 1004, server_isn + 1, toBytes("BBB")), t0)
                  .accepted_payload.empty());
        auto snapshot = table.snapshotOf(key);
        CHECK(snapshot.has_value());
        if (snapshot) CHECK(snapshot->reassembly_fragment_count == 1); // B and C coalesced

        auto released = table.handle(key, makeData(8080, 54321, 1001, server_isn + 1, toBytes("AAA")), t0);
        CHECK(released.accepted_payload == toBytes("AAABBBCCC"));
    }

    // gap in the middle: A then C buffered, B fills the gap
    {
        TcpConnectionTable table(8080);
        TcpConnectionKey key{localIp(), 8080, remoteIp(), 54321};
        std::uint32_t server_isn = establish(table, key, 1000);
        CHECK(table.handle(key, makeData(8080, 54321, 1001, server_isn + 1, toBytes("AAA")), t0)
                  .accepted_payload == toBytes("AAA"));
        CHECK(table.handle(key, makeData(8080, 54321, 1007, server_isn + 1, toBytes("CCC")), t0)
                  .accepted_payload.empty());
        auto released = table.handle(key, makeData(8080, 54321, 1004, server_isn + 1, toBytes("BBB")), t0);
        CHECK(released.accepted_payload == toBytes("BBBCCC"));
    }

    // duplicate segment: no re-delivery, no fragment growth
    {
        TcpConnectionTable table(8080);
        TcpConnectionKey key{localIp(), 8080, remoteIp(), 54321};
        std::uint32_t server_isn = establish(table, key, 1000);
        table.handle(key, makeData(8080, 54321, 1004, server_isn + 1, toBytes("BBB")), t0);
        auto before = table.snapshotOf(key);
        auto dup = table.handle(key, makeData(8080, 54321, 1004, server_isn + 1, toBytes("BBB")), t0);
        CHECK(dup.accepted_payload.empty());
        auto after = table.snapshotOf(key);
        CHECK(before.has_value() && after.has_value());
        if (before && after) {
            CHECK(after->reassembly_fragment_count == before->reassembly_fragment_count);
            CHECK(after->reassembly_buffered_bytes == before->reassembly_buffered_bytes);
        }
    }

    // partial left overlap: new segment covers part of a buffered
    // fragment plus new bytes before it; existing bytes are kept
    {
        TcpConnectionTable table(8080);
        TcpConnectionKey key{localIp(), 8080, remoteIp(), 54321};
        std::uint32_t server_isn = establish(table, key, 1000);
        table.handle(key, makeData(8080, 54321, 1010, server_isn + 1, toBytes("XXXXXXXXXX")), t0); // 1010..1020
        // New segment 1005..1015 overlaps the front of the buffered
        // fragment; only 1005..1010 is genuinely new.
        table.handle(key, makeData(8080, 54321, 1005, server_isn + 1, toBytes("YYYYYYYYYY")), t0);
        auto snapshot = table.snapshotOf(key);
        CHECK(snapshot.has_value());
        if (snapshot) CHECK(snapshot->reassembly_buffered_bytes == 15); // 1005..1020

        auto released = table.handle(key, makeData(8080, 54321, 1001, server_isn + 1, toBytes("ZZZZ")), t0);
        // 1001..1005 new (Z), 1005..1010 new (Y), 1010..1020 first-arrival (X).
        CHECK(released.accepted_payload == toBytes("ZZZZYYYYYXXXXXXXXXX"));
    }

    // partial right overlap: new segment covers the tail of a buffered
    // fragment plus new bytes after it
    {
        TcpConnectionTable table(8080);
        TcpConnectionKey key{localIp(), 8080, remoteIp(), 54321};
        std::uint32_t server_isn = establish(table, key, 1000);
        table.handle(key, makeData(8080, 54321, 1010, server_isn + 1, toBytes("XXXXXXXXXX")), t0); // 1010..1020
        table.handle(key, makeData(8080, 54321, 1015, server_isn + 1, toBytes("YYYYYYYYYY")), t0); // 1015..1025
        auto snapshot = table.snapshotOf(key);
        CHECK(snapshot.has_value());
        if (snapshot) CHECK(snapshot->reassembly_buffered_bytes == 15); // 1010..1025

        auto released = table.handle(key, makeData(8080, 54321, 1001, server_isn + 1, toBytes("ZZZZZZZZZ")), t0);
        CHECK(released.accepted_payload == toBytes("ZZZZZZZZZXXXXXXXXXXYYYYY"));
    }

    // one new segment covering two buffered fragments (fills both gaps
    // around them and merges everything on release)
    {
        TcpConnectionTable table(8080);
        TcpConnectionKey key{localIp(), 8080, remoteIp(), 54321};
        std::uint32_t server_isn = establish(table, key, 1000);
        table.handle(key, makeData(8080, 54321, 1010, server_isn + 1, toBytes("11111")), t0); // 1010..1015
        table.handle(key, makeData(8080, 54321, 1020, server_isn + 1, toBytes("22222")), t0); // 1020..1025
        auto covering =
            table.handle(key, makeData(8080, 54321, 1005, server_isn + 1, makeFilledPayload(25, std::byte{'0'})), t0);
        // 1005..1030 -- covers both existing fragments; only the gaps
        // (1005..1010 and 1015..1020) plus the tail (1025..1030) are new.
        CHECK(covering.accepted_payload.empty()); // still gapped at rcv_nxt (1001..1005 missing)
        auto snapshot = table.snapshotOf(key);
        CHECK(snapshot.has_value());
        if (snapshot) CHECK(snapshot->reassembly_buffered_bytes == 25); // 1005..1030, one fragment

        auto released = table.handle(key, makeData(8080, 54321, 1001, server_isn + 1, toBytes("ABCD")), t0);
        CHECK(released.accepted_payload ==
              toBytes("ABCD0000011111000002222200000")); // 1001..1030 fully contiguous
    }

    // conflicting overlap: first-arrival-wins keeps the originally
    // buffered bytes even when new data disagrees
    {
        TcpConnectionTable table(8080);
        TcpConnectionKey key{localIp(), 8080, remoteIp(), 54321};
        std::uint32_t server_isn = establish(table, key, 1000);
        table.handle(key, makeData(8080, 54321, 1010, server_isn + 1, toBytes("AAAA")), t0); // first
        table.handle(key, makeData(8080, 54321, 1010, server_isn + 1, toBytes("ZZZZ")), t0); // conflicting
        auto released = table.handle(key, makeData(8080, 54321, 1001, server_isn + 1, makeFilledPayload(9, std::byte{'m'})), t0);
        CHECK(released.accepted_payload == toBytes("mmmmmmmmmAAAA")); // original bytes kept
    }

    // segment entirely before rcv_nxt: pure duplicate, no state change
    {
        TcpConnectionTable table(8080);
        TcpConnectionKey key{localIp(), 8080, remoteIp(), 54321};
        std::uint32_t server_isn = establish(table, key, 1000);
        table.handle(key, makeData(8080, 54321, 1001, server_isn + 1, toBytes("AAA")), t0);
        auto before = table.snapshotOf(key);
        auto dup = table.handle(key, makeData(8080, 54321, 1001, server_isn + 1, toBytes("AAA")), t0);
        CHECK(dup.accepted_payload.empty());
        CHECK(dup.reply.has_value());
        auto after = table.snapshotOf(key);
        CHECK(before.has_value() && after.has_value());
        if (before && after) CHECK(before->rcv_nxt == after->rcv_nxt);
    }

    // segment entirely after the receive window: rejected wholesale
    {
        TcpConnectionTable table(8080);
        TcpConnectionKey key{localIp(), 8080, remoteIp(), 54321};
        std::uint32_t server_isn = establish(table, key, 1000);
        std::uint32_t far_seq = 1001 + static_cast<std::uint32_t>(kTcpReceiveCapacity) + 1000;
        auto result = table.handle(key, makeData(8080, 54321, far_seq, server_isn + 1, toBytes("late")), t0);
        CHECK(result.accepted_payload.empty());
        CHECK(result.reply.has_value());
        auto snapshot = table.snapshotOf(key);
        CHECK(snapshot.has_value());
        if (snapshot) CHECK(snapshot->reassembly_fragment_count == 0);
    }

    // segment crossing the right window edge: only the in-window prefix
    // is retained. This connection never negotiates Window Scale, so its
    // actual advertised window is wire-clamped at 65535 even though the
    // internal buffer capacity (kTcpReceiveCapacity) is larger.
    {
        TcpConnectionTable table(8080);
        TcpConnectionKey key{localIp(), 8080, remoteIp(), 54321};
        std::uint32_t server_isn = establish(table, key, 1000);
        std::uint32_t edge_seq = 1001 + 65535u - 3;
        auto result =
            table.handle(key, makeData(8080, 54321, edge_seq, server_isn + 1, toBytes("XXXXXX")), t0);
        CHECK(result.accepted_payload.empty()); // still gapped, not at rcv_nxt
        auto snapshot = table.snapshotOf(key);
        CHECK(snapshot.has_value());
        if (snapshot) CHECK(snapshot->reassembly_buffered_bytes == 3); // only the first 3 bytes fit
    }

    // fragment-count limit: 128 disjoint fragments accepted, the 129th dropped
    {
        TcpConnectionTable table(8080);
        TcpConnectionKey key{localIp(), 8080, remoteIp(), 54321};
        std::uint32_t server_isn = establish(table, key, 1000);
        for (std::size_t i = 0; i < kMaxReassemblyFragments; ++i) {
            std::uint32_t seq = 1001 + static_cast<std::uint32_t>(2 + 2 * i); // spaced, never touching
            table.handle(key, makeData(8080, 54321, seq, server_isn + 1, toBytes({0xaa})), t0);
        }
        auto before = table.snapshotOf(key);
        CHECK(before.has_value());
        if (before) CHECK(before->reassembly_fragment_count == kMaxReassemblyFragments);

        std::uint32_t extra_seq =
            1001 + static_cast<std::uint32_t>(2 + 2 * kMaxReassemblyFragments);
        table.handle(key, makeData(8080, 54321, extra_seq, server_isn + 1, toBytes({0xbb})), t0);
        auto after = table.snapshotOf(key);
        CHECK(after.has_value());
        if (after) CHECK(after->reassembly_fragment_count == kMaxReassemblyFragments); // unchanged
    }

    // byte-capacity limit: the advertised window naturally bounds
    // buffering to kTcpReceiveCapacity. Requires Window Scale negotiated
    // -- an unscaled connection can never advertise (or thus buffer)
    // more than the wire-clamped 65535 bytes regardless of the larger
    // internal capacity (see the scaled-window tests for that case).
    {
        TcpConnectionTable table(8080);
        TcpConnectionKey key{localIp(), 8080, remoteIp(), 54321};
        std::uint32_t server_isn = establishWithWindowScale(table, key, 1000, 2);
        // One big out-of-order fragment right up to (but not filling)
        // capacity, then confirm the window has shrunk by exactly that much.
        std::size_t big = kTcpReceiveCapacity - 1000;
        auto big_payload = makeFilledPayload(big, std::byte{'q'});
        table.handle(key, makeData(8080, 54321, 1002, server_isn + 1, big_payload), t0);
        auto snapshot = table.snapshotOf(key);
        CHECK(snapshot.has_value());
        if (snapshot) {
            CHECK(snapshot->reassembly_buffered_bytes == big);
            // Wire value is floor-divided by the negotiated scale (2).
            CHECK(snapshot->advertised_window == (kTcpReceiveCapacity - big) >> 2);
        }
    }

    // wraparound reassembly: rcv_nxt crosses 0xffffffff -> 0, delivered
    // out of order
    {
        TcpConnectionTable table(8080);
        TcpConnectionKey key{localIp(), 8080, remoteIp(), 54321};
        std::uint32_t server_isn = establish(table, key, 0xfffffffb); // rcv_nxt starts at 0xfffffffc
        auto late = table.handle(key, makeData(8080, 54321, 0, server_isn + 1, toBytes("Y")), t0); // wrapped
        CHECK(late.accepted_payload.empty());
        auto released =
            table.handle(key, makeData(8080, 54321, 0xfffffffc, server_isn + 1, toBytes("XXXX")), t0);
        CHECK(released.accepted_payload == toBytes("XXXXY"));
        auto snapshot = table.snapshotOf(key);
        CHECK(snapshot.has_value());
        if (snapshot) CHECK(snapshot->rcv_nxt == 1);
    }

    // ================= Milestone 10: out-of-order FIN =================

    // out-of-order FIN retained, released once the gap fills
    {
        TcpConnectionTable table(8080);
        TcpConnectionKey key{localIp(), 8080, remoteIp(), 54321};
        std::uint32_t server_isn = establish(table, key, 1000);
        auto late_fin = table.handle(key, makeFin(8080, 54321, 1004, server_isn + 1, toBytes("BBB")), t0);
        CHECK(late_fin.accepted_payload.empty());
        CHECK(!late_fin.peer_closed);
        CHECK(table.stateOf(key) == TcpState::Established);

        auto gap_fill = table.handle(key, makeData(8080, 54321, 1001, server_isn + 1, toBytes("AAA")), t0);
        CHECK(gap_fill.accepted_payload == toBytes("AAABBB"));
        CHECK(gap_fill.peer_closed); // EOF signaled exactly once, on the releasing call
        CHECK(table.stateOf(key) == TcpState::CloseWait);
    }

    // duplicate buffered FIN does not re-signal EOF
    {
        TcpConnectionTable table(8080);
        TcpConnectionKey key{localIp(), 8080, remoteIp(), 54321};
        std::uint32_t server_isn = establish(table, key, 1000);
        table.handle(key, makeFin(8080, 54321, 1001, server_isn + 1), t0); // in-order FIN -> CloseWait
        CHECK(table.stateOf(key) == TcpState::CloseWait);
        auto dup = table.handle(key, makeFin(8080, 54321, 1001, server_isn + 1), t0);
        CHECK(!dup.peer_closed);
        CHECK(table.stateOf(key) == TcpState::CloseWait);
    }

    // FIN beyond the receive window is not retained
    {
        TcpConnectionTable table(8080);
        TcpConnectionKey key{localIp(), 8080, remoteIp(), 54321};
        std::uint32_t server_isn = establish(table, key, 1000);
        std::uint32_t far_seq = 1001 + static_cast<std::uint32_t>(kTcpReceiveCapacity) + 1000;
        auto result = table.handle(key, makeFin(8080, 54321, far_seq, server_isn + 1), t0);
        CHECK(!result.peer_closed);
        CHECK(table.stateOf(key) == TcpState::Established);
    }

    // FIN riding along with overlapping payload: only the new suffix is
    // accepted, and the FIN (right after the original payload's end)
    // is retained/consumed only once that position becomes contiguous
    {
        TcpConnectionTable table(8080);
        TcpConnectionKey key{localIp(), 8080, remoteIp(), 54321};
        std::uint32_t server_isn = establish(table, key, 1000);
        table.handle(key, makeData(8080, 54321, 1001, server_isn + 1, toBytes("AAA")), t0); // rcv_nxt=1004
        // Overlapping FIN segment: starts at 1001 (already delivered),
        // 3-byte payload again, then FIN at 1004 -- exactly at rcv_nxt.
        auto result = table.handle(key, makeFin(8080, 54321, 1001, server_isn + 1, toBytes("AAA")), t0);
        CHECK(result.accepted_payload.empty()); // nothing new in the payload itself
        CHECK(result.peer_closed); // but the FIN at 1004 is exactly in-order
        CHECK(table.stateOf(key) == TcpState::CloseWait);
    }

    // FIN sequence wraparound
    {
        TcpConnectionTable table(8080);
        TcpConnectionKey key{localIp(), 8080, remoteIp(), 54321};
        std::uint32_t server_isn = establish(table, key, 0xfffffffe); // rcv_nxt starts at 0xffffffff
        auto result = table.handle(key, makeFin(8080, 54321, 0xffffffff, server_isn + 1), t0);
        CHECK(result.peer_closed);
        auto snapshot = table.snapshotOf(key);
        CHECK(snapshot.has_value());
        if (snapshot) CHECK(snapshot->rcv_nxt == 0);
    }

    // RST clears a pending (retained) out-of-order FIN along with
    // everything else
    {
        TcpConnectionTable table(8080);
        TcpConnectionKey key{localIp(), 8080, remoteIp(), 54321};
        std::uint32_t server_isn = establish(table, key, 1000);
        table.handle(key, makeFin(8080, 54321, 1004, server_isn + 1, toBytes("BBB")), t0); // retained
        auto result = table.handle(key, makeRst(8080, 54321, 1001), t0);
        CHECK(result.connection_reset);
        CHECK(!table.stateOf(key).has_value());
    }

    // timeout removal clears a pending out-of-order FIN along with the
    // rest of the connection
    {
        TcpConnectionTable table(8080);
        TcpConnectionKey key{localIp(), 8080, remoteIp(), 54321};
        std::uint32_t server_isn = establish(table, key, 1000);
        table.handle(key, makeFin(8080, 54321, 1004, server_isn + 1, toBytes("BBB")), t0); // retained
        auto fin_result = table.beginClose(key, t0); // our own FIN, to give pollRetransmissions something to time out
        auto fin = fin_result.fin;
        CHECK(fin.has_value());
        auto t = t0;
        std::chrono::milliseconds rto = kInitialRto;
        for (int i = 0; i < kMaxRetransmits; ++i) {
            t += rto;
            table.pollRetransmissions(t);
            rto = std::min(rto * 2, std::chrono::duration_cast<std::chrono::milliseconds>(kMaxRto));
        }
        t += rto;
        auto exhausted = table.pollRetransmissions(t);
        CHECK(exhausted.timed_out.size() == 1);
        CHECK(!table.stateOf(key).has_value());
    }

    // ================= Milestone 11: SYN-ACK option vectors =================

    // Without peer Window Scale: MSS only, 24-byte header, Data Offset 6.
    {
        TcpConnectionTable table(8080);
        TcpConnectionKey key{localIp(), 8080, remoteIp(), 54321};
        auto reply = table.handle(key, makeSynWithOptions(8080, 54321, 1000, {}), t0).reply;
        CHECK(reply.has_value());
        if (reply) {
            CHECK(reply->options == toBytes({0x02, 0x04, 0x05, 0xb4}));
            CHECK(reply->window_size == 65535); // unscaled

            auto serialized = serializeTcpSegment(*reply, localIp(), remoteIp());
            CHECK(std::holds_alternative<std::vector<std::byte>>(serialized));
            if (auto* bytes = std::get_if<std::vector<std::byte>>(&serialized)) {
                CHECK(bytes->size() == 24); // 20-byte header + 4-byte options
                CHECK((*bytes)[12] >> 4 == std::byte{6}); // Data Offset 6

                auto reparsed = parseTcpSegment(*bytes, localIp(), remoteIp()); // validates checksum
                CHECK(std::holds_alternative<TcpSegment>(reparsed));
                if (auto* segment = std::get_if<TcpSegment>(&reparsed)) {
                    CHECK(segment->flags.syn && segment->flags.ack);
                    CHECK(segment->options == toBytes({0x02, 0x04, 0x05, 0xb4}));
                }
            }
        }
    }

    // With peer Window Scale: MSS + NOP + Window Scale, 28-byte header,
    // Data Offset 7. Local scale is always kLocalWindowScaleShift (2),
    // never derived from what the peer offered.
    {
        TcpConnectionTable table(8080);
        TcpConnectionKey key{localIp(), 8080, remoteIp(), 54321};
        std::vector<std::byte> syn_options = {std::byte{2}, std::byte{4}, std::byte{0x05},
                                                std::byte{0xb4}, std::byte{1}, std::byte{3},
                                                std::byte{3},    std::byte{7}};
        auto reply =
            table.handle(key, makeSynWithOptions(8080, 54321, 1000, syn_options), t0).reply;
        CHECK(reply.has_value());
        if (reply) {
            CHECK(reply->options ==
                  toBytes({0x02, 0x04, 0x05, 0xb4, 0x01, 0x03, 0x03, 0x02}));
            CHECK(reply->window_size == 65535); // still unscaled

            auto serialized = serializeTcpSegment(*reply, localIp(), remoteIp());
            CHECK(std::holds_alternative<std::vector<std::byte>>(serialized));
            if (auto* bytes = std::get_if<std::vector<std::byte>>(&serialized)) {
                CHECK(bytes->size() == 28);
                CHECK((*bytes)[12] >> 4 == std::byte{7}); // Data Offset 7
                CHECK(std::holds_alternative<TcpSegment>(
                    parseTcpSegment(*bytes, localIp(), remoteIp())));
            }
        }
    }

    // ================= Milestone 11: effective MSS =================

    {
        auto check = [&](std::optional<std::uint16_t> peer_mss, std::uint16_t expected) {
            TcpConnectionTable table(8080);
            TcpConnectionKey key{localIp(), 8080, remoteIp(), 54321};
            establishWithPeerMss(table, key, 1000, peer_mss, t0);
            auto snapshot = table.snapshotOf(key);
            CHECK(snapshot.has_value());
            if (snapshot) {
                CHECK(snapshot->peer_mss == peer_mss.value_or(536));
                CHECK(snapshot->effective_send_mss == expected);
            }
        };
        check(1460, 1460);
        check(1200, 1200);
        check(536, 536);
        check(2000, 1460);       // capped at local path MSS
        check(std::nullopt, 536); // absent -> IPv4 default fallback
    }

    // peer MSS 536, payload 1200 -> segments of 536, 536, 128
    {
        TcpConnectionTable table(8080);
        TcpConnectionKey key{localIp(), 8080, remoteIp(), 54321};
        establishWithPeerMss(table, key, 1000, std::uint16_t{536}, t0);
        auto payload = makeFilledPayload(1200);
        auto sent = table.makeOutgoingData(key, payload, t0);
        CHECK(sent.segments.size() == 3);
        if (sent.segments.size() == 3) {
            CHECK(sent.segments[0].payload.size() == 536);
            CHECK(sent.segments[1].payload.size() == 536);
            CHECK(sent.segments[2].payload.size() == 128);
            CHECK(!sent.segments[0].flags.psh);
            CHECK(!sent.segments[1].flags.psh);
            CHECK(sent.segments[2].flags.psh);
            CHECK(sent.segments[1].sequence_number == sent.segments[0].sequence_number + 536);
            CHECK(sent.segments[2].sequence_number == sent.segments[1].sequence_number + 536);
            std::vector<std::byte> reconstructed;
            for (const auto& seg : sent.segments) {
                reconstructed.insert(reconstructed.end(), seg.payload.begin(), seg.payload.end());
            }
            CHECK(reconstructed == payload);
        }
        auto snapshot = table.snapshotOf(key);
        CHECK(snapshot.has_value());
        if (snapshot) CHECK(snapshot->pending_count == 3);
    }

    // segment-count bound: enqueue always succeeds up to the send-buffer
    // capacity now, but one scheduling pass with a tiny negotiated peer
    // MSS is still bounded by kMaxSegmentsPerSend, regardless of
    // allowance -- here the fresh connection's initial congestion window
    // (10*SMSS = 10 bytes) is the actual binding limit for this first
    // pass anyway, well under the bound.
    {
        TcpConnectionTable table(8080);
        TcpConnectionKey key{localIp(), 8080, remoteIp(), 54321};
        establishWithPeerMss(table, key, 1000, std::uint16_t{1}, t0); // effective_send_mss = 1
        auto before = table.snapshotOf(key);
        auto sent = table.makeOutgoingData(key, makeFilledPayload(kMaxSegmentsPerSend + 1), t0);
        CHECK(!sent.error);
        CHECK(sent.bytes_accepted == kMaxSegmentsPerSend + 1);
        CHECK(sent.segments.size() <= kMaxSegmentsPerSend);
        CHECK(sent.segments.size() == 10); // cwnd-limited (10*SMSS with SMSS=1)
        auto after = table.snapshotOf(key);
        CHECK(before.has_value() && after.has_value());
        if (before && after) CHECK(after->snd_nxt == before->snd_nxt + 10);
    }

    // ================= Milestone 11: Window Scale negotiation =================

    // not offered
    {
        TcpConnectionTable table(8080);
        TcpConnectionKey key{localIp(), 8080, remoteIp(), 54321};
        establish(table, key, 1000); // makeSyn() carries MSS only, no Window Scale
        auto snapshot = table.snapshotOf(key);
        CHECK(snapshot.has_value());
        if (snapshot) {
            CHECK(!snapshot->window_scaling_enabled);
            CHECK(snapshot->peer_window_scale == 0);
            CHECK(snapshot->local_window_scale == 0);
        }
    }

    // peer scale 0, 2, 14, and 15 (clamped to 14)
    {
        auto check = [&](std::uint8_t offered, std::uint8_t expected_stored) {
            TcpConnectionTable table(8080);
            TcpConnectionKey key{localIp(), 8080, remoteIp(), 54321};
            establishWithWindowScale(table, key, 1000, offered, t0);
            auto snapshot = table.snapshotOf(key);
            CHECK(snapshot.has_value());
            if (snapshot) {
                CHECK(snapshot->window_scaling_enabled);
                CHECK(snapshot->peer_window_scale == expected_stored);
                CHECK(snapshot->local_window_scale == 2);
            }
        };
        check(0, 0);
        check(2, 2);
        check(14, 14);
        check(15, 14);
    }

    // final ACK's window field is scaled once negotiated (data-segment
    // window decoding uses the same path)
    {
        TcpConnectionTable table(8080);
        TcpConnectionKey key{localIp(), 8080, remoteIp(), 54321};
        std::vector<std::byte> options = {std::byte{2}, std::byte{4}, std::byte{0x05},
                                            std::byte{0xb4}, std::byte{1}, std::byte{3},
                                            std::byte{3},    std::byte{2}};
        auto syn_ack = table.handle(key, makeSynWithOptions(8080, 54321, 1000, options), t0).reply;
        CHECK(syn_ack.has_value());
        std::uint32_t server_isn = syn_ack ? syn_ack->sequence_number : 0;
        TcpSegment final_ack = makeAck(8080, 54321, 1001, server_isn + 1);
        final_ack.window_size = 100; // raw wire value
        table.handle(key, final_ack, t0);
        auto snapshot = table.snapshotOf(key);
        CHECK(snapshot.has_value());
        if (snapshot) CHECK(snapshot->snd_wnd == (100u << 2)); // decoded: 400
    }

    // outgoing receive-window encoding: floor division, never
    // over-advertises
    {
        TcpConnectionTable table(8080);
        TcpConnectionKey key{localIp(), 8080, remoteIp(), 54321};
        std::uint32_t server_isn = establishWithWindowScale(table, key, 1000, 2, t0);
        // 1 byte out-of-order: available = capacity - 1 = 262139;
        // floor(262139 / 4) = 65534 (262139 = 4*65534 + 3) -- rounds
        // down, never up.
        table.handle(key, makeData(8080, 54321, 1003, server_isn + 1, toBytes({0xaa})), t0);
        auto snapshot = table.snapshotOf(key);
        CHECK(snapshot.has_value());
        if (snapshot) CHECK(snapshot->advertised_window == 65534);
    }

    // receive acceptance matches the encoded logical window, not the
    // (larger) internal capacity
    {
        TcpConnectionTable table(8080);
        TcpConnectionKey key{localIp(), 8080, remoteIp(), 54321};
        std::uint32_t server_isn = establishWithWindowScale(table, key, 1000, 2, t0);
        std::uint32_t edge_seq = 1001 + static_cast<std::uint32_t>(kTcpReceiveCapacity);
        auto result =
            table.handle(key, makeData(8080, 54321, edge_seq, server_isn + 1, toBytes("x")), t0);
        CHECK(result.accepted_payload.empty());
        auto snapshot = table.snapshotOf(key);
        CHECK(snapshot.has_value());
        if (snapshot) CHECK(snapshot->reassembly_fragment_count == 0); // rejected, nothing stored
    }

    // zero window (scaled) rejects new data; window reopens; a stale
    // scaled-window update is rejected
    {
        TcpConnectionTable table(8080);
        TcpConnectionKey key{localIp(), 8080, remoteIp(), 54321};
        std::uint32_t server_isn = establishWithWindowScale(table, key, 1000, 2, t0);

        TcpSegment zero = makeAck(8080, 54321, 1001, server_isn + 1);
        zero.window_size = 0;
        table.handle(key, zero, t0);
        CHECK(table.makeOutgoingData(key, toBytes("x"), t0).segments.empty());

        TcpSegment newer = makeAck(8080, 54321, 1001, server_isn + 1);
        newer.window_size = 500; // logical 2000
        table.handle(key, newer, t0);
        CHECK(!table.makeOutgoingData(key, toBytes("x"), t0).segments.empty());

        TcpSegment stale = makeAck(8080, 54321, 1000, server_isn + 1); // earlier sequence number
        stale.window_size = 10;
        table.handle(key, stale, t0);
        auto snapshot = table.snapshotOf(key);
        CHECK(snapshot.has_value());
        if (snapshot) CHECK(snapshot->snd_wnd == (500u << 2)); // stale update ignored
    }

    // ================= Milestone 11: RTT and adaptive RTO =================

    // initial state: no sample yet, RTO = 1 second
    {
        TcpConnectionTable table(8080);
        TcpConnectionKey key{localIp(), 8080, remoteIp(), 54321};
        table.handle(key, makeSyn(8080, 54321, 1000), t0); // SynReceived, no ACK yet
        auto snapshot = table.snapshotOf(key);
        CHECK(snapshot.has_value());
        if (snapshot) {
            CHECK(!snapshot->has_rtt_sample);
            CHECK(snapshot->current_rto == kInitialRto);
        }
    }

    // first sample: R=200ms -> SRTT=200ms, RTTVAR=100ms, RTO clamped to 1s
    {
        TcpConnectionTable table(8080);
        TcpConnectionKey key{localIp(), 8080, remoteIp(), 54321};
        auto syn_ack = table.handle(key, makeSyn(8080, 54321, 1000), t0).reply;
        CHECK(syn_ack.has_value());
        std::uint32_t server_isn = syn_ack ? syn_ack->sequence_number : 0;
        auto ack_time = t0 + std::chrono::milliseconds(200);
        table.handle(key, makeAck(8080, 54321, 1001, server_isn + 1), ack_time);
        auto snapshot = table.snapshotOf(key);
        CHECK(snapshot.has_value());
        if (snapshot) {
            CHECK(snapshot->has_rtt_sample);
            CHECK(snapshot->srtt == std::chrono::milliseconds(200));
            CHECK(snapshot->rttvar == std::chrono::milliseconds(100));
            CHECK(snapshot->current_rto == kInitialRto); // 600ms raw, clamped to the 1s minimum
        }
    }

    // second sample: existing SRTT=200/RTTVAR=100, new R=1000ms ->
    // RTTVAR=275ms, SRTT=300ms, RTO=1400ms (exact known vector)
    {
        TcpConnectionTable table(8080);
        TcpConnectionKey key{localIp(), 8080, remoteIp(), 54321};
        auto syn_ack = table.handle(key, makeSyn(8080, 54321, 1000), t0).reply;
        std::uint32_t server_isn = syn_ack ? syn_ack->sequence_number : 0;
        auto ack_time = t0 + std::chrono::milliseconds(200);
        table.handle(key, makeAck(8080, 54321, 1001, server_isn + 1), ack_time); // first sample

        auto sent = table.makeOutgoingData(key, toBytes("x"), ack_time);
        CHECK(!sent.segments.empty());
        auto second_ack_time = ack_time + std::chrono::milliseconds(1000);
        std::uint32_t ack_num = sent.segments.front().sequence_number +
                                 static_cast<std::uint32_t>(sent.segments.front().payload.size());
        table.handle(key, makeAck(8080, 54321, 1001, ack_num), second_ack_time);

        auto snapshot = table.snapshotOf(key);
        CHECK(snapshot.has_value());
        if (snapshot) {
            CHECK(snapshot->rttvar == std::chrono::milliseconds(275));
            CHECK(snapshot->srtt == std::chrono::milliseconds(300));
            CHECK(snapshot->current_rto == std::chrono::milliseconds(1400));
        }
    }

    // minimum clamp: a tiny consistent RTT never drives RTO below 1s
    {
        TcpConnectionTable table(8080);
        TcpConnectionKey key{localIp(), 8080, remoteIp(), 54321};
        auto syn_ack = table.handle(key, makeSyn(8080, 54321, 1000), t0).reply;
        std::uint32_t server_isn = syn_ack ? syn_ack->sequence_number : 0;
        table.handle(key, makeAck(8080, 54321, 1001, server_isn + 1),
                     t0 + std::chrono::milliseconds(10));
        auto snapshot = table.snapshotOf(key);
        CHECK(snapshot.has_value());
        if (snapshot) CHECK(snapshot->current_rto == kMinRto);
    }

    // maximum clamp: a huge RTT sample never drives RTO above 60s
    {
        TcpConnectionTable table(8080);
        TcpConnectionKey key{localIp(), 8080, remoteIp(), 54321};
        auto syn_ack = table.handle(key, makeSyn(8080, 54321, 1000), t0).reply;
        std::uint32_t server_isn = syn_ack ? syn_ack->sequence_number : 0;
        table.handle(key, makeAck(8080, 54321, 1001, server_isn + 1), t0 + std::chrono::seconds(100));
        auto snapshot = table.snapshotOf(key);
        CHECK(snapshot.has_value());
        if (snapshot) CHECK(snapshot->current_rto == kMaxRto);
    }

    // Karn's rule: an ACK of a retransmitted segment produces no sample
    {
        TcpConnectionTable table(8080);
        TcpConnectionKey key{localIp(), 8080, remoteIp(), 54321};
        establish(table, key, 1000);
        auto sent = table.makeOutgoingData(key, toBytes("data"), t0);
        CHECK(!sent.segments.empty());
        auto due = table.pollRetransmissions(t0 + kInitialRto);
        CHECK(due.retransmissions.size() == 1);
        auto before = table.snapshotOf(key);
        std::uint32_t ack_num = sent.segments.front().sequence_number +
                                 static_cast<std::uint32_t>(sent.segments.front().payload.size());
        table.handle(key, makeAck(8080, 54321, 1001, ack_num),
                     t0 + kInitialRto + std::chrono::milliseconds(500));
        auto after = table.snapshotOf(key);
        CHECK(before.has_value() && after.has_value());
        if (before && after) {
            CHECK(after->srtt == before->srtt);
            CHECK(after->rttvar == before->rttvar);
            CHECK(after->current_rto == before->current_rto);
        }
    }

    // duplicate ACK produces no sample
    {
        TcpConnectionTable table(8080);
        TcpConnectionKey key{localIp(), 8080, remoteIp(), 54321};
        establish(table, key, 1000);
        auto sent = table.makeOutgoingData(key, toBytes("data"), t0);
        std::uint32_t ack_num = sent.segments.front().sequence_number +
                                 static_cast<std::uint32_t>(sent.segments.front().payload.size());
        table.handle(key, makeAck(8080, 54321, 1001, ack_num), t0 + std::chrono::milliseconds(50));
        auto before = table.snapshotOf(key);
        CHECK(before.has_value());
        if (before) {
            table.handle(key, makeAck(8080, 54321, 1001, before->snd_una),
                         t0 + std::chrono::milliseconds(999)); // duplicate
        }
        auto after = table.snapshotOf(key);
        CHECK(before.has_value() && after.has_value());
        if (before && after) CHECK(after->srtt == before->srtt);
    }

    // invalid ACK (beyond snd_nxt) produces no sample and no state change
    {
        TcpConnectionTable table(8080);
        TcpConnectionKey key{localIp(), 8080, remoteIp(), 54321};
        establish(table, key, 1000);
        auto before = table.snapshotOf(key);
        CHECK(before.has_value());
        if (before) {
            table.handle(key, makeAck(8080, 54321, 1001, before->snd_nxt + 1000),
                         t0 + std::chrono::seconds(5));
        }
        auto after = table.snapshotOf(key);
        CHECK(before.has_value() && after.has_value());
        if (before && after) {
            CHECK(after->srtt == before->srtt);
            CHECK(after->snd_una == before->snd_una);
        }
    }

    // one cumulative ACK covering multiple segments produces at most one
    // sample -- verified against the exact single-sample formula applied
    // to the pre-existing (degenerate, R=0) handshake estimate
    {
        TcpConnectionTable table(8080);
        TcpConnectionKey key{localIp(), 8080, remoteIp(), 54321};
        establish(table, key, 1000); // handshake sample: R=0 (SYN-ACK and final ACK both at t0)
        auto a = table.makeOutgoingData(key, toBytes("AAA"), t0);
        auto b = table.makeOutgoingData(key, toBytes("BBB"), t0 + std::chrono::milliseconds(100));
        auto c = table.makeOutgoingData(key, toBytes("CCC"), t0 + std::chrono::milliseconds(200));
        CHECK(!a.segments.empty() && !b.segments.empty() && !c.segments.empty());

        std::uint32_t cumulative_ack = c.segments.front().sequence_number +
                                        static_cast<std::uint32_t>(c.segments.front().payload.size());
        auto ack_time = t0 + std::chrono::milliseconds(700); // R for C = 500ms
        table.handle(key, makeAck(8080, 54321, 1001, cumulative_ack), ack_time);

        auto snapshot = table.snapshotOf(key);
        CHECK(snapshot.has_value());
        if (snapshot) {
            // Single subsequent-sample update from (srtt=0, rttvar=0), R=500ms.
            CHECK(snapshot->rttvar == std::chrono::milliseconds(125));
            CHECK(snapshot->srtt == std::chrono::microseconds(62500));
        }
    }

    // recovery after backoff: a later clean sample lowers the RTO again
    {
        TcpConnectionTable table(8080);
        TcpConnectionKey key{localIp(), 8080, remoteIp(), 54321};
        establish(table, key, 1000);
        auto sent = table.makeOutgoingData(key, toBytes("data"), t0);
        auto due = table.pollRetransmissions(t0 + kInitialRto);
        CHECK(due.retransmissions.size() == 1);
        auto after_backoff = table.snapshotOf(key);
        CHECK(after_backoff.has_value());
        if (after_backoff) CHECK(after_backoff->current_rto == kInitialRto * 2);

        std::uint32_t ack_num = sent.segments.front().sequence_number +
                                 static_cast<std::uint32_t>(sent.segments.front().payload.size());
        table.handle(key, makeAck(8080, 54321, 1001, ack_num),
                     t0 + kInitialRto + std::chrono::milliseconds(10)); // Karn's rule, no sample

        auto clean_time = t0 + kInitialRto + std::chrono::milliseconds(500);
        auto sent2 = table.makeOutgoingData(key, toBytes("more"), clean_time);
        CHECK(!sent2.segments.empty());
        auto clean_ack_time = clean_time + std::chrono::milliseconds(100);
        std::uint32_t ack_num2 = sent2.segments.front().sequence_number +
                                  static_cast<std::uint32_t>(sent2.segments.front().payload.size());
        table.handle(key, makeAck(8080, 54321, 1001, ack_num2), clean_ack_time);

        auto after_recovery = table.snapshotOf(key);
        CHECK(after_recovery.has_value());
        if (after_recovery && after_backoff) {
            CHECK(after_recovery->current_rto < after_backoff->current_rto);
        }
    }

    // ================= Milestone 11: multi-connection and duplicate-SYN isolation =================

    // MSS, Window Scale, and RTT/RTO state remain independent per connection
    {
        TcpConnectionTable table(8080);
        TcpConnectionKey key_a{localIp(), 8080, remoteIp(), 11111};
        TcpConnectionKey key_b{localIp(), 8080, remoteIp(), 22222};
        establishWithPeerMss(table, key_a, 1000, std::uint16_t{536}, t0);
        establishWithWindowScale(table, key_b, 2000, 4, t0);

        auto snap_a = table.snapshotOf(key_a);
        auto snap_b = table.snapshotOf(key_b);
        CHECK(snap_a.has_value() && snap_b.has_value());
        if (snap_a && snap_b) {
            CHECK(snap_a->effective_send_mss == 536);
            CHECK(!snap_a->window_scaling_enabled);
            CHECK(snap_b->effective_send_mss == 1460);
            CHECK(snap_b->window_scaling_enabled);
            CHECK(snap_b->peer_window_scale == 4);
        }

        auto sent_a = table.makeOutgoingData(key_a, toBytes("x"), t0);
        CHECK(!sent_a.segments.empty());
        table.handle(key_a,
                     makeAck(8080, 11111, 1001, sent_a.segments.front().sequence_number + 1),
                     t0 + std::chrono::milliseconds(300));

        auto after_a = table.snapshotOf(key_a);
        auto after_b = table.snapshotOf(key_b);
        CHECK(after_a.has_value() && after_b.has_value());
        if (after_a && after_b) {
            CHECK(after_a->srtt > TcpClock::duration{});
            CHECK(after_b->srtt == TcpClock::duration{}); // untouched by A's activity
        }
    }

    // duplicate SYN with different options: original negotiation remains
    // authoritative, identical SYN-ACK bytes are replayed
    {
        TcpConnectionTable table(8080);
        TcpConnectionKey key{localIp(), 8080, remoteIp(), 54321};
        std::vector<std::byte> original_options = {std::byte{2}, std::byte{4}, std::byte{0x02},
                                                      std::byte{0x18}}; // MSS 536
        auto first_reply =
            table.handle(key, makeSynWithOptions(8080, 54321, 1000, original_options), t0).reply;
        CHECK(first_reply.has_value());

        std::vector<std::byte> different_options = {std::byte{2}, std::byte{4}, std::byte{0x05},
                                                       std::byte{0xb4}, std::byte{1}, std::byte{3},
                                                       std::byte{3},    std::byte{5}};
        auto second_reply = table
                                 .handle(key,
                                         makeSynWithOptions(8080, 54321, 1000, different_options),
                                         t0 + std::chrono::milliseconds(100))
                                 .reply;
        CHECK(second_reply.has_value());
        if (first_reply && second_reply) {
            CHECK(first_reply->options == second_reply->options);
            CHECK(first_reply->sequence_number == second_reply->sequence_number);
        }

        auto snapshot = table.snapshotOf(key);
        CHECK(snapshot.has_value());
        if (snapshot) {
            CHECK(snapshot->peer_mss == 536);
            CHECK(!snapshot->window_scaling_enabled);
        }
    }

    // malformed SYN options: no SYN-ACK, no connection state, no RST
    {
        TcpConnectionTable table(8080);
        TcpConnectionKey key{localIp(), 8080, remoteIp(), 54321};
        auto result = table.handle(key, makeSynWithOptions(8080, 54321, 1000, toBytes({2})), t0);
        CHECK(!result.reply.has_value());
        CHECK(!table.stateOf(key).has_value());
    }
    {
        TcpConnectionTable table(8080);
        TcpConnectionKey key{localIp(), 8080, remoteIp(), 54321};
        auto result = table.handle(
            key,
            makeSynWithOptions(8080, 54321, 1000,
                                toBytes({2, 4, 0x05, 0xb4, 2, 4, 0x02, 0x18})), // duplicate MSS
            t0);
        CHECK(!result.reply.has_value());
        CHECK(!table.stateOf(key).has_value());
    }

    // ================= PR #5 fix 1: local vs peer window scale =================

    // snd_wnd decodes using the PEER's scale; the receive-acceptance
    // boundary expands using Wirestack's own LOCAL scale (fixed at 2) --
    // these must stay independent even when the peer offers a very
    // different shift.
    {
        auto check = [&](std::uint8_t peer_scale) {
            TcpConnectionTable table(8080);
            TcpConnectionKey key{localIp(), 8080, remoteIp(), 54321};
            std::uint32_t server_isn = establishWithWindowScale(table, key, 1000, peer_scale, t0);

            TcpSegment window_update = makeAck(8080, 54321, 1001, server_isn + 1);
            window_update.window_size = 100;
            table.handle(key, window_update, t0);
            auto snapshot = table.snapshotOf(key);
            CHECK(snapshot.has_value());
            if (snapshot) {
                CHECK(snapshot->peer_window_scale == peer_scale);
                CHECK(snapshot->local_window_scale == 2);
                CHECK(snapshot->snd_wnd == (static_cast<std::uint32_t>(100) << peer_scale));
            }

            // Right edge of Wirestack's own advertised logical window is
            // governed by local_window_scale (2) alone: kTcpReceiveCapacity
            // (262140) bytes from rcv_nxt, regardless of peer_scale.
            std::uint32_t last_in_window =
                1001 + static_cast<std::uint32_t>(kTcpReceiveCapacity) - 1;
            table.handle(key, makeData(8080, 54321, last_in_window, server_isn + 1, toBytes({0xaa})),
                         t0);
            auto after_last = table.snapshotOf(key);
            CHECK(after_last.has_value());
            if (after_last) {
                // Far out-of-order (rcv_nxt is still 1001) but within the
                // window -- buffered, not rejected.
                CHECK(after_last->reassembly_fragment_count == 1);
                CHECK(after_last->reassembly_buffered_bytes <= kTcpReceiveCapacity);
            }
        };
        check(0);
        check(3);
        check(14);
    }

    // One byte beyond the local logical window's right edge is rejected --
    // in particular, with peer_scale=14, incorrectly expanding Wirestack's
    // own window using the PEER's shift would have advertised an
    // approximately 1 GiB window (65535 << 14) and wrongly accepted this
    // byte.
    {
        TcpConnectionTable table(8080);
        TcpConnectionKey key{localIp(), 8080, remoteIp(), 54321};
        std::uint32_t server_isn = establishWithWindowScale(table, key, 1000, 14, t0);
        auto snapshot_before = table.snapshotOf(key);
        CHECK(snapshot_before.has_value());
        if (snapshot_before) {
            CHECK(snapshot_before->peer_window_scale == 14);
            CHECK(snapshot_before->local_window_scale == 2);
        }

        std::uint32_t one_past_window = 1001 + static_cast<std::uint32_t>(kTcpReceiveCapacity);
        auto result = table.handle(
            key, makeData(8080, 54321, one_past_window, server_isn + 1, toBytes({0xaa})), t0);
        CHECK(result.accepted_payload.empty());
        auto snapshot_after = table.snapshotOf(key);
        CHECK(snapshot_after.has_value());
        if (snapshot_after) {
            CHECK(snapshot_after->reassembly_fragment_count == 0); // rejected, nothing stored
        }
    }

    // ================= PR #5 fix 2: SYN-ACK options survive retransmission =================

    // MSS only: initial and timeout-retransmitted SYN-ACK both carry
    // "02 04 05 b4", Data Offset 6, 24-byte header.
    {
        TcpConnectionTable table(8080);
        TcpConnectionKey key{localIp(), 8080, remoteIp(), 54321};
        auto initial_reply = table.handle(key, makeSynWithOptions(8080, 54321, 1000, {}), t0).reply;
        CHECK(initial_reply.has_value());
        if (!initial_reply) return wirestack::test::failureCount() == 0 ? 0 : 1;
        CHECK(initial_reply->options == toBytes({0x02, 0x04, 0x05, 0xb4}));

        auto due = table.pollRetransmissions(t0 + kInitialRto);
        CHECK(due.retransmissions.size() == 1);
        if (due.retransmissions.size() == 1) {
            const auto& retransmitted = due.retransmissions[0].segment;
            CHECK(retransmitted.options == toBytes({0x02, 0x04, 0x05, 0xb4}));
            CHECK(retransmitted.sequence_number == initial_reply->sequence_number);
            CHECK(retransmitted.acknowledgment_number == initial_reply->acknowledgment_number);
            CHECK(retransmitted.flags.syn && retransmitted.flags.ack);
            CHECK(retransmitted.window_size == 65535); // still unscaled

            auto serialized = serializeTcpSegment(retransmitted, localIp(), remoteIp());
            CHECK(std::holds_alternative<std::vector<std::byte>>(serialized));
            if (auto* bytes = std::get_if<std::vector<std::byte>>(&serialized)) {
                CHECK(bytes->size() == 24);
                CHECK((*bytes)[12] >> 4 == std::byte{6}); // Data Offset 6
                auto reparsed = parseTcpSegment(*bytes, localIp(), remoteIp()); // validates checksum
                CHECK(std::holds_alternative<TcpSegment>(reparsed));
                if (auto* segment = std::get_if<TcpSegment>(&reparsed)) {
                    CHECK(segment->options == toBytes({0x02, 0x04, 0x05, 0xb4}));
                }
            }
        }

        // Retransmission does not renegotiate.
        auto snapshot = table.snapshotOf(key);
        CHECK(snapshot.has_value());
        if (snapshot) {
            CHECK(snapshot->peer_mss == 536); // no MSS offered -> fallback, unchanged
            CHECK(!snapshot->window_scaling_enabled);
        }

        // Karn's rule: the ACK completing the handshake after a SYN-ACK
        // retransmission must not produce an RTT sample.
        table.handle(key, makeAck(8080, 54321, 1001, initial_reply->sequence_number + 1),
                     t0 + kInitialRto);
        CHECK(table.stateOf(key) == TcpState::Established);
        auto after = table.snapshotOf(key);
        CHECK(after.has_value());
        if (after) CHECK(!after->has_rtt_sample);
    }

    // MSS and Window Scale: initial and timeout-retransmitted SYN-ACK both
    // carry "02 04 05 b4 01 03 03 02", Data Offset 7, 28-byte header.
    {
        TcpConnectionTable table(8080);
        TcpConnectionKey key{localIp(), 8080, remoteIp(), 54321};
        std::vector<std::byte> syn_options = {std::byte{2}, std::byte{4}, std::byte{0x05},
                                                std::byte{0xb4}, std::byte{1}, std::byte{3},
                                                std::byte{3},    std::byte{5}};
        auto initial_reply =
            table.handle(key, makeSynWithOptions(8080, 54321, 1000, syn_options), t0).reply;
        CHECK(initial_reply.has_value());
        if (!initial_reply) return wirestack::test::failureCount() == 0 ? 0 : 1;
        CHECK(initial_reply->options == toBytes({0x02, 0x04, 0x05, 0xb4, 0x01, 0x03, 0x03, 0x02}));

        auto due = table.pollRetransmissions(t0 + kInitialRto);
        CHECK(due.retransmissions.size() == 1);
        if (due.retransmissions.size() == 1) {
            const auto& retransmitted = due.retransmissions[0].segment;
            CHECK(retransmitted.options ==
                  toBytes({0x02, 0x04, 0x05, 0xb4, 0x01, 0x03, 0x03, 0x02}));
            CHECK(retransmitted.sequence_number == initial_reply->sequence_number);
            CHECK(retransmitted.acknowledgment_number == initial_reply->acknowledgment_number);
            CHECK(retransmitted.flags.syn && retransmitted.flags.ack);
            CHECK(retransmitted.window_size == 65535); // still unscaled

            auto serialized = serializeTcpSegment(retransmitted, localIp(), remoteIp());
            CHECK(std::holds_alternative<std::vector<std::byte>>(serialized));
            if (auto* bytes = std::get_if<std::vector<std::byte>>(&serialized)) {
                CHECK(bytes->size() == 28);
                CHECK((*bytes)[12] >> 4 == std::byte{7}); // Data Offset 7
                auto reparsed = parseTcpSegment(*bytes, localIp(), remoteIp()); // validates checksum
                CHECK(std::holds_alternative<TcpSegment>(reparsed));
                if (auto* segment = std::get_if<TcpSegment>(&reparsed)) {
                    CHECK(segment->options ==
                          toBytes({0x02, 0x04, 0x05, 0xb4, 0x01, 0x03, 0x03, 0x02}));
                }
            }
        }

        auto snapshot = table.snapshotOf(key);
        CHECK(snapshot.has_value());
        if (snapshot) {
            CHECK(snapshot->window_scaling_enabled);
            CHECK(snapshot->peer_window_scale == 5); // unchanged by the retransmission
            CHECK(snapshot->local_window_scale == 2);
        }

        table.handle(key, makeAck(8080, 54321, 1001, initial_reply->sequence_number + 1),
                     t0 + kInitialRto);
        CHECK(table.stateOf(key) == TcpState::Established);
        auto after = table.snapshotOf(key);
        CHECK(after.has_value());
        if (after) CHECK(!after->has_rtt_sample);
    }

    // ================= PR #5 fix 3: backoff must never reduce current_rto =================

    // Two outstanding transmissions A (older, front of queue) and B
    // (younger): A times out twice, backing the connection off to 4s. A is
    // then acknowledged (Karn's rule: no sample). B, still carrying its
    // original 1s per-entry interval, then times out once (interval
    // becomes 2s) -- this must NOT reduce the connection's current_rto
    // below the 4s A already established.
    {
        TcpConnectionTable table(8080);
        TcpConnectionKey key{localIp(), 8080, remoteIp(), 54321};
        establish(table, key, 1000, t0); // handshake sample clamps current_rto to kMinRto (1s)

        auto sent_a = table.makeOutgoingData(key, toBytes("AAAA"), t0);
        auto sent_b = table.makeOutgoingData(key, toBytes("BBBB"), t0);
        CHECK(sent_a.segments.size() == 1 && sent_b.segments.size() == 1);
        if (sent_a.segments.size() != 1 || sent_b.segments.size() != 1) {
            return wirestack::test::failureCount() == 0 ? 0 : 1;
        }
        std::uint32_t a_end = sent_a.segments.front().sequence_number +
                               static_cast<std::uint32_t>(sent_a.segments.front().payload.size());

        auto t1 = t0 + kInitialRto; // 1s: A's first timeout
        auto due1 = table.pollRetransmissions(t1);
        CHECK(due1.retransmissions.size() == 1);
        if (due1.retransmissions.size() == 1) {
            CHECK(due1.retransmissions[0].segment.payload == toBytes("AAAA"));
        }
        auto after_first_timeout = table.snapshotOf(key);
        CHECK(after_first_timeout.has_value());
        if (after_first_timeout) CHECK(after_first_timeout->current_rto == std::chrono::milliseconds(2000));

        auto t2 = t1 + std::chrono::milliseconds(2000); // A's second timeout
        auto due2 = table.pollRetransmissions(t2);
        CHECK(due2.retransmissions.size() == 1);
        if (due2.retransmissions.size() == 1) {
            CHECK(due2.retransmissions[0].segment.payload == toBytes("AAAA"));
        }
        auto after_second_timeout = table.snapshotOf(key);
        CHECK(after_second_timeout.has_value());
        if (after_second_timeout) {
            CHECK(after_second_timeout->current_rto == std::chrono::milliseconds(4000));
        }

        // ACK A fully (it was retransmitted twice -- no RTT sample).
        table.handle(key, makeAck(8080, 54321, 1001, a_end), t2);
        auto after_ack_a = table.snapshotOf(key);
        CHECK(after_ack_a.has_value());
        if (after_ack_a) {
            CHECK(after_ack_a->current_rto == std::chrono::milliseconds(4000)); // unchanged
            CHECK(after_ack_a->pending_count == 1); // only B remains
        }

        // B is now the front of the queue; its own timeout_interval is
        // still 1s (never touched by A's backoff) and its deadline
        // (t0 + 1s) has long since passed.
        auto due3 = table.pollRetransmissions(t2);
        CHECK(due3.retransmissions.size() == 1);
        if (due3.retransmissions.size() == 1) {
            CHECK(due3.retransmissions[0].segment.payload == toBytes("BBBB"));
        }
        auto after_b_timeout = table.snapshotOf(key);
        CHECK(after_b_timeout.has_value());
        if (after_b_timeout) {
            // B's own interval only reached 2s, but the connection-level
            // RTO must not regress below A's already-established 4s.
            CHECK(after_b_timeout->current_rto == std::chrono::milliseconds(4000));
        }

        // A later clean RTT sample may still legitimately recalculate and
        // reduce the RTO -- this is not a floor, only a "never regress on
        // timeout" rule.
        std::uint32_t b_end = sent_b.segments.front().sequence_number +
                               static_cast<std::uint32_t>(sent_b.segments.front().payload.size());
        table.handle(key, makeAck(8080, 54321, 1001, b_end), t2); // Karn's rule: B was retransmitted
        auto sent_c = table.makeOutgoingData(key, toBytes("CCCC"), t2);
        CHECK(sent_c.segments.size() == 1);
        if (sent_c.segments.size() == 1) {
            std::uint32_t c_end = sent_c.segments.front().sequence_number +
                                   static_cast<std::uint32_t>(sent_c.segments.front().payload.size());
            auto t3 = t2 + std::chrono::milliseconds(50); // clean, fast RTT sample
            table.handle(key, makeAck(8080, 54321, 1001, c_end), t3);
            auto after_clean_sample = table.snapshotOf(key);
            CHECK(after_clean_sample.has_value());
            if (after_clean_sample) {
                CHECK(after_clean_sample->current_rto < std::chrono::milliseconds(4000));
                CHECK(after_clean_sample->current_rto == kMinRto); // clamped down to the 1s floor
            }
        }
    }

    // ================= PR #5 fix 4: one transmission samples at most once =================

    {
        TcpConnectionTable table(8080);
        TcpConnectionKey key{localIp(), 8080, remoteIp(), 54321};
        establish(table, key, 1000, t0);

        auto sent = table.makeOutgoingData(key, makeFilledPayload(100), t0);
        CHECK(sent.segments.size() == 1);
        if (sent.segments.size() != 1) return wirestack::test::failureCount() == 0 ? 0 : 1;
        std::uint32_t seq_start = sent.segments.front().sequence_number;

        // Partial ACK of the first 40 bytes at T0+200ms: takes the first
        // real sample for this transmission.
        auto t200 = t0 + std::chrono::milliseconds(200);
        table.handle(key, makeAck(8080, 54321, 1001, seq_start + 40), t200);
        auto after_first_sample = table.snapshotOf(key);
        CHECK(after_first_sample.has_value());
        if (after_first_sample) CHECK(after_first_sample->pending_count == 1); // trimmed, not retired

        // Partial ACK of another 30 bytes at T0+500ms: same original
        // transmission, already sampled once -- must not sample again.
        auto t500 = t0 + std::chrono::milliseconds(500);
        table.handle(key, makeAck(8080, 54321, 1001, seq_start + 70), t500);
        auto after_second_partial = table.snapshotOf(key);
        CHECK(after_second_partial.has_value());
        if (after_first_sample && after_second_partial) {
            CHECK(after_second_partial->srtt == after_first_sample->srtt);
            CHECK(after_second_partial->rttvar == after_first_sample->rttvar);
            CHECK(after_second_partial->current_rto == after_first_sample->current_rto);
        }

        // Final ACK of the remaining 30 bytes at T0+800ms fully retires
        // the entry -- still no second sample.
        auto t800 = t0 + std::chrono::milliseconds(800);
        table.handle(key, makeAck(8080, 54321, 1001, seq_start + 100), t800);
        auto after_full_retirement = table.snapshotOf(key);
        CHECK(after_full_retirement.has_value());
        if (after_first_sample && after_full_retirement) {
            CHECK(after_full_retirement->srtt == after_first_sample->srtt);
            CHECK(after_full_retirement->rttvar == after_first_sample->rttvar);
            CHECK(after_full_retirement->current_rto == after_first_sample->current_rto);
            CHECK(after_full_retirement->pending_count == 0);
        }

        // A new, distinct clean transmission may produce the next sample.
        auto clean_sent = table.makeOutgoingData(key, toBytes("fresh"), t800);
        CHECK(clean_sent.segments.size() == 1);
        if (clean_sent.segments.size() == 1) {
            std::uint32_t clean_end =
                clean_sent.segments.front().sequence_number +
                static_cast<std::uint32_t>(clean_sent.segments.front().payload.size());
            auto t850 = t800 + std::chrono::milliseconds(50);
            table.handle(key, makeAck(8080, 54321, 1001, clean_end), t850);
            auto after_new_sample = table.snapshotOf(key);
            CHECK(after_new_sample.has_value());
            if (after_first_sample && after_new_sample) {
                CHECK((after_new_sample->srtt != after_first_sample->srtt) ||
                      (after_new_sample->current_rto != after_first_sample->current_rto));
            }
        }
    }

    // ================= Milestone 12: congestion-control initialization =================

    {
        auto check = [&](std::uint16_t peer_mss, std::uint32_t expected_cwnd) {
            TcpConnectionTable table(8080);
            TcpConnectionKey key{localIp(), 8080, remoteIp(), 54321};
            establishWithPeerMss(table, key, 1000, peer_mss, t0); // handshake ACK acks only the SYN-ACK
            auto snapshot = table.snapshotOf(key);
            CHECK(snapshot.has_value());
            if (snapshot) {
                CHECK(snapshot->cwnd == expected_cwnd);
                CHECK(snapshot->ssthresh == kInitialSsthresh);
                CHECK(snapshot->duplicate_ack_count == 0);
                CHECK(!snapshot->in_fast_recovery);
                CHECK(snapshot->congestion_avoidance_acked_bytes == 0);
            }
        };
        check(1460, 14600);
        check(1200, 12000);
        check(536, 5360);
        check(1, 10);
    }

    // ================= Milestone 12: send-gating tests =================

    // payload exactly fills cwnd_available; one byte more is enqueued but
    // only the allowance's worth is scheduled immediately
    {
        TcpConnectionTable table(8080);
        TcpConnectionKey key{localIp(), 8080, remoteIp(), 54321};
        establish(table, key, 1000, t0); // SMSS 1460 -> cwnd 14600, rwnd 65535
        auto before = table.snapshotOf(key);
        CHECK(before.has_value());

        auto exact = table.makeOutgoingData(key, makeFilledPayload(14600), t0);
        CHECK(exact.segments.size() == 10); // ceil(14600/1460)
        CHECK(exact.bytes_accepted == 14600);
    }
    {
        TcpConnectionTable table(8080);
        TcpConnectionKey key{localIp(), 8080, remoteIp(), 54321};
        establish(table, key, 1000, t0);
        auto before = table.snapshotOf(key);
        CHECK(before.has_value());

        auto over = table.makeOutgoingData(key, makeFilledPayload(14601), t0);
        CHECK(!over.error);
        CHECK(over.bytes_accepted == 14601);
        std::size_t sent_bytes = 0;
        for (const auto& seg : over.segments) sent_bytes += seg.payload.size();
        CHECK(sent_bytes == 14600); // cwnd-limited
        auto after = table.snapshotOf(key);
        CHECK(before.has_value() && after.has_value());
        if (before && after) {
            CHECK(after->snd_nxt == before->snd_nxt + 14600);
            CHECK(after->unsent_bytes == 1);
        }
    }

    // peer window smaller than cwnd: rwnd controls how much is scheduled
    {
        TcpConnectionTable table(8080);
        TcpConnectionKey key{localIp(), 8080, remoteIp(), 54321};
        establishWithWindow(table, key, 1000, 5000, t0); // rwnd=5000 < cwnd=14600
        auto ok = table.makeOutgoingData(key, makeFilledPayload(5000), t0);
        CHECK(ok.bytes_accepted == 5000);
    }
    {
        TcpConnectionTable table(8080);
        TcpConnectionKey key{localIp(), 8080, remoteIp(), 54321};
        establishWithWindow(table, key, 1000, 5000, t0);
        auto sent = table.makeOutgoingData(key, makeFilledPayload(5001), t0);
        CHECK(!sent.error);
        std::size_t sent_bytes = 0;
        for (const auto& seg : sent.segments) sent_bytes += seg.payload.size();
        CHECK(sent_bytes == 5000);
        auto snapshot = table.snapshotOf(key);
        CHECK(snapshot.has_value());
        if (snapshot) CHECK(snapshot->unsent_bytes == 1);
    }

    // cwnd smaller than peer window: cwnd controls how much is scheduled
    {
        TcpConnectionTable table(8080);
        TcpConnectionKey key{localIp(), 8080, remoteIp(), 54321};
        establishWithPeerMss(table, key, 1000, std::uint16_t{200}, t0); // cwnd = 10*200 = 2000
        auto sent = table.makeOutgoingData(key, makeFilledPayload(2001), t0);
        CHECK(!sent.error);
        std::size_t sent_bytes = 0;
        for (const auto& seg : sent.segments) sent_bytes += seg.payload.size();
        CHECK(sent_bytes == 2000);
        auto snapshot = table.snapshotOf(key);
        CHECK(snapshot.has_value());
        if (snapshot) CHECK(snapshot->unsent_bytes == 1);
    }

    // both limits equal: exactly the shared allowance is scheduled
    {
        TcpConnectionTable table(8080);
        TcpConnectionKey key{localIp(), 8080, remoteIp(), 54321};
        establishWithWindow(table, key, 1000, 14600, t0); // rwnd == cwnd == 14600
        auto sent = table.makeOutgoingData(key, makeFilledPayload(14601), t0);
        CHECK(!sent.error);
        std::size_t sent_bytes = 0;
        for (const auto& seg : sent.segments) sent_bytes += seg.payload.size();
        CHECK(sent_bytes == 14600);
        auto snapshot = table.snapshotOf(key);
        CHECK(snapshot.has_value());
        if (snapshot) CHECK(snapshot->unsent_bytes == 1);
    }

    // retransmission remains permitted even with zero new-data allowance
    {
        TcpConnectionTable table(8080);
        TcpConnectionKey key{localIp(), 8080, remoteIp(), 54321};
        establish(table, key, 1000, t0);
        auto sent = table.makeOutgoingData(key, makeFilledPayload(14600), t0); // fills cwnd exactly
        CHECK(sent.bytes_accepted == 14600);
        auto blocked = table.makeOutgoingData(key, toBytes("x"), t0);
        CHECK(!blocked.error); // enqueued into the buffer, just not scheduled yet
        CHECK(blocked.segments.empty());

        auto due = table.pollRetransmissions(t0 + kInitialRto);
        CHECK(due.retransmissions.size() == 1); // still retransmits despite zero availability
    }

    // FIN is deferred behind any still-unsent send-buffer bytes, even
    // when they are unsent only because the congestion window (not the
    // peer window) is exhausted -- FIN never precedes unsent application
    // data in sequence space regardless of which allowance blocked it.
    {
        TcpConnectionTable table(8080);
        TcpConnectionKey key{localIp(), 8080, remoteIp(), 54321};
        establish(table, key, 1000, t0);
        auto sent = table.makeOutgoingData(key, makeFilledPayload(14600), t0); // cwnd exhausted
        CHECK(sent.bytes_accepted == 14600);
        auto blocked = table.makeOutgoingData(key, toBytes("x"), t0);
        CHECK(!blocked.error);
        CHECK(blocked.segments.empty());

        auto close_result = table.beginClose(key, t0); // rwnd (65535) has room, but 1 byte is unsent
        CHECK(close_result.accepted);
        CHECK(!close_result.fin.has_value());

        // Acknowledging the outstanding data reopens cwnd; the same ACK
        // schedules both the queued byte and the now-eligible FIN.
        auto snapshot = table.snapshotOf(key);
        CHECK(snapshot.has_value());
        if (snapshot) {
            auto ack_result = table.handle(key, makeAck(8080, 54321, 1001, snapshot->snd_nxt), t0);
            bool saw_fin = false;
            for (const auto& seg : ack_result.scheduled) {
                if (seg.flags.fin) saw_fin = true;
            }
            CHECK(saw_fin);
        }
    }

    // wraparound flight-size calculation
    {
        TcpConnectionTable table(8080);
        TcpConnectionKey key{localIp(), 8080, remoteIp(), 54321};
        establish(table, key, 0xffffffff - 10, t0); // crosses the sequence-number boundary
        auto sent = table.makeOutgoingData(key, toBytes("abcdefghij"), t0);
        CHECK(sent.bytes_accepted == 10);
        auto snapshot = table.snapshotOf(key);
        CHECK(snapshot.has_value());
        if (snapshot) {
            CHECK(snapshot->cwnd >= 10); // congestion window still computed correctly across the wrap
        }
    }

    // ================= Milestone 12: Slow Start tests =================

    // exact vector: SMSS 1460 -> cwnd 14600 -> ACK full segment -> 16060 -> ACK another -> 17520
    {
        TcpConnectionTable table(8080);
        TcpConnectionKey key{localIp(), 8080, remoteIp(), 54321};
        establish(table, key, 1000, t0);
        auto snap0 = table.snapshotOf(key);
        CHECK(snap0.has_value());
        if (snap0) CHECK(snap0->cwnd == 14600);

        auto sent1 = table.makeOutgoingData(key, makeFilledPayload(1460), t0);
        CHECK(sent1.segments.size() == 1);
        table.handle(key, makeAck(8080, 54321, 1001,
                                   sent1.segments.front().sequence_number + 1460),
                     t0);
        auto snap1 = table.snapshotOf(key);
        CHECK(snap1.has_value());
        if (snap1) CHECK(snap1->cwnd == 16060);

        auto sent2 = table.makeOutgoingData(key, makeFilledPayload(1460), t0);
        CHECK(sent2.segments.size() == 1);
        table.handle(key, makeAck(8080, 54321, 1001,
                                   sent2.segments.front().sequence_number + 1460),
                     t0);
        auto snap2 = table.snapshotOf(key);
        CHECK(snap2.has_value());
        if (snap2) CHECK(snap2->cwnd == 17520);
    }

    // one partial-MSS ACK grows cwnd by exactly the acked bytes
    {
        TcpConnectionTable table(8080);
        TcpConnectionKey key{localIp(), 8080, remoteIp(), 54321};
        establish(table, key, 1000, t0);
        auto sent = table.makeOutgoingData(key, makeFilledPayload(500), t0);
        CHECK(sent.segments.size() == 1);
        table.handle(key, makeAck(8080, 54321, 1001, sent.segments.front().sequence_number + 500),
                     t0);
        auto snapshot = table.snapshotOf(key);
        CHECK(snapshot.has_value());
        if (snapshot) CHECK(snapshot->cwnd == 14600 + 500);
    }

    // a cumulative ACK covering more than one MSS grows cwnd by at most one MSS
    {
        TcpConnectionTable table(8080);
        TcpConnectionKey key{localIp(), 8080, remoteIp(), 54321};
        establishWithWindow(table, key, 1000, 65535, t0);
        auto sent = table.makeOutgoingData(key, makeFilledPayload(3 * 1460), t0);
        CHECK(sent.segments.size() == 3);
        // One cumulative ACK covering all three segments (4380 bytes).
        table.handle(key, makeAck(8080, 54321, 1001,
                                   sent.segments.back().sequence_number +
                                       static_cast<std::uint32_t>(sent.segments.back().payload.size())),
                     t0);
        auto snapshot = table.snapshotOf(key);
        CHECK(snapshot.has_value());
        if (snapshot) CHECK(snapshot->cwnd == 14600 + 1460); // capped to one SMSS, not 4380
    }

    // ACK of FIN alone does not grow cwnd
    {
        TcpConnectionTable table(8080);
        TcpConnectionKey key{localIp(), 8080, remoteIp(), 54321};
        establish(table, key, 1000, t0);
        auto fin_result = table.beginClose(key, t0);
        auto fin = fin_result.fin;
        CHECK(fin.has_value());
        auto before = table.snapshotOf(key);
        CHECK(before.has_value());
        if (fin) {
            table.handle(key, makeAck(8080, 54321, 1001, fin->sequence_number + 1), t0);
        }
        auto after = table.snapshotOf(key);
        CHECK(before.has_value() && after.has_value());
        if (before && after) CHECK(after->cwnd == before->cwnd);
    }

    // a duplicate (non-advancing) ACK does not use Slow Start growth
    {
        TcpConnectionTable table(8080);
        TcpConnectionKey key{localIp(), 8080, remoteIp(), 54321};
        establish(table, key, 1000, t0);
        auto sent = table.makeOutgoingData(key, makeFilledPayload(1460), t0);
        CHECK(sent.segments.size() == 1);
        auto before = table.snapshotOf(key);
        CHECK(before.has_value());
        table.handle(key, makeAck(8080, 54321, 1001, sent.segments.front().sequence_number), t0);
        table.handle(key, makeAck(8080, 54321, 1001, sent.segments.front().sequence_number), t0);
        auto after = table.snapshotOf(key);
        CHECK(before.has_value() && after.has_value());
        if (before && after) CHECK(after->cwnd == before->cwnd);
    }

    // crossing ssthresh: a timeout sets a small ssthresh, then one ACK's Slow
    // Start growth lands cwnd exactly on it, and the NEXT ACK uses
    // Congestion Avoidance instead (no growth, since it acked less than one
    // full cwnd) -- proving the two growth rules are never both applied to
    // the same acknowledged bytes.
    {
        TcpConnectionTable table(8080);
        TcpConnectionKey key{localIp(), 8080, remoteIp(), 54321};
        establishWithWindow(table, key, 1000, 65535, t0);
        auto lost = table.makeOutgoingData(key, makeFilledPayload(3000), t0); // flight = 3000
        CHECK(!lost.segments.empty());
        auto due = table.pollRetransmissions(t0 + kInitialRto); // timeout collapse
        CHECK(due.retransmissions.size() == 1);
        auto after_timeout = table.snapshotOf(key);
        CHECK(after_timeout.has_value());
        if (after_timeout) {
            CHECK(after_timeout->ssthresh == 2920); // max(3000/2, 2*1460)
            CHECK(after_timeout->cwnd == 1460);      // SMSS
        }

        auto t1 = t0 + kInitialRto;
        // Free the still-outstanding original 3000 bytes (Karn's rule
        // prevents a sample from this retransmitted flight) before
        // sending new data. This ACK itself is Slow Start's growth step
        // (cwnd 1460 < ssthresh 2920): increase = min(3000, 1460) = 1460,
        // landing cwnd exactly on ssthresh (2920) -- the boundary.
        table.handle(key, makeAck(8080, 54321, 1001,
                                   lost.segments.back().sequence_number +
                                       static_cast<std::uint32_t>(
                                           lost.segments.back().payload.size())),
                     t1);
        auto snap0 = table.snapshotOf(key);
        CHECK(snap0.has_value());
        if (snap0) CHECK(snap0->cwnd == 2920); // == ssthresh exactly, one SS step only

        // The next ACK, for new data, now uses Congestion Avoidance
        // instead: it acked less than one full cwnd (1460 < 2920), so no
        // growth yet -- proving Slow Start and Congestion Avoidance were
        // never both applied to the same acknowledged bytes.
        auto sent1 = table.makeOutgoingData(key, makeFilledPayload(1460), t1);
        CHECK(sent1.segments.size() == 1);
        if (sent1.segments.size() != 1) return wirestack::test::failureCount() == 0 ? 0 : 1;
        table.handle(key, makeAck(8080, 54321, 1001,
                                   sent1.segments.front().sequence_number + 1460),
                     t1);
        auto snap1 = table.snapshotOf(key);
        CHECK(snap1.has_value());
        if (snap1) {
            CHECK(snap1->cwnd == 2920); // Congestion Avoidance: 1460 < cwnd(2920), no growth yet
            CHECK(snap1->congestion_avoidance_acked_bytes == 1460);
        }
    }

    // ================= Milestone 12: Congestion Avoidance tests =================

    {
        // Enter Congestion Avoidance directly by starting from a timeout
        // that sets ssthresh == cwnd's next value (see boundary test
        // above for the crossing itself); here cwnd == ssthresh == 2920
        // from the outset.
        TcpConnectionTable table(8080);
        TcpConnectionKey key{localIp(), 8080, remoteIp(), 54321};
        establishWithWindow(table, key, 1000, 65535, t0);
        auto lost = table.makeOutgoingData(key, makeFilledPayload(5840), t0); // flight = 5840
        CHECK(!lost.segments.empty());
        table.pollRetransmissions(t0 + kInitialRto); // ssthresh = max(2920,2920) = 2920, cwnd = 1460
        auto t1 = t0 + kInitialRto;
        // Acknowledging the still-outstanding original flight both frees
        // it for new sends and is itself the Slow Start step that lands
        // cwnd exactly on ssthresh: increase = min(5840, 1460) = 1460.
        table.handle(key, makeAck(8080, 54321, 1001,
                                   lost.segments.back().sequence_number +
                                       static_cast<std::uint32_t>(
                                           lost.segments.back().payload.size())),
                     t1);
        auto snap = table.snapshotOf(key);
        CHECK(snap.has_value());
        if (snap) CHECK(snap->cwnd == 2920 && snap->ssthresh == 2920); // now in CA

        // No growth before one cwnd (2920) of data is acknowledged.
        auto s1 = table.makeOutgoingData(key, makeFilledPayload(1000), t1);
        CHECK(s1.segments.size() == 1);
        table.handle(key, makeAck(8080, 54321, 1001, s1.segments.front().sequence_number + 1000), t1);
        auto snap_partial = table.snapshotOf(key);
        CHECK(snap_partial.has_value());
        if (snap_partial) {
            CHECK(snap_partial->cwnd == 2920);
            CHECK(snap_partial->congestion_avoidance_acked_bytes == 1000);
        }

        // Exact threshold (2920 total, 1920 more) produces exactly one
        // SMSS of growth and resets the accumulator.
        auto s2 = table.makeOutgoingData(key, makeFilledPayload(1920), t1);
        CHECK(s2.segments.size() == 2); // 1460 + 460
        table.handle(key, makeAck(8080, 54321, 1001, s2.segments.back().sequence_number +
                                                           static_cast<std::uint32_t>(
                                                               s2.segments.back().payload.size())),
                     t1);
        auto snap_threshold = table.snapshotOf(key);
        CHECK(snap_threshold.has_value());
        if (snap_threshold) {
            CHECK(snap_threshold->cwnd == 2920 + 1460);
            CHECK(snap_threshold->congestion_avoidance_acked_bytes == 0);
        }

        // A large cumulative ACK filling the entire current window in one
        // shot still produces exactly the correct growth (one SMSS) and
        // an exactly-zero remainder, safely -- the "repeat while the
        // accumulator still reaches cwnd" loop is exercised the same way
        // it would be for a multi-window jump, just with a single
        // crossing here: since every legitimate atomic send is itself
        // gated by the current cwnd (see "New application-data allowance"
        // in docs/tcp.md), one ACK can never newly-acknowledge more than
        // one window's worth of data under ordinary operation, so a
        // literal multi-threshold single-ACK crossing is not organically
        // reachable through the public send/ack API -- documented as a
        // structural, not tested, consequence of correct cwnd gating.
        auto s3 = table.makeOutgoingData(key, makeFilledPayload(4380), t1); // exactly cwnd
        CHECK(s3.segments.size() == 3);
        if (s3.segments.empty()) return wirestack::test::failureCount() == 0 ? 0 : 1;
        table.handle(key, makeAck(8080, 54321, 1001,
                                   s3.segments.back().sequence_number +
                                       static_cast<std::uint32_t>(s3.segments.back().payload.size())),
                     t1);
        auto snap_large = table.snapshotOf(key);
        CHECK(snap_large.has_value());
        if (snap_large) {
            CHECK(snap_large->cwnd == 4380 + 1460); // 5840
            CHECK(snap_large->congestion_avoidance_acked_bytes == 0);
        }
    }

    // loss resets the accumulator
    {
        TcpConnectionTable table(8080);
        TcpConnectionKey key{localIp(), 8080, remoteIp(), 54321};
        establishWithWindow(table, key, 1000, 65535, t0);
        auto lost = table.makeOutgoingData(key, makeFilledPayload(5840), t0);
        CHECK(!lost.segments.empty());
        table.pollRetransmissions(t0 + kInitialRto); // ssthresh=2920, cwnd=1460
        auto t1 = t0 + kInitialRto;
        // Frees flight and is itself the Slow Start step landing cwnd on
        // ssthresh (2920), same as the Congestion Avoidance test above.
        table.handle(key, makeAck(8080, 54321, 1001,
                                   lost.segments.back().sequence_number +
                                       static_cast<std::uint32_t>(
                                           lost.segments.back().payload.size())),
                     t1);
        auto s1 = table.makeOutgoingData(key, makeFilledPayload(1000), t1); // partial CA credit
        CHECK(s1.segments.size() == 1);
        if (s1.segments.size() != 1) return wirestack::test::failureCount() == 0 ? 0 : 1;
        table.handle(key, makeAck(8080, 54321, 1001, s1.segments.front().sequence_number + 1000), t1);
        auto before_loss = table.snapshotOf(key);
        CHECK(before_loss.has_value());
        if (before_loss) CHECK(before_loss->congestion_avoidance_acked_bytes == 1000);

        auto more = table.makeOutgoingData(key, makeFilledPayload(1460), t1);
        CHECK(more.segments.size() == 1);
        auto due2 = table.pollRetransmissions(t1 + before_loss->current_rto);
        CHECK(due2.retransmissions.size() == 1);
        auto after_loss = table.snapshotOf(key);
        CHECK(after_loss.has_value());
        if (after_loss) CHECK(after_loss->congestion_avoidance_acked_bytes == 0);
    }

    // ================= Milestone 12: duplicate-ACK classification =================

    {
        TcpConnectionTable table(8080);
        TcpConnectionKey key{localIp(), 8080, remoteIp(), 54321};
        std::uint32_t server_isn = establish(table, key, 1000, t0);
        auto sent = table.makeOutgoingData(key, makeFilledPayload(1460), t0);
        CHECK(sent.segments.size() == 1);
        std::uint32_t seq = sent.segments.front().sequence_number;

        // first and second duplicate: count increases, no other effect
        table.handle(key, makeAck(8080, 54321, 1001, seq), t0);
        auto after1 = table.snapshotOf(key);
        CHECK(after1.has_value());
        if (after1) CHECK(after1->duplicate_ack_count == 1);

        table.handle(key, makeAck(8080, 54321, 1001, seq), t0);
        auto after2 = table.snapshotOf(key);
        CHECK(after2.has_value());
        if (after2) {
            CHECK(after2->duplicate_ack_count == 2);
            CHECK(!after2->in_fast_recovery);
        }

        // future ACK (beyond snd_nxt) is dropped entirely, count untouched
        auto future_result =
            table.handle(key, makeAck(8080, 54321, 1001, after2->snd_nxt + 100000), t0);
        CHECK(!future_result.reply.has_value());
        auto after_future = table.snapshotOf(key);
        CHECK(after_future.has_value());
        if (after_future) CHECK(after_future->duplicate_ack_count == 2);

        // stale ACK (below snd_una, i.e. below the connection's ISN+1) is
        // simply not equal to snd_una -- not counted, and not a reset
        // trigger either.
        auto stale = makeAck(8080, 54321, 1001, server_isn); // < snd_una
        table.handle(key, stale, t0);
        auto after_stale = table.snapshotOf(key);
        CHECK(after_stale.has_value());
        if (after_stale) CHECK(after_stale->duplicate_ack_count == 2);

        // ACK carrying data is excluded from duplicate counting
        auto with_data = makeData(8080, 54321, 1001, seq, toBytes("x"));
        table.handle(key, with_data, t0);
        auto after_data = table.snapshotOf(key);
        CHECK(after_data.has_value());
        if (after_data) CHECK(after_data->duplicate_ack_count == 2);

        // FIN|ACK is excluded from duplicate counting
        auto fin_ack = makeAck(8080, 54321, 1001, seq);
        fin_ack.flags.fin = true;
        table.handle(key, fin_ack, t0);
        auto after_fin = table.snapshotOf(key);
        CHECK(after_fin.has_value());
        if (after_fin) CHECK(after_fin->duplicate_ack_count == 2);

        // SYN|ACK is dropped entirely in a synchronized state
        auto syn_ack = makeAck(8080, 54321, 1001, seq);
        syn_ack.flags.syn = true;
        auto syn_ack_result = table.handle(key, syn_ack, t0);
        CHECK(!syn_ack_result.reply.has_value());
        auto after_syn = table.snapshotOf(key);
        CHECK(after_syn.has_value());
        if (after_syn) CHECK(after_syn->duplicate_ack_count == 2);

        // an unacceptable RST (wrong sequence number) changes nothing
        auto bad_rst = makeRst(8080, 54321, 1001);
        table.handle(key, bad_rst, t0);
        auto after_rst = table.snapshotOf(key);
        CHECK(after_rst.has_value());
        if (after_rst) CHECK(after_rst->duplicate_ack_count == 2);

        // a changed advertised window disqualifies AND resets the count
        auto window_update = makeWindowUpdate(8080, 54321, 1001, seq, 40000);
        table.handle(key, window_update, t0);
        auto after_window = table.snapshotOf(key);
        CHECK(after_window.has_value());
        if (after_window) CHECK(after_window->duplicate_ack_count == 0);

        // Restore the window to the 65535 that plain makeAck() advertises,
        // so the remaining duplicate ACKs below don't themselves register
        // as window changes against the just-updated 40000.
        table.handle(key, makeWindowUpdate(8080, 54321, 1001, seq, 65535), t0);

        // third qualifying duplicate (fresh count from here) triggers fast retransmit
        table.handle(key, makeAck(8080, 54321, 1001, seq), t0);
        table.handle(key, makeAck(8080, 54321, 1001, seq), t0);
        auto third = table.handle(key, makeAck(8080, 54321, 1001, seq), t0);
        CHECK(third.fast_retransmit.has_value());
        auto after_third = table.snapshotOf(key);
        CHECK(after_third.has_value());
        if (after_third) CHECK(after_third->in_fast_recovery);

        // an advancing ACK resets the count (and exits recovery)
        table.handle(key, makeAck(8080, 54321, 1001, seq + 1460), t0);
        auto after_advance = table.snapshotOf(key);
        CHECK(after_advance.has_value());
        if (after_advance) {
            CHECK(after_advance->duplicate_ack_count == 0);
            CHECK(!after_advance->in_fast_recovery);
        }
    }

    // no outstanding data: a duplicate-looking ACK after the queue is
    // fully drained does not count
    {
        TcpConnectionTable table(8080);
        TcpConnectionKey key{localIp(), 8080, remoteIp(), 54321};
        establish(table, key, 1000, t0);
        auto sent = table.makeOutgoingData(key, makeFilledPayload(100), t0);
        CHECK(sent.segments.size() == 1);
        table.handle(key, makeAck(8080, 54321, 1001, sent.segments.front().sequence_number + 100),
                     t0); // fully drains the queue
        auto drained = table.snapshotOf(key);
        CHECK(drained.has_value());
        if (drained) CHECK(drained->pending_count == 0);

        table.handle(key, makeAck(8080, 54321, 1001, sent.segments.front().sequence_number + 100),
                     t0); // ack == snd_una, but nothing outstanding
        auto after = table.snapshotOf(key);
        CHECK(after.has_value());
        if (after) CHECK(after->duplicate_ack_count == 0);
    }

    // ACK for an outstanding FIN but no outstanding data does not count
    {
        TcpConnectionTable table(8080);
        TcpConnectionKey key{localIp(), 8080, remoteIp(), 54321};
        establish(table, key, 1000, t0);
        auto fin_result = table.beginClose(key, t0);
        auto fin = fin_result.fin;
        CHECK(fin.has_value());
        auto before = table.snapshotOf(key);
        CHECK(before.has_value());
        if (before) CHECK(before->pending_count == 1); // only the FIN is outstanding

        table.handle(key, makeAck(8080, 54321, 1001, before->snd_una), t0); // ack == snd_una
        auto after = table.snapshotOf(key);
        CHECK(after.has_value());
        if (after) CHECK(after->duplicate_ack_count == 0);
    }

    // ================= Milestone 12: fast retransmit and fast recovery =================

    {
        TcpConnectionTable table(8080);
        TcpConnectionKey key{localIp(), 8080, remoteIp(), 54321};
        establishWithWindow(table, key, 1000, 65535, t0);

        std::vector<TcpSegment> sent_segments;
        for (int i = 0; i < 5; ++i) {
            auto sent = table.makeOutgoingData(key, makeFilledPayload(1460), t0);
            CHECK(sent.segments.size() == 1);
            if (sent.segments.size() == 1) sent_segments.push_back(sent.segments.front());
        }
        CHECK(sent_segments.size() == 5);
        if (sent_segments.size() != 5) return wirestack::test::failureCount() == 0 ? 0 : 1;

        std::uint32_t seg2_seq = sent_segments[1].sequence_number;
        auto seg2_payload = sent_segments[1].payload;
        auto before_snd_nxt = table.snapshotOf(key);
        CHECK(before_snd_nxt.has_value());

        // Segment 1 acknowledged (advances snd_una to the start of segment 2).
        table.handle(key, makeAck(8080, 54321, 1001, seg2_seq), t0);

        // Segments 3, 4, 5 arrive out of order behind the missing segment 2:
        // three duplicate ACKs, each still acknowledging up to seg2_seq.
        auto dup1 = table.handle(key, makeAck(8080, 54321, 1001, seg2_seq), t0);
        CHECK(!dup1.fast_retransmit.has_value());
        auto dup2 = table.handle(key, makeAck(8080, 54321, 1001, seg2_seq), t0);
        CHECK(!dup2.fast_retransmit.has_value());
        auto dup3 = table.handle(key, makeAck(8080, 54321, 1001, seg2_seq), t0);
        CHECK(dup3.fast_retransmit.has_value());

        if (dup3.fast_retransmit) {
            CHECK(dup3.fast_retransmit->sequence_number == seg2_seq);
            CHECK(dup3.fast_retransmit->payload == seg2_payload);
            CHECK(dup3.fast_retransmit->flags.ack);
        }

        auto after_fr = table.snapshotOf(key);
        CHECK(after_fr.has_value());
        if (after_fr && before_snd_nxt) {
            CHECK(after_fr->snd_nxt == before_snd_nxt->snd_nxt); // unchanged
            CHECK(after_fr->snd_una == seg2_seq);                // unchanged by the dup ACKs
            // flight at the moment of the 3rd duplicate = 4 segments still
            // outstanding (2,3,4,5) = 5840; ssthresh = max(2920,2920).
            CHECK(after_fr->ssthresh == 2920);
            CHECK(after_fr->cwnd == 2920 + 3 * 1460);
            CHECK(after_fr->in_fast_recovery);
            CHECK(after_fr->recovery_point == after_fr->snd_nxt);
        }

        // The retransmitted entry's deadline was only refreshed, not
        // doubled: it is due again after exactly one more kInitialRto
        // from t0 (since it was never previously retransmitted).
        auto immediate_poll = table.pollRetransmissions(t0);
        CHECK(immediate_poll.retransmissions.empty());

        // Duplicate ACK 4: inflates cwnd by one SMSS, no additional retransmission.
        auto dup4 = table.handle(key, makeAck(8080, 54321, 1001, seg2_seq), t0);
        CHECK(!dup4.fast_retransmit.has_value());
        auto after_dup4 = table.snapshotOf(key);
        CHECK(after_dup4.has_value());
        if (after_dup4 && after_fr) CHECK(after_dup4->cwnd == after_fr->cwnd + 1460);
    }

    // recovery exit: a valid cumulative ACK covering everything
    {
        TcpConnectionTable table(8080);
        TcpConnectionKey key{localIp(), 8080, remoteIp(), 54321};
        establishWithWindow(table, key, 1000, 65535, t0);

        std::vector<TcpSegment> sent_segments;
        for (int i = 0; i < 5; ++i) {
            auto sent = table.makeOutgoingData(key, makeFilledPayload(1460), t0);
            if (sent.segments.size() == 1) sent_segments.push_back(sent.segments.front());
        }
        CHECK(sent_segments.size() == 5);
        if (sent_segments.size() != 5) return wirestack::test::failureCount() == 0 ? 0 : 1;
        std::uint32_t seg2_seq = sent_segments[1].sequence_number;

        table.handle(key, makeAck(8080, 54321, 1001, seg2_seq), t0);
        table.handle(key, makeAck(8080, 54321, 1001, seg2_seq), t0);
        table.handle(key, makeAck(8080, 54321, 1001, seg2_seq), t0);
        auto dup3 = table.handle(key, makeAck(8080, 54321, 1001, seg2_seq), t0);
        CHECK(dup3.fast_retransmit.has_value());
        auto recovering = table.snapshotOf(key);
        CHECK(recovering.has_value());
        std::uint32_t recovery_ssthresh = recovering ? recovering->ssthresh : 0;

        auto final_ack = table.handle(
            key, makeAck(8080, 54321, 1001, recovering ? recovering->snd_nxt : 0),
            t0 + std::chrono::milliseconds(50));
        CHECK(!final_ack.reply.has_value());
        auto after_exit = table.snapshotOf(key);
        CHECK(after_exit.has_value());
        if (after_exit) {
            CHECK(after_exit->cwnd == recovery_ssthresh);
            CHECK(!after_exit->in_fast_recovery);
            CHECK(after_exit->duplicate_ack_count == 0);
            CHECK(after_exit->congestion_avoidance_acked_bytes == 0);
            CHECK(after_exit->pending_count == 0);
        }
    }

    // NewReno partial-ACK recovery: an advancing ACK below recovery_point
    // remains in fast recovery, deflates cwnd, and retransmits one further
    // eligible entry rather than exiting immediately (see docs/tcp.md).
    {
        TcpConnectionTable table(8080);
        TcpConnectionKey key{localIp(), 8080, remoteIp(), 54321};
        establishWithWindow(table, key, 1000, 65535, t0);

        std::vector<TcpSegment> sent_segments;
        for (int i = 0; i < 3; ++i) {
            auto sent = table.makeOutgoingData(key, makeFilledPayload(1460), t0);
            if (sent.segments.size() == 1) sent_segments.push_back(sent.segments.front());
        }
        CHECK(sent_segments.size() == 3);
        if (sent_segments.size() != 3) return wirestack::test::failureCount() == 0 ? 0 : 1;
        std::uint32_t seg2_seq = sent_segments[1].sequence_number;
        std::uint32_t seg3_seq = sent_segments[2].sequence_number;

        table.handle(key, makeAck(8080, 54321, 1001, seg2_seq), t0);
        table.handle(key, makeAck(8080, 54321, 1001, seg2_seq), t0);
        table.handle(key, makeAck(8080, 54321, 1001, seg2_seq), t0);
        auto dup3 = table.handle(key, makeAck(8080, 54321, 1001, seg2_seq), t0);
        CHECK(dup3.fast_retransmit.has_value());
        auto recovering = table.snapshotOf(key);
        CHECK(recovering.has_value());
        if (recovering) CHECK(recovering->recovery_point > seg3_seq); // recovery_point == snd_nxt
        std::uint32_t cwnd_before_partial = recovering ? recovering->cwnd : 0;

        // Only acknowledges segment 2 (retransmitted), leaving segment 3
        // still outstanding and below recovery_point: a NewReno partial
        // ACK, not a full one.
        auto partial = table.handle(key, makeAck(8080, 54321, 1001, seg3_seq), t0);
        CHECK(partial.fast_retransmit.has_value()); // retransmits segment 3
        if (partial.fast_retransmit) {
            CHECK(partial.fast_retransmit->sequence_number == seg3_seq);
        }
        auto after_partial = table.snapshotOf(key);
        CHECK(after_partial.has_value());
        if (after_partial) {
            CHECK(after_partial->in_fast_recovery); // remains in recovery, below recovery_point
            CHECK(after_partial->duplicate_ack_count == 0);
            CHECK(after_partial->pending_count == 1); // segment 3 remains queued
            std::uint32_t newly_acked = seg3_seq - seg2_seq; // 1460
            std::uint32_t expected =
                std::max<std::uint32_t>(cwnd_before_partial - newly_acked, 1460) + 1460;
            CHECK(after_partial->cwnd == expected);
        }

        // Cumulative ACK reaches recovery_point: full ACK, exit recovery.
        auto final_ack = table.handle(
            key, makeAck(8080, 54321, 1001, recovering ? recovering->recovery_point : 0), t0);
        auto after_exit = table.snapshotOf(key);
        CHECK(after_exit.has_value());
        if (after_exit) {
            CHECK(!after_exit->in_fast_recovery);
            CHECK(after_exit->pending_count == 0);
        }
    }

    // ================= Milestone 12: timeout congestion collapse =================

    {
        TcpConnectionTable table(8080);
        TcpConnectionKey key{localIp(), 8080, remoteIp(), 54321};
        establishWithWindow(table, key, 1000, 65535, t0);
        auto sent = table.makeOutgoingData(key, makeFilledPayload(3000), t0); // flight = 3000
        CHECK(!sent.segments.empty());

        auto due = table.pollRetransmissions(t0 + kInitialRto);
        CHECK(due.retransmissions.size() == 1);
        auto after = table.snapshotOf(key);
        CHECK(after.has_value());
        if (after) {
            CHECK(after->ssthresh == 2920); // max(3000/2, 2*1460) = max(1500,2920)
            CHECK(after->cwnd == 1460);      // SMSS
            CHECK(!after->in_fast_recovery);
            CHECK(after->duplicate_ack_count == 0);
            CHECK(after->congestion_avoidance_acked_bytes == 0);
        }

        // A second poll at the same instant must not collapse a second time.
        auto due_again = table.pollRetransmissions(t0 + kInitialRto);
        CHECK(due_again.retransmissions.empty());
        auto after_again = table.snapshotOf(key);
        CHECK(after_again.has_value());
        if (after_again && after) {
            CHECK(after_again->ssthresh == after->ssthresh);
            CHECK(after_again->cwnd == after->cwnd);
        }
    }

    // SYN-ACK timeout does not collapse application-data congestion state
    {
        TcpConnectionTable table(8080);
        TcpConnectionKey key{localIp(), 8080, remoteIp(), 54321};
        table.handle(key, makeSyn(8080, 54321, 1000), t0);
        auto before = table.snapshotOf(key);
        CHECK(before.has_value());

        auto due = table.pollRetransmissions(t0 + kInitialRto);
        CHECK(due.retransmissions.size() == 1);
        auto after = table.snapshotOf(key);
        CHECK(before.has_value() && after.has_value());
        if (before && after) {
            CHECK(after->cwnd == before->cwnd);
            CHECK(after->ssthresh == before->ssthresh);
        }
    }

    // FIN timeout does not collapse application-data congestion state
    {
        TcpConnectionTable table(8080);
        TcpConnectionKey key{localIp(), 8080, remoteIp(), 54321};
        establish(table, key, 1000, t0);
        auto fin_result = table.beginClose(key, t0);
        auto fin = fin_result.fin;
        CHECK(fin.has_value());
        auto before = table.snapshotOf(key);
        CHECK(before.has_value());

        auto due = before ? table.pollRetransmissions(t0 + before->current_rto)
                           : wirestack::TcpTimeoutPollResult{};
        CHECK(due.retransmissions.size() == 1);
        auto after = table.snapshotOf(key);
        CHECK(before.has_value() && after.has_value());
        if (before && after) {
            CHECK(after->cwnd == before->cwnd);
            CHECK(after->ssthresh == before->ssthresh);
        }
    }

    // ================= Milestone 12: Karn's rule regression =================

    // fast-retransmitted data produces no RTT sample; fast retransmit does
    // not consume the timeout retry budget
    {
        TcpConnectionTable table(8080);
        TcpConnectionKey key{localIp(), 8080, remoteIp(), 54321};
        establish(table, key, 1000, t0);
        auto sent = table.makeOutgoingData(key, makeFilledPayload(1460), t0);
        CHECK(sent.segments.size() == 1);
        std::uint32_t seq = sent.segments.front().sequence_number;

        table.handle(key, makeAck(8080, 54321, 1001, seq), t0);
        table.handle(key, makeAck(8080, 54321, 1001, seq), t0);
        auto dup3 = table.handle(key, makeAck(8080, 54321, 1001, seq), t0);
        CHECK(dup3.fast_retransmit.has_value());

        auto before_ack = table.snapshotOf(key);
        CHECK(before_ack.has_value());
        table.handle(key, makeAck(8080, 54321, 1001, seq + 1460),
                     t0 + std::chrono::milliseconds(500));
        auto after_ack = table.snapshotOf(key);
        CHECK(before_ack.has_value() && after_ack.has_value());
        if (before_ack && after_ack) {
            CHECK(after_ack->srtt == before_ack->srtt);
            CHECK(after_ack->rttvar == before_ack->rttvar);
            CHECK(after_ack->pending_count == 0);
        }

        // The fast-retransmitted entry's timeout was never doubled or
        // consumed: this same entry, if it had gone on to time out, would
        // still be retry #0 -- demonstrated separately below since this
        // entry is already retired here.
    }

    // fast retransmit does not consume the timeout retry budget: the same
    // entry can still legitimately time out afterward, starting from
    // timeout-retry zero
    {
        TcpConnectionTable table(8080);
        TcpConnectionKey key{localIp(), 8080, remoteIp(), 54321};
        establish(table, key, 1000, t0);
        auto sent = table.makeOutgoingData(key, makeFilledPayload(1460), t0);
        CHECK(sent.segments.size() == 1);
        std::uint32_t seq = sent.segments.front().sequence_number;

        table.handle(key, makeAck(8080, 54321, 1001, seq), t0);
        table.handle(key, makeAck(8080, 54321, 1001, seq), t0);
        auto dup3 = table.handle(key, makeAck(8080, 54321, 1001, seq), t0);
        CHECK(dup3.fast_retransmit.has_value());

        // The entry's own timeout_interval was untouched by the fast
        // retransmission (still kInitialRto), and last_sent_at was reset
        // to t0 -- it becomes due again at t0 + kInitialRto, not sooner
        // (not doubled) and not later (RTO not otherwise changed).
        auto early = table.pollRetransmissions(t0 + kInitialRto - std::chrono::milliseconds(1));
        CHECK(early.retransmissions.empty());
        auto due = table.pollRetransmissions(t0 + kInitialRto);
        CHECK(due.retransmissions.size() == 1); // genuine timeout retry #1 for this entry

        // Free the still-outstanding (timed-out, congestion-collapsed)
        // original entry before sending new data -- this ACK also carries
        // no RTT sample (Karn's rule: was_retransmitted from the timeout).
        auto t1 = t0 + kInitialRto;
        table.handle(key, makeAck(8080, 54321, 1001, seq + 1460), t1);

        // A later, different, never-retransmitted transmission can still
        // update RTT normally.
        auto clean = table.makeOutgoingData(key, makeFilledPayload(200), t1);
        CHECK(clean.segments.size() == 1);
        auto before_clean_ack = table.snapshotOf(key);
        CHECK(before_clean_ack.has_value());
        table.handle(key, makeAck(8080, 54321, 1001, clean.segments.front().sequence_number + 200),
                     t1 + std::chrono::milliseconds(100));
        auto after_clean_ack = table.snapshotOf(key);
        CHECK(before_clean_ack.has_value() && after_clean_ack.has_value());
        if (before_clean_ack && after_clean_ack) {
            CHECK((after_clean_ack->srtt != before_clean_ack->srtt) ||
                  (after_clean_ack->current_rto != before_clean_ack->current_rto));
        }
    }

    // ================= Milestone 13: send-buffer capacity =================

    // exact-capacity enqueue accepted (across multiple calls, each capped
    // at kMaxApplicationSendSize); one byte beyond is rejected atomically,
    // with capacity unchanged
    {
        TcpConnectionTable table(8080);
        TcpConnectionKey key{localIp(), 8080, remoteIp(), 54321};
        establishWithWindow(table, key, 1000, 0, t0); // zero rwnd: nothing ever scheduled
        std::size_t remaining = kTcpSendBufferCapacity;
        while (remaining > 0) {
            std::size_t chunk = std::min(remaining, kMaxApplicationSendSize);
            auto sent = table.makeOutgoingData(key, makeFilledPayload(chunk), t0);
            CHECK(!sent.error);
            remaining -= chunk;
        }
        auto snapshot = table.snapshotOf(key);
        CHECK(snapshot.has_value());
        if (snapshot) CHECK(snapshot->owned_bytes == kTcpSendBufferCapacity);

        auto over = table.makeOutgoingData(key, toBytes("x"), t0);
        CHECK(over.error == TcpSendError::BufferFull);
        CHECK(over.bytes_accepted == 0);
        auto after = table.snapshotOf(key);
        CHECK(after.has_value());
        if (after) CHECK(after->owned_bytes == kTcpSendBufferCapacity); // unchanged
    }

    // ================= Milestone 13: total ownership =================

    {
        TcpConnectionTable table(8080);
        TcpConnectionKey key{localIp(), 8080, remoteIp(), 54321};
        establish(table, key, 1000, t0);
        auto sent = table.makeOutgoingData(key, makeFilledPayload(1000), t0);
        CHECK(sent.segments.size() == 1); // fully scheduled: fits allowance
        auto snap1 = table.snapshotOf(key);
        CHECK(snap1.has_value());
        if (snap1) {
            CHECK(snap1->unsent_bytes == 0);
            CHECK(snap1->owned_bytes == 1000); // still owned via the pending entry
            CHECK(snap1->pending_count == 1);
        }

        // Partial ACK releases only the acknowledged application bytes.
        table.handle(key, makeAck(8080, 54321, 1001, sent.segments.front().sequence_number + 400),
                     t0);
        auto snap2 = table.snapshotOf(key);
        CHECK(snap2.has_value());
        if (snap2) CHECK(snap2->owned_bytes == 600);

        // Full ACK releases the rest.
        table.handle(key, makeAck(8080, 54321, 1001, sent.segments.front().sequence_number + 1000),
                     t0);
        auto snap3 = table.snapshotOf(key);
        CHECK(snap3.has_value());
        if (snap3) CHECK(snap3->owned_bytes == 0);
    }

    // retransmitted bytes do not count twice
    {
        TcpConnectionTable table(8080);
        TcpConnectionKey key{localIp(), 8080, remoteIp(), 54321};
        establish(table, key, 1000, t0);
        auto sent = table.makeOutgoingData(key, makeFilledPayload(500), t0);
        CHECK(sent.segments.size() == 1);
        auto before = table.snapshotOf(key);
        auto due = table.pollRetransmissions(t0 + kInitialRto);
        CHECK(due.retransmissions.size() == 1);
        auto after = table.snapshotOf(key);
        CHECK(before.has_value() && after.has_value());
        if (before && after) CHECK(after->owned_bytes == before->owned_bytes);
    }

    // ================= Milestone 13: FIFO across enqueue boundaries =================

    {
        TcpConnectionTable table(8080);
        TcpConnectionKey key{localIp(), 8080, remoteIp(), 54321};
        establishWithWindow(table, key, 1000, 3, t0); // tiny rwnd forces queuing
        auto binary = toBytes({0x00, 0x01, 0x7f, 0x80, 0xff, 0x0a});
        std::vector<std::byte> part1(binary.begin(), binary.begin() + 3);
        std::vector<std::byte> part2(binary.begin() + 3, binary.end());
        auto sent1 = table.makeOutgoingData(key, part1, t0);
        CHECK(!sent1.error);
        auto sent2 = table.makeOutgoingData(key, part2, t0);
        CHECK(!sent2.error);

        std::vector<std::byte> reconstructed;
        for (const auto& s : sent1.segments) {
            reconstructed.insert(reconstructed.end(), s.payload.begin(), s.payload.end());
        }
        for (const auto& s : sent2.segments) {
            reconstructed.insert(reconstructed.end(), s.payload.begin(), s.payload.end());
        }

        auto snapshot = table.snapshotOf(key);
        CHECK(snapshot.has_value());
        if (snapshot) {
            auto opened = table.handle(
                key, makeWindowUpdate(8080, 54321, 1001, snapshot->snd_nxt, 65535), t0);
            // Segmentation may coalesce across the two enqueue calls'
            // boundary -- application call boundaries have no wire
            // semantics.
            for (const auto& s : opened.scheduled) {
                if (!s.flags.fin) {
                    reconstructed.insert(reconstructed.end(), s.payload.begin(), s.payload.end());
                }
            }
        }
        CHECK(reconstructed == binary);
    }

    // ================= Milestone 13: isolation =================

    {
        TcpConnectionTable table(8080);
        TcpConnectionKey key_a{localIp(), 8080, remoteIp(), 11111};
        TcpConnectionKey key_b{localIp(), 8080, remoteIp(), 22222};
        establishWithWindow(table, key_a, 1000, 0, t0);
        establish(table, key_b, 2000, t0);

        std::size_t remaining = kTcpSendBufferCapacity;
        while (remaining > 0) {
            std::size_t chunk = std::min(remaining, kMaxApplicationSendSize);
            table.makeOutgoingData(key_a, makeFilledPayload(chunk), t0);
            remaining -= chunk;
        }
        auto full_a = table.makeOutgoingData(key_a, toBytes("x"), t0);
        CHECK(full_a.error == TcpSendError::BufferFull);

        auto ok_b = table.makeOutgoingData(key_b, toBytes("hello"), t0);
        CHECK(!ok_b.error); // unaffected by A's full buffer
    }

    {
        TcpConnectionTable table(8080);
        TcpConnectionKey key_a{localIp(), 8080, remoteIp(), 11111};
        TcpConnectionKey key_b{localIp(), 8080, remoteIp(), 22222};
        establish(table, key_a, 1000, t0);
        establish(table, key_b, 2000, t0);
        table.makeOutgoingData(key_a, toBytes("a-data"), t0);
        table.makeOutgoingData(key_b, toBytes("b-data"), t0);

        table.handle(key_a, makeRst(8080, 11111, 1001), t0);
        CHECK(!table.stateOf(key_a).has_value());
        auto snap_b = table.snapshotOf(key_b);
        CHECK(snap_b.has_value());
        if (snap_b) CHECK(snap_b->owned_bytes == 6); // untouched by A's RST
    }

    // ================= Milestone 13: state restrictions =================

    {
        TcpConnectionTable table(8080);
        TcpConnectionKey key{localIp(), 8080, remoteIp(), 54321};
        auto unknown = table.makeOutgoingData(key, toBytes("x"), t0);
        CHECK(unknown.error == TcpSendError::NotSendable);

        table.handle(key, makeSyn(8080, 54321, 1000), t0);
        auto syn_received = table.makeOutgoingData(key, toBytes("x"), t0);
        CHECK(syn_received.error == TcpSendError::NotSendable);
    }
    {
        TcpConnectionTable table(8080);
        TcpConnectionKey key{localIp(), 8080, remoteIp(), 54321};
        establish(table, key, 1000, t0);
        auto close_result = table.beginClose(key, t0);
        CHECK(close_result.accepted);
        auto after_close = table.makeOutgoingData(key, toBytes("x"), t0);
        CHECK(after_close.error == TcpSendError::NotSendable);
    }
    {
        TcpConnectionTable table(8080);
        TcpConnectionKey key{localIp(), 8080, remoteIp(), 54321};
        establish(table, key, 1000, t0);
        auto empty = table.makeOutgoingData(key, {}, t0);
        CHECK(empty.error == TcpSendError::EmptyPayload);
    }
    {
        // CloseWait accepted before local close is requested.
        TcpConnectionTable table(8080);
        TcpConnectionKey key{localIp(), 8080, remoteIp(), 54321};
        auto server_isn = establish(table, key, 1000, t0);
        table.handle(key, makeFin(8080, 54321, 1001, server_isn + 1), t0);
        CHECK(table.stateOf(key) == TcpState::CloseWait);
        auto ok = table.makeOutgoingData(key, toBytes("reply"), t0);
        CHECK(!ok.error);
    }

    // ================= Milestone 13: scheduler =================

    // exact MSS / MSS+1 / allowance smaller than MSS / allowance ending
    // one byte before the queue end
    {
        TcpConnectionTable table(8080);
        TcpConnectionKey key{localIp(), 8080, remoteIp(), 54321};
        establish(table, key, 1000, t0); // SMSS 1460
        auto sent = table.makeOutgoingData(key, makeFilledPayload(1460), t0);
        CHECK(sent.segments.size() == 1);
        if (sent.segments.size() == 1) {
            CHECK(sent.segments.front().payload.size() == 1460);
            CHECK(sent.segments.front().flags.psh); // drains the whole queue
        }
    }
    {
        TcpConnectionTable table(8080);
        TcpConnectionKey key{localIp(), 8080, remoteIp(), 54321};
        establish(table, key, 1000, t0);
        auto sent = table.makeOutgoingData(key, makeFilledPayload(1461), t0);
        CHECK(sent.segments.size() == 2);
        if (sent.segments.size() == 2) {
            CHECK(sent.segments[0].payload.size() == 1460);
            CHECK(!sent.segments[0].flags.psh);
            CHECK(sent.segments[1].payload.size() == 1);
            CHECK(sent.segments[1].flags.psh);
        }
    }
    {
        TcpConnectionTable table(8080);
        TcpConnectionKey key{localIp(), 8080, remoteIp(), 54321};
        establishWithWindow(table, key, 1000, 100, t0); // allowance < MSS
        auto sent = table.makeOutgoingData(key, makeFilledPayload(1460), t0);
        CHECK(sent.segments.size() == 1);
        if (sent.segments.size() == 1) {
            CHECK(sent.segments.front().payload.size() == 100);
            CHECK(!sent.segments.front().flags.psh); // queue not fully drained
        }
        auto snapshot = table.snapshotOf(key);
        CHECK(snapshot.has_value());
        if (snapshot) CHECK(snapshot->unsent_bytes == 1360);
    }
    {
        // allowance ending exactly one byte before the queue end
        TcpConnectionTable table(8080);
        TcpConnectionKey key{localIp(), 8080, remoteIp(), 54321};
        establishWithWindow(table, key, 1000, 99, t0);
        auto sent = table.makeOutgoingData(key, makeFilledPayload(100), t0);
        CHECK(sent.segments.size() == 1);
        if (sent.segments.size() == 1) {
            CHECK(sent.segments.front().payload.size() == 99);
            CHECK(!sent.segments.front().flags.psh);
        }
        auto snapshot = table.snapshotOf(key);
        CHECK(snapshot.has_value());
        if (snapshot) CHECK(snapshot->unsent_bytes == 1);
    }
    {
        // exact sequence/ACK numbers across multiple MSS-bounded segments
        TcpConnectionTable table(8080);
        TcpConnectionKey key{localIp(), 8080, remoteIp(), 54321};
        auto server_isn = establishWithWindow(table, key, 1000, 65535, t0);
        auto sent = table.makeOutgoingData(key, makeFilledPayload(3 * 1460), t0);
        CHECK(sent.segments.size() == 3);
        if (sent.segments.size() == 3) {
            CHECK(sent.segments[0].sequence_number == server_isn + 1);
            CHECK(sent.segments[1].sequence_number == server_isn + 1 + 1460);
            CHECK(sent.segments[2].sequence_number == server_isn + 1 + 2 * 1460);
            for (const auto& seg : sent.segments) {
                CHECK(seg.acknowledgment_number == 1001);
                CHECK(seg.flags.ack);
            }
            std::vector<std::byte> reconstructed;
            for (const auto& seg : sent.segments) {
                reconstructed.insert(reconstructed.end(), seg.payload.begin(), seg.payload.end());
            }
            CHECK(reconstructed == makeFilledPayload(3 * 1460));
        }
        auto snapshot = table.snapshotOf(key);
        CHECK(snapshot.has_value());
        if (snapshot) {
            CHECK(snapshot->snd_nxt == server_isn + 1 + 3 * 1460);
            CHECK(snapshot->pending_count == 3);
            CHECK(snapshot->unsent_bytes == 0);
        }
    }

    // ================= Milestone 13: ACK-driven scheduling =================

    // an advancing ACK opens space and immediately produces new segments,
    // without a second application call
    {
        TcpConnectionTable table(8080);
        TcpConnectionKey key{localIp(), 8080, remoteIp(), 54321};
        establishWithWindow(table, key, 1000, 1460, t0); // exactly one MSS of room
        auto sent = table.makeOutgoingData(key, makeFilledPayload(2920), t0); // 2 MSS
        CHECK(sent.segments.size() == 1); // only the first MSS fits
        auto ack_result = table.handle(
            key, makeAck(8080, 54321, 1001, sent.segments.front().sequence_number + 1460), t0);
        CHECK(ack_result.scheduled.size() == 1);
        if (ack_result.scheduled.size() == 1) {
            CHECK(ack_result.scheduled.front().payload.size() == 1460);
            CHECK(ack_result.scheduled.front().flags.psh); // drains the whole queue now
        }
        CHECK(!ack_result.reply.has_value()); // scheduled data replaces the redundant pure ACK
    }

    // cumulative ACK may release several segments at once
    {
        TcpConnectionTable table(8080);
        TcpConnectionKey key{localIp(), 8080, remoteIp(), 54321};
        establishWithWindow(table, key, 1000, 1460, t0);
        auto sent = table.makeOutgoingData(key, makeFilledPayload(4 * 1460), t0);
        CHECK(sent.segments.size() == 1);
        auto snapshot = table.snapshotOf(key);
        CHECK(snapshot.has_value());
        if (snapshot) {
            // The ACK retires the 1 outstanding MSS (flight -> 0) and
            // grows cwnd via Slow Start; the new 3-MSS window then fits
            // all 3 remaining queued MSS at once.
            auto ack_result = table.handle(
                key, makeWindowUpdate(8080, 54321, 1001, snapshot->snd_nxt, 3 * 1460), t0);
            CHECK(ack_result.scheduled.size() == 3);
        }
    }

    // partial ACK may release only part of the outstanding window's worth
    {
        TcpConnectionTable table(8080);
        TcpConnectionKey key{localIp(), 8080, remoteIp(), 54321};
        establishWithWindow(table, key, 1000, 100, t0);
        auto sent = table.makeOutgoingData(key, makeFilledPayload(150), t0);
        CHECK(sent.segments.size() == 1);
        if (sent.segments.size() == 1) CHECK(sent.segments.front().payload.size() == 100);
        auto snapshot = table.snapshotOf(key);
        CHECK(snapshot.has_value());
        if (snapshot) {
            // Partial ACK of 30 of the 100 outstanding bytes, window
            // still 100 total: flight drops to 70, freeing 30 bytes of
            // rwnd room (cwnd is not the binding limit here).
            auto ack_result = table.handle(
                key,
                makeWindowUpdate(8080, 54321, 1001, snapshot->snd_una + 30, 100),
                t0);
            CHECK(ack_result.scheduled.size() == 1);
            if (ack_result.scheduled.size() == 1) {
                CHECK(ack_result.scheduled.front().payload.size() == 30);
            }
        }
    }

    // a window update without ACK advancement may still reopen sending;
    // a stale window update does not
    {
        TcpConnectionTable table(8080);
        TcpConnectionKey key{localIp(), 8080, remoteIp(), 54321};
        establishWithWindow(table, key, 1000, 0, t0);
        auto sent = table.makeOutgoingData(key, toBytes("hi"), t0);
        CHECK(sent.segments.empty());

        // Stale: sequence number behind snd_wl1 (still 1001 from the
        // handshake) -- rejected by the existing SND.WL1/WL2 freshness
        // test, so it must not reopen sending.
        auto stale = table.handle(key, makeWindowUpdate(8080, 54321, 1000, 1001, 65535), t0);
        CHECK(stale.scheduled.empty());

        auto fresh = table.handle(key, makeWindowUpdate(8080, 54321, 1001, 1001, 65535), t0);
        CHECK(fresh.scheduled.size() == 1);
    }

    // future ACK does not schedule data; ACK-only processing creates no ACK loop
    {
        TcpConnectionTable table(8080);
        TcpConnectionKey key{localIp(), 8080, remoteIp(), 54321};
        auto server_isn = establishWithWindow(table, key, 1000, 0, t0);
        table.makeOutgoingData(key, toBytes("hi"), t0);
        auto future = table.handle(key, makeAck(8080, 54321, 1001, server_isn + 100000), t0);
        CHECK(future.scheduled.empty());
        CHECK(!future.reply.has_value());
    }

    // ================= Milestone 13: Reno interaction with the queue =================

    // Slow Start / Congestion Avoidance growth releases queued bytes
    {
        TcpConnectionTable table(8080);
        TcpConnectionKey key{localIp(), 8080, remoteIp(), 54321};
        establish(table, key, 1000, t0); // cwnd 14600
        auto fill = table.makeOutgoingData(key, makeFilledPayload(14600), t0); // cwnd exhausted
        CHECK(fill.bytes_accepted == 14600);
        auto more = table.makeOutgoingData(key, makeFilledPayload(1460), t0); // queued only
        CHECK(more.segments.empty());

        // ACK one MSS: Slow Start grows cwnd by 1460, freeing exactly
        // enough room for the queued MSS.
        auto ack_result = table.handle(
            key, makeAck(8080, 54321, 1001, fill.segments.front().sequence_number + 1460), t0);
        bool saw_new_data = false;
        for (const auto& seg : ack_result.scheduled) {
            if (seg.sequence_number == fill.segments.back().sequence_number +
                                            static_cast<std::uint32_t>(
                                                fill.segments.back().payload.size())) {
                saw_new_data = true;
            }
        }
        CHECK(saw_new_data);
    }

    // duplicate ACK 1 and 2 do not implement Limited Transmit (no new
    // queued data scheduled merely because of a duplicate ACK)
    {
        TcpConnectionTable table(8080);
        TcpConnectionKey key{localIp(), 8080, remoteIp(), 54321};
        establish(table, key, 1000, t0);
        auto fill = table.makeOutgoingData(key, makeFilledPayload(14600), t0);
        auto more = table.makeOutgoingData(key, toBytes("queued"), t0);
        CHECK(more.segments.empty());

        auto dup1 = table.handle(
            key, makeAck(8080, 54321, 1001, fill.segments.front().sequence_number), t0);
        CHECK(dup1.scheduled.empty());
        auto dup2 = table.handle(
            key, makeAck(8080, 54321, 1001, fill.segments.front().sequence_number), t0);
        CHECK(dup2.scheduled.empty());
    }

    // duplicate ACK 3 fast-retransmits the oldest missing data without
    // removing unsent queue data; recovery's inflated cwnd may schedule
    // new queued data only when allowance genuinely exists
    {
        TcpConnectionTable table(8080);
        TcpConnectionKey key{localIp(), 8080, remoteIp(), 54321};
        establishWithWindow(table, key, 1000, 65535, t0);
        // Exhaust cwnd exactly (10 * 1460 = 14600) so a further enqueue
        // is guaranteed to stay queued.
        std::vector<TcpSegment> sent_segments;
        for (int i = 0; i < 10; ++i) {
            auto sent = table.makeOutgoingData(key, makeFilledPayload(1460), t0);
            if (sent.segments.size() == 1) sent_segments.push_back(sent.segments.front());
        }
        CHECK(sent_segments.size() == 10);
        if (sent_segments.size() != 10) return wirestack::test::failureCount() == 0 ? 0 : 1;

        auto more = table.makeOutgoingData(key, toBytes("still-queued"), t0);
        CHECK(more.segments.empty()); // no allowance left: stays queued
        CHECK(more.bytes_accepted == 12);

        // Segment 0 acknowledged (advances snd_una, and legitimately
        // grows cwnd via Slow Start -- which may itself schedule some of
        // the queued backlog; that is ordinary ACK-driven scheduling, not
        // the fast retransmit under test below).
        std::uint32_t seg1_seq = sent_segments[1].sequence_number;
        table.handle(key, makeAck(8080, 54321, 1001, seg1_seq), t0);

        // Two plain duplicates, then the third duplicate that fast-
        // retransmits: this specific step must not touch the unsent
        // queue, whatever it currently holds.
        table.handle(key, makeAck(8080, 54321, 1001, seg1_seq), t0);
        table.handle(key, makeAck(8080, 54321, 1001, seg1_seq), t0);
        auto snap_before_dup3 = table.snapshotOf(key);
        CHECK(snap_before_dup3.has_value());
        std::size_t unsent_before_dup3 = snap_before_dup3 ? snap_before_dup3->unsent_bytes : 0;

        auto dup3 = table.handle(key, makeAck(8080, 54321, 1001, seg1_seq), t0);
        CHECK(dup3.fast_retransmit.has_value());

        auto after_recovery = table.snapshotOf(key);
        CHECK(after_recovery.has_value());
        if (after_recovery) {
            CHECK(after_recovery->in_fast_recovery);
            // Untouched by the fast retransmit step itself.
            CHECK(after_recovery->unsent_bytes == unsent_before_dup3);
        }
    }

    // recovery exit uses ssthresh before draining more queued bytes
    {
        TcpConnectionTable table(8080);
        TcpConnectionKey key{localIp(), 8080, remoteIp(), 54321};
        establishWithWindow(table, key, 1000, 65535, t0);
        std::vector<TcpSegment> sent_segments;
        for (int i = 0; i < 10; ++i) {
            auto sent = table.makeOutgoingData(key, makeFilledPayload(1460), t0);
            if (sent.segments.size() == 1) sent_segments.push_back(sent.segments.front());
        }
        CHECK(sent_segments.size() == 10);
        if (sent_segments.size() != 10) return wirestack::test::failureCount() == 0 ? 0 : 1;
        std::uint32_t seg1_seq = sent_segments[1].sequence_number;

        table.handle(key, makeAck(8080, 54321, 1001, seg1_seq), t0);
        table.handle(key, makeAck(8080, 54321, 1001, seg1_seq), t0);
        table.handle(key, makeAck(8080, 54321, 1001, seg1_seq), t0);
        auto dup3 = table.handle(key, makeAck(8080, 54321, 1001, seg1_seq), t0);
        CHECK(dup3.fast_retransmit.has_value());
        auto recovering = table.snapshotOf(key);
        CHECK(recovering.has_value());
        std::uint32_t recovery_ssthresh = recovering ? recovering->ssthresh : 0;

        auto exit_result = table.handle(
            key, makeAck(8080, 54321, 1001, recovering ? recovering->snd_nxt : 0), t0);
        auto after_exit = table.snapshotOf(key);
        CHECK(after_exit.has_value());
        if (after_exit) CHECK(after_exit->cwnd == recovery_ssthresh); // not further grown this ACK
        (void)exit_result;
    }

    // timeout collapse preserves unsent queued data
    {
        TcpConnectionTable table(8080);
        TcpConnectionKey key{localIp(), 8080, remoteIp(), 54321};
        establishWithWindow(table, key, 1000, 65535, t0);
        table.makeOutgoingData(key, makeFilledPayload(3000), t0);
        auto more = table.makeOutgoingData(key, toBytes("queued-across-timeout"), t0);
        auto before_timeout = table.snapshotOf(key);
        CHECK(before_timeout.has_value());

        auto due = table.pollRetransmissions(t0 + kInitialRto);
        CHECK(due.retransmissions.size() == 1);
        auto after_timeout = table.snapshotOf(key);
        CHECK(after_timeout.has_value() && before_timeout.has_value());
        if (after_timeout && before_timeout) {
            CHECK(after_timeout->unsent_bytes == before_timeout->unsent_bytes);
        }
        (void)more;
    }

    // ================= Milestone 13: deferred close =================

    {
        TcpConnectionTable table(8080);
        TcpConnectionKey key{localIp(), 8080, remoteIp(), 54321};
        establishWithWindow(table, key, 1000, 100, t0); // limited allowance
        auto sent = table.makeOutgoingData(key, makeFilledPayload(200), t0);
        CHECK(sent.segments.size() == 1);
        if (sent.segments.size() == 1) CHECK(sent.segments.front().payload.size() == 100);

        auto close_result = table.beginClose(key, t0);
        CHECK(close_result.accepted);
        CHECK(!close_result.fin.has_value()); // no FIN yet: bytes still queued

        auto snapshot = table.snapshotOf(key);
        CHECK(snapshot.has_value());
        if (snapshot) {
            auto opened = table.handle(
                key, makeWindowUpdate(8080, 54321, 1001, snapshot->snd_nxt, 65535), t0);
            CHECK(opened.scheduled.size() == 2); // remaining 100 data bytes, then FIN
            if (opened.scheduled.size() == 2) {
                CHECK(opened.scheduled[0].payload.size() == 100);
                CHECK(!opened.scheduled[0].flags.fin);
                CHECK(opened.scheduled[1].flags.fin);
                CHECK(opened.scheduled[1].sequence_number ==
                      opened.scheduled[0].sequence_number +
                          static_cast<std::uint32_t>(opened.scheduled[0].payload.size()));
            }
        }
    }

    // repeated close requests are idempotent; no data enqueue accepted after
    {
        TcpConnectionTable table(8080);
        TcpConnectionKey key{localIp(), 8080, remoteIp(), 54321};
        establish(table, key, 1000, t0);
        auto first = table.beginClose(key, t0);
        CHECK(first.accepted);
        CHECK(first.fin.has_value());
        auto second = table.beginClose(key, t0);
        CHECK(!second.accepted); // state already left Established/CloseWait
        CHECK(!second.fin.has_value()); // no second FIN created

        auto rejected = table.makeOutgoingData(key, toBytes("x"), t0);
        CHECK(rejected.error.has_value());
    }

    // ================= Milestone 13: zero-window persist =================

    // arming: zero peer window, unsent data queued, no outstanding
    // sequence space -> deadline = now + 1s
    {
        TcpConnectionTable table(8080);
        TcpConnectionKey key{localIp(), 8080, remoteIp(), 54321};
        establishWithWindow(table, key, 1000, 0, t0);
        auto sent = table.makeOutgoingData(key, toBytes("persisted"), t0);
        CHECK(sent.segments.empty());
        auto snapshot = table.snapshotOf(key);
        CHECK(snapshot.has_value());
        if (snapshot) {
            CHECK(snapshot->persist_armed);
            CHECK(snapshot->persist_deadline.has_value());
            if (snapshot->persist_deadline) CHECK(*snapshot->persist_deadline == t0 + kInitialPersistInterval);
        }
    }

    // ineligible: no queued data, nonzero window, outstanding sequence
    // space, only a deferred FIN
    {
        TcpConnectionTable table(8080);
        TcpConnectionKey key{localIp(), 8080, remoteIp(), 54321};
        establishWithWindow(table, key, 1000, 0, t0);
        auto snapshot = table.snapshotOf(key);
        CHECK(snapshot.has_value());
        if (snapshot) CHECK(!snapshot->persist_armed); // no queued data yet
    }
    {
        TcpConnectionTable table(8080);
        TcpConnectionKey key{localIp(), 8080, remoteIp(), 54321};
        establish(table, key, 1000, t0); // nonzero window
        table.makeOutgoingData(key, toBytes("x"), t0);
        auto snapshot = table.snapshotOf(key);
        CHECK(snapshot.has_value());
        if (snapshot) CHECK(!snapshot->persist_armed);
    }
    {
        // outstanding sequence space with a zero window: ordinary
        // retransmission applies, not persist.
        TcpConnectionTable table(8080);
        TcpConnectionKey key{localIp(), 8080, remoteIp(), 54321};
        auto server_isn = establishWithWindow(table, key, 1000, 10, t0);
        table.makeOutgoingData(key, makeFilledPayload(10), t0); // fills the window, outstanding
        // Window update that does not acknowledge the outstanding 10
        // bytes (ack == snd_una), just lowers the window to zero.
        table.handle(key, makeWindowUpdate(8080, 54321, 1001, server_isn + 1, 0), t0);
        table.makeOutgoingData(key, toBytes("more"), t0); // queued behind it
        auto snapshot = table.snapshotOf(key);
        CHECK(snapshot.has_value());
        if (snapshot) CHECK(!snapshot->persist_armed); // snd_nxt != snd_una
    }
    {
        // only a deferred FIN, no unsent data: persist must not arm.
        TcpConnectionTable table(8080);
        TcpConnectionKey key{localIp(), 8080, remoteIp(), 54321};
        establishWithWindow(table, key, 1000, 0, t0);
        table.beginClose(key, t0);
        auto snapshot = table.snapshotOf(key);
        CHECK(snapshot.has_value());
        if (snapshot) CHECK(!snapshot->persist_armed);
    }

    // probe fields: seq = snd_nxt - 1, ack = rcv_nxt, one-byte payload,
    // no options, current advertised window; no state consumption
    {
        TcpConnectionTable table(8080);
        TcpConnectionKey key{localIp(), 8080, remoteIp(), 54321};
        auto server_isn = establishWithWindow(table, key, 1000, 0, t0);
        auto data = toBytes("ZW");
        table.makeOutgoingData(key, data, t0);
        auto before = table.snapshotOf(key);
        CHECK(before.has_value());

        auto due = table.pollPersistProbes(t0 + kInitialPersistInterval);
        CHECK(due.probes.size() == 1);
        if (due.probes.size() == 1) {
            const auto& probe = due.probes[0].segment;
            CHECK(probe.sequence_number == server_isn + 1 - 1); // snd_nxt - 1
            CHECK(probe.acknowledgment_number == 1001);
            CHECK(probe.flags.ack);
            CHECK(!probe.flags.psh);
            CHECK(probe.payload.size() == 1);
            CHECK(probe.payload.front() == data.front());
            CHECK(probe.options.empty());
        }

        auto after = table.snapshotOf(key);
        CHECK(before.has_value() && after.has_value());
        if (before && after) {
            CHECK(after->snd_nxt == before->snd_nxt);
            CHECK(after->snd_una == before->snd_una);
            CHECK(after->unsent_bytes == before->unsent_bytes);
            CHECK(after->owned_bytes == before->owned_bytes);
            CHECK(after->pending_count == before->pending_count);
            CHECK(after->cwnd == before->cwnd);
            CHECK(after->ssthresh == before->ssthresh);
            CHECK(after->current_rto == before->current_rto);
            CHECK(after->has_rtt_sample == before->has_rtt_sample);
        }
    }

    // backoff: 1s, 2s, 4s, 8s, 16s, 32s, 60s, 60s (repeated probes reuse
    // the same sequence number and byte; no duplicate pending entries)
    {
        TcpConnectionTable table(8080);
        TcpConnectionKey key{localIp(), 8080, remoteIp(), 54321};
        establishWithWindow(table, key, 1000, 0, t0);
        table.makeOutgoingData(key, toBytes("p"), t0);

        std::vector<std::chrono::milliseconds> expected = {
            std::chrono::milliseconds(1000),  std::chrono::milliseconds(2000),
            std::chrono::milliseconds(4000),  std::chrono::milliseconds(8000),
            std::chrono::milliseconds(16000), std::chrono::milliseconds(32000),
            std::chrono::milliseconds(60000), std::chrono::milliseconds(60000),
        };
        auto t = t0;
        std::optional<std::uint32_t> first_seq;
        for (auto interval : expected) {
            t += interval;
            auto due = table.pollPersistProbes(t);
            CHECK(due.probes.size() == 1);
            if (due.probes.size() == 1) {
                if (!first_seq) first_seq = due.probes[0].segment.sequence_number;
                CHECK(due.probes[0].segment.sequence_number == *first_seq); // same probe each time
            }
            auto snapshot = table.snapshotOf(key);
            CHECK(snapshot.has_value());
            if (snapshot) CHECK(snapshot->pending_count == 0); // never a pending entry
        }
    }

    // cancellation: window reopens, queue empties, RST, timeout
    // exhaustion, close completion
    {
        TcpConnectionTable table(8080);
        TcpConnectionKey key{localIp(), 8080, remoteIp(), 54321};
        establishWithWindow(table, key, 1000, 0, t0);
        table.makeOutgoingData(key, toBytes("p"), t0);
        auto armed = table.snapshotOf(key);
        CHECK(armed.has_value());
        if (armed) CHECK(armed->persist_armed);

        table.handle(key, makeWindowUpdate(8080, 54321, 1001, 1001, 65535), t0);
        auto reopened = table.snapshotOf(key);
        CHECK(reopened.has_value());
        if (reopened) CHECK(!reopened->persist_armed);
    }
    {
        TcpConnectionTable table(8080);
        TcpConnectionKey key{localIp(), 8080, remoteIp(), 54321};
        establishWithWindow(table, key, 1000, 0, t0);
        table.makeOutgoingData(key, toBytes("p"), t0);
        table.handle(key, makeRst(8080, 54321, 1001), t0);
        CHECK(!table.stateOf(key).has_value());
        auto due = table.pollPersistProbes(t0 + kInitialPersistInterval);
        CHECK(due.probes.empty()); // connection gone, nothing to probe
    }

    // wraparound: the sequence subtraction is unsigned and wraps
    // naturally, matching every other sequence computation in this file
    {
        TcpConnectionTable table(8080);
        TcpConnectionKey key{localIp(), 8080, remoteIp(), 54321};
        establishWithWindow(table, key, 1000, 0, t0);
        table.makeOutgoingData(key, toBytes("p"), t0);
        auto snapshot = table.snapshotOf(key);
        CHECK(snapshot.has_value());
        if (snapshot) {
            std::uint32_t expected_probe_seq = snapshot->snd_nxt - 1; // wraps if snd_nxt == 0
            auto due = table.pollPersistProbes(t0 + kInitialPersistInterval);
            CHECK(due.probes.size() == 1);
            if (due.probes.size() == 1) CHECK(due.probes[0].segment.sequence_number == expected_probe_seq);
        }
    }

    // ========= receive/scheduling ordering: ACK + in-order payload =========
    //
    // scheduleQueuedData() stamps scheduled segments with the CURRENT
    // connection.rcv_nxt. If scheduling ran before this segment's own
    // in-order payload advanced rcv_nxt, the scheduled segments would
    // acknowledge the old (pre-payload) rcv_nxt -- a stale ACK. This test
    // fails against commit a918b0e for exactly that reason.
    {
        TcpConnectionTable table(8080);
        TcpConnectionKey key{localIp(), 8080, remoteIp(), 54321};
        auto server_isn = establishWithWindow(table, key, 6000, 0, t0); // zero window: nothing can send yet

        auto queued = makeFilledPayload(250);
        auto sent = table.makeOutgoingData(key, queued, t0);
        CHECK(!sent.error);
        CHECK(sent.segments.empty()); // zero window prevented all transmission

        // One segment that both opens the send window AND carries
        // in-order application payload.
        TcpSegment client_segment;
        client_segment.source_port = 54321;
        client_segment.destination_port = 8080;
        client_segment.sequence_number = 6001;
        client_segment.acknowledgment_number = server_isn + 1; // no outstanding data to ack
        client_segment.flags.ack = true;
        client_segment.flags.psh = true;
        client_segment.window_size = 100;
        client_segment.payload = makeFilledPayload(30, std::byte{'y'});

        auto result = table.handle(key, client_segment, t0);

        CHECK(result.accepted_payload == client_segment.payload); // delivered exactly once

        auto snapshot = table.snapshotOf(key);
        CHECK(snapshot.has_value());
        std::uint32_t expected_rcv_nxt = 6001 + 30;
        if (snapshot) {
            CHECK(snapshot->rcv_nxt == expected_rcv_nxt); // rcv_nxt advanced by payload length
        }

        CHECK(!result.scheduled.empty()); // queued data scheduled immediately
        std::size_t scheduled_bytes = 0;
        for (const auto& seg : result.scheduled) {
            CHECK(seg.acknowledgment_number == expected_rcv_nxt); // not the stale pre-payload rcv_nxt
            scheduled_bytes += seg.payload.size();
        }
        CHECK(scheduled_bytes == 100); // bound by the newly opened 100-byte window

        CHECK(!result.reply.has_value()); // no redundant pure ACK

        if (snapshot) {
            CHECK(snapshot->unsent_bytes == queued.size() - 100);
            CHECK(snapshot->owned_bytes == queued.size()); // all still owned (queued + pending)
        }
    }

    // ============= receive/scheduling ordering: ACK + payload + FIN =============
    {
        TcpConnectionTable table(8080);
        TcpConnectionKey key{localIp(), 8080, remoteIp(), 54321};
        auto server_isn = establishWithWindow(table, key, 7000, 0, t0);

        auto queued = makeFilledPayload(50, std::byte{'q'});
        auto sent = table.makeOutgoingData(key, queued, t0);
        CHECK(sent.segments.empty());

        auto close_result = table.beginClose(key, t0);
        CHECK(close_result.accepted);
        CHECK(!close_result.fin.has_value()); // deferred: unsent is still non-empty

        auto client_payload = makeFilledPayload(20, std::byte{'z'});
        TcpSegment client_segment;
        client_segment.source_port = 54321;
        client_segment.destination_port = 8080;
        client_segment.sequence_number = 7001;
        client_segment.acknowledgment_number = server_isn + 1;
        client_segment.flags.ack = true;
        client_segment.flags.fin = true;
        client_segment.window_size = 1000; // plenty: drains the whole queue plus the FIN
        client_segment.payload = client_payload;

        auto result = table.handle(key, client_segment, t0);

        CHECK(result.accepted_payload == client_payload); // delivered exactly once
        CHECK(result.peer_closed); // EOF signaled exactly once

        std::uint32_t expected_rcv_nxt = 7001 + 20 + 1; // payload.size() + FIN
        auto snapshot = table.snapshotOf(key);
        CHECK(snapshot.has_value());
        if (snapshot) {
            CHECK(snapshot->rcv_nxt == expected_rcv_nxt);
            CHECK(snapshot->state == TcpState::LastAck); // post-FIN state: CloseWait -> LastAck
        }

        CHECK(!result.scheduled.empty());
        bool saw_fin = false;
        std::uint32_t max_data_seq_end = 0;
        std::optional<std::uint32_t> fin_seq;
        for (const auto& seg : result.scheduled) {
            CHECK(seg.acknowledgment_number == expected_rcv_nxt); // every scheduled segment
            if (seg.flags.fin) {
                CHECK(!saw_fin); // exactly one FIN
                saw_fin = true;
                fin_seq = seg.sequence_number;
            } else {
                max_data_seq_end =
                    seg.sequence_number + static_cast<std::uint32_t>(seg.payload.size());
            }
        }
        CHECK(saw_fin); // deferred local FIN followed the queued application data
        CHECK(fin_seq.has_value());
        if (fin_seq) CHECK(*fin_seq == max_data_seq_end); // FIN sequenced after all queued bytes

        CHECK(!result.reply.has_value()); // no redundant pure ACK

        // A duplicate copy of the peer's FIN (same seq/payload) must not
        // re-deliver payload or re-signal EOF.
        auto duplicate_result = table.handle(key, client_segment, t0);
        CHECK(duplicate_result.accepted_payload.empty());
        CHECK(!duplicate_result.peer_closed);
    }

    // ============= receive/scheduling ordering: out-of-order payload =============
    //
    // Proves scheduling observes the FINAL receive state in the
    // non-advancing case too: a gap leaves rcv_nxt unchanged, so scheduled
    // segments must still ack the unchanged rcv_nxt, not a value computed
    // as if the gap had been filled.
    {
        TcpConnectionTable table(8080);
        TcpConnectionKey key{localIp(), 8080, remoteIp(), 54321};
        auto server_isn = establishWithWindow(table, key, 8000, 0, t0);

        auto queued = makeFilledPayload(40, std::byte{'q'});
        auto sent = table.makeOutgoingData(key, queued, t0);
        CHECK(sent.segments.empty());

        // Out-of-order: leaves a 10-byte gap before this segment's start.
        TcpSegment client_segment;
        client_segment.source_port = 54321;
        client_segment.destination_port = 8080;
        client_segment.sequence_number = 8001 + 10;
        client_segment.acknowledgment_number = server_isn + 1;
        client_segment.flags.ack = true;
        client_segment.window_size = 500; // opens the send window
        client_segment.payload = makeFilledPayload(15, std::byte{'g'});

        auto result = table.handle(key, client_segment, t0);

        CHECK(result.accepted_payload.empty()); // gap: nothing released early

        auto snapshot = table.snapshotOf(key);
        CHECK(snapshot.has_value());
        if (snapshot) {
            CHECK(snapshot->rcv_nxt == 8001); // unchanged: still awaiting the missing 10 bytes
            CHECK(snapshot->reassembly_buffered_bytes == 15); // buffered, not delivered
            CHECK(snapshot->reassembly_fragment_count == 1);
        }

        CHECK(!result.scheduled.empty()); // window update still scheduled queued data
        for (const auto& seg : result.scheduled) {
            CHECK(seg.acknowledgment_number == 8001); // the unchanged rcv_nxt, not an advanced one
        }
    }

    // ================= Milestone: SACK negotiation =================

    // peer omits SACK-Permitted: sack_permitted stays false, SYN-ACK has
    // only MSS
    {
        TcpConnectionTable table(8080);
        TcpConnectionKey key{localIp(), 8080, remoteIp(), 54321};
        auto syn_ack = table.handle(key, makeSyn(8080, 54321, 1000), t0).reply;
        CHECK(syn_ack.has_value());
        if (syn_ack) CHECK(syn_ack->options == toBytes({0x02, 0x04, 0x05, 0xb4}));
        table.handle(key, makeAck(8080, 54321, 1001, syn_ack ? syn_ack->sequence_number + 1 : 0),
                     t0);
        auto snap = table.snapshotOf(key);
        CHECK(snap.has_value());
        if (snap) CHECK(!snap->sack_permitted);
    }

    // peer offers SACK-Permitted: negotiated, SYN-ACK advertises it after
    // MSS, exactly "02 04 05 b4 04 02 00 00"
    {
        TcpConnectionTable table(8080);
        TcpConnectionKey key{localIp(), 8080, remoteIp(), 54321};
        establishWithSack(table, key, 1000, t0);
        auto snap = table.snapshotOf(key);
        CHECK(snap.has_value());
        if (snap) CHECK(snap->sack_permitted);
    }

    // exact SYN-ACK option bytes for all four negotiated combinations
    {
        // MSS only
        TcpConnectionTable t1(8080);
        TcpConnectionKey k1{localIp(), 8080, remoteIp(), 1};
        auto r1 = t1.handle(k1, makeSyn(8080, 1, 1000), t0).reply;
        CHECK(r1.has_value());
        if (r1) CHECK(r1->options == toBytes({0x02, 0x04, 0x05, 0xb4}));

        // MSS + Window Scale
        TcpConnectionTable t2(8080);
        TcpConnectionKey k2{localIp(), 8080, remoteIp(), 2};
        std::vector<std::byte> ws_opts = {std::byte{2}, std::byte{4}, std::byte{0x05},
                                           std::byte{0xb4}, std::byte{1}, std::byte{3},
                                           std::byte{3},   std::byte{2}};
        auto r2 = t2.handle(k2, makeSynWithOptions(8080, 2, 1000, ws_opts), t0).reply;
        CHECK(r2.has_value());
        if (r2)
            CHECK(r2->options ==
                  toBytes({0x02, 0x04, 0x05, 0xb4, 0x01, 0x03, 0x03, 0x02}));

        // MSS + SACK-Permitted
        TcpConnectionTable t3(8080);
        TcpConnectionKey k3{localIp(), 8080, remoteIp(), 3};
        std::vector<std::byte> sack_opts = {std::byte{2}, std::byte{4}, std::byte{0x05},
                                             std::byte{0xb4}, std::byte{4}, std::byte{2}};
        auto r3 = t3.handle(k3, makeSynWithOptions(8080, 3, 1000, sack_opts), t0).reply;
        CHECK(r3.has_value());
        if (r3)
            CHECK(r3->options ==
                  toBytes({0x02, 0x04, 0x05, 0xb4, 0x04, 0x02, 0x00, 0x00}));

        // MSS + SACK-Permitted + Window Scale
        TcpConnectionTable t4(8080);
        TcpConnectionKey k4{localIp(), 8080, remoteIp(), 4};
        std::vector<std::byte> both_opts = {std::byte{2}, std::byte{4}, std::byte{0x05},
                                             std::byte{0xb4}, std::byte{4}, std::byte{2},
                                             std::byte{1},    std::byte{3}, std::byte{3},
                                             std::byte{2}};
        auto r4 = t4.handle(k4, makeSynWithOptions(8080, 4, 1000, both_opts), t0).reply;
        CHECK(r4.has_value());
        if (r4)
            CHECK(r4->options == toBytes({0x02, 0x04, 0x05, 0xb4, 0x04, 0x02, 0x01, 0x03,
                                            0x03, 0x02, 0x00, 0x00}));
    }

    // duplicate SACK-Permitted on the SYN: malformed, no connection created
    {
        TcpConnectionTable table(8080);
        TcpConnectionKey key{localIp(), 8080, remoteIp(), 54321};
        std::vector<std::byte> bad = {std::byte{4}, std::byte{2}, std::byte{4}, std::byte{2}};
        auto result = table.handle(key, makeSynWithOptions(8080, 54321, 1000, bad), t0);
        CHECK(!result.reply.has_value());
        CHECK(!table.stateOf(key).has_value());
    }

    // malformed SACK-Permitted length on the SYN: no connection created
    {
        TcpConnectionTable table(8080);
        TcpConnectionKey key{localIp(), 8080, remoteIp(), 54321};
        std::vector<std::byte> bad = {std::byte{4}, std::byte{3}, std::byte{0}};
        auto result = table.handle(key, makeSynWithOptions(8080, 54321, 1000, bad), t0);
        CHECK(!result.reply.has_value());
        CHECK(!table.stateOf(key).has_value());
    }

    // a SACK block on the SYN is invalid: no connection created
    {
        TcpConnectionTable table(8080);
        TcpConnectionKey key{localIp(), 8080, remoteIp(), 54321};
        std::vector<std::byte> bad = {
            std::byte{5}, std::byte{10}, std::byte{0}, std::byte{0}, std::byte{0},
            std::byte{1}, std::byte{0},  std::byte{0}, std::byte{0}, std::byte{5},
        };
        auto result = table.handle(key, makeSynWithOptions(8080, 54321, 1000, bad), t0);
        CHECK(!result.reply.has_value());
        CHECK(!table.stateOf(key).has_value());
    }

    // duplicate SYN with changed options (dropping SACK-Permitted) never
    // renegotiates -- the retransmitted SYN-ACK still advertises SACK
    {
        TcpConnectionTable table(8080);
        TcpConnectionKey key{localIp(), 8080, remoteIp(), 54321};
        std::vector<std::byte> sack_opts = {std::byte{2}, std::byte{4}, std::byte{0x05},
                                             std::byte{0xb4}, std::byte{4}, std::byte{2}};
        auto first = table.handle(key, makeSynWithOptions(8080, 54321, 1000, sack_opts), t0).reply;
        CHECK(first.has_value());
        auto second = table.handle(key, makeSyn(8080, 54321, 1000), t0).reply; // no SACK this time
        CHECK(second.has_value());
        if (first && second) CHECK(first->options == second->options); // unchanged
    }

    // two connections negotiate SACK independently
    {
        TcpConnectionTable table(8080);
        TcpConnectionKey key_a{localIp(), 8080, remoteIp(), 1};
        TcpConnectionKey key_b{localIp(), 8080, remoteIp(), 2};
        establishWithSack(table, key_a, 1000, t0);
        auto server_isn_b = establish(table, key_b, 2000, t0); // no SACK
        (void)server_isn_b;
        auto snap_a = table.snapshotOf(key_a);
        auto snap_b = table.snapshotOf(key_b);
        CHECK(snap_a.has_value() && snap_b.has_value());
        if (snap_a && snap_b) {
            CHECK(snap_a->sack_permitted);
            CHECK(!snap_b->sack_permitted);
        }
    }

    // SYN-ACK timeout retransmission preserves SACK-Permitted
    {
        TcpConnectionTable table(8080);
        TcpConnectionKey key{localIp(), 8080, remoteIp(), 54321};
        std::vector<std::byte> sack_opts = {std::byte{2}, std::byte{4}, std::byte{0x05},
                                             std::byte{0xb4}, std::byte{4}, std::byte{2}};
        auto first = table.handle(key, makeSynWithOptions(8080, 54321, 1000, sack_opts), t0).reply;
        CHECK(first.has_value());
        auto due = table.pollRetransmissions(t0 + kInitialRto);
        CHECK(due.retransmissions.size() == 1);
        if (due.retransmissions.size() == 1 && first) {
            CHECK(due.retransmissions[0].segment.options == first->options);
        }
    }

    // an established-state SACK-Permitted option is safely parsed but
    // ignored (never enables SACK after the handshake)
    {
        TcpConnectionTable table(8080);
        TcpConnectionKey key{localIp(), 8080, remoteIp(), 54321};
        establish(table, key, 1000, t0); // no SACK on the SYN
        std::vector<std::byte> late_sack = {std::byte{4}, std::byte{2}};
        auto ack = makeAck(8080, 54321, 1001, 0);
        ack.options = late_sack;
        table.handle(key, ack, t0);
        auto snap = table.snapshotOf(key);
        CHECK(snap.has_value());
        if (snap) CHECK(!snap->sack_permitted);
    }

    // ================= Milestone: sender SACK scoreboard =================

    // one block covering one pending segment marks it sacked; SACK never
    // advances snd_una, frees capacity, grows cwnd, or takes an RTT sample
    {
        TcpConnectionTable table(8080);
        TcpConnectionKey key{localIp(), 8080, remoteIp(), 54321};
        establishWithSack(table, key, 1000, t0);

        std::vector<TcpSegment> sent_segments;
        for (int i = 0; i < 3; ++i) {
            auto sent = table.makeOutgoingData(key, makeFilledPayload(100), t0);
            if (sent.segments.size() == 1) sent_segments.push_back(sent.segments.front());
        }
        CHECK(sent_segments.size() == 3);
        if (sent_segments.size() != 3) return wirestack::test::failureCount() == 0 ? 0 : 1;
        std::uint32_t seq1 = sent_segments[0].sequence_number;
        std::uint32_t seq2 = sent_segments[1].sequence_number;
        std::uint32_t seq3 = sent_segments[2].sequence_number;

        auto before = table.snapshotOf(key);
        CHECK(before.has_value());
        std::uint32_t cwnd_before = before ? before->cwnd : 0;
        std::size_t owned_before = before ? before->owned_bytes : 0;

        // Reports segment 2 received (segment 1 missing at the cumulative
        // ACK, which stays pinned at seq1).
        auto result = table.handle(
            key, makeAckWithSack(8080, 54321, 1001, seq1, {{seq2, seq3}}), t0);

        auto after = table.snapshotOf(key);
        CHECK(after.has_value());
        if (after && before) {
            CHECK(after->snd_una == seq1);        // unchanged: SACK never advances snd_una
            CHECK(after->pending_count == 3);      // no entry removed
            CHECK(after->sacked_pending_count == 1); // exactly segment 2
            CHECK(after->cwnd == cwnd_before);      // no growth from a SACK-only ACK
            CHECK(after->owned_bytes == owned_before); // no capacity freed
        }
    }

    // one block covering several pending segments marks all of them
    {
        TcpConnectionTable table(8080);
        TcpConnectionKey key{localIp(), 8080, remoteIp(), 54321};
        establishWithSack(table, key, 1000, t0);
        std::vector<TcpSegment> sent_segments;
        for (int i = 0; i < 4; ++i) {
            auto sent = table.makeOutgoingData(key, makeFilledPayload(100), t0);
            if (sent.segments.size() == 1) sent_segments.push_back(sent.segments.front());
        }
        CHECK(sent_segments.size() == 4);
        if (sent_segments.size() != 4) return wirestack::test::failureCount() == 0 ? 0 : 1;
        std::uint32_t seq1 = sent_segments[0].sequence_number;
        std::uint32_t seq2 = sent_segments[1].sequence_number;
        std::uint32_t seq4_end = sent_segments[3].sequence_number + 100;

        table.handle(key, makeAckWithSack(8080, 54321, 1001, seq1, {{seq2, seq4_end}}), t0);
        auto snap = table.snapshotOf(key);
        CHECK(snap.has_value());
        if (snap) CHECK(snap->sacked_pending_count == 3); // segments 2,3,4
    }

    // multiple disjoint blocks, duplicate blocks, and overlapping/touching
    // blocks (merged) all behave idempotently
    {
        TcpConnectionTable table(8080);
        TcpConnectionKey key{localIp(), 8080, remoteIp(), 54321};
        establishWithSack(table, key, 1000, t0);
        std::vector<TcpSegment> sent_segments;
        for (int i = 0; i < 4; ++i) {
            auto sent = table.makeOutgoingData(key, makeFilledPayload(100), t0);
            if (sent.segments.size() == 1) sent_segments.push_back(sent.segments.front());
        }
        CHECK(sent_segments.size() == 4);
        if (sent_segments.size() != 4) return wirestack::test::failureCount() == 0 ? 0 : 1;
        std::uint32_t seq1 = sent_segments[0].sequence_number;
        std::uint32_t seq2 = sent_segments[1].sequence_number;
        std::uint32_t seq2_end = seq2 + 100;
        std::uint32_t seq4 = sent_segments[3].sequence_number;
        std::uint32_t seq4_end = seq4 + 100;

        // disjoint blocks for segments 2 and 4
        table.handle(key, makeAckWithSack(8080, 54321, 1001, seq1,
                                           {{seq2, seq2_end}, {seq4, seq4_end}}),
                     t0);
        auto snap1 = table.snapshotOf(key);
        CHECK(snap1.has_value());
        if (snap1) CHECK(snap1->sacked_pending_count == 2);

        // duplicate report: idempotent
        table.handle(key, makeAckWithSack(8080, 54321, 1001, seq1,
                                           {{seq2, seq2_end}, {seq4, seq4_end}}),
                     t0);
        auto snap2 = table.snapshotOf(key);
        CHECK(snap2.has_value());
        if (snap2) CHECK(snap2->sacked_pending_count == 2);

        // touching/overlapping block covering segment 3 too, merged with
        // the segment-2 report
        std::uint32_t seq3 = sent_segments[2].sequence_number;
        table.handle(key,
                     makeAckWithSack(8080, 54321, 1001, seq1, {{seq2, seq3 + 100}}), t0);
        auto snap3 = table.snapshotOf(key);
        CHECK(snap3.has_value());
        if (snap3) CHECK(snap3->sacked_pending_count == 3); // 2, 3, and still 4
    }

    // a block only partially covering a segment does not mark it sacked
    {
        TcpConnectionTable table(8080);
        TcpConnectionKey key{localIp(), 8080, remoteIp(), 54321};
        establishWithSack(table, key, 1000, t0);
        auto sent = table.makeOutgoingData(key, makeFilledPayload(100), t0);
        CHECK(sent.segments.size() == 1);
        if (sent.segments.size() != 1) return wirestack::test::failureCount() == 0 ? 0 : 1;
        std::uint32_t seq = sent.segments.front().sequence_number;

        table.handle(key, makeAckWithSack(8080, 54321, 1001, seq, {{seq + 10, seq + 100}}), t0);
        auto snap = table.snapshotOf(key);
        CHECK(snap.has_value());
        if (snap) CHECK(snap->sacked_pending_count == 0);
    }

    // structurally valid but semantically unusable blocks are ignored
    // individually: at/below cumulative ACK, beyond snd_nxt, reversed,
    // empty -- none corrupt an otherwise-valid cumulative ACK
    {
        TcpConnectionTable table(8080);
        TcpConnectionKey key{localIp(), 8080, remoteIp(), 54321};
        establishWithSack(table, key, 1000, t0);
        std::vector<TcpSegment> sent_segments;
        for (int i = 0; i < 2; ++i) {
            auto sent = table.makeOutgoingData(key, makeFilledPayload(100), t0);
            if (sent.segments.size() == 1) sent_segments.push_back(sent.segments.front());
        }
        CHECK(sent_segments.size() == 2);
        if (sent_segments.size() != 2) return wirestack::test::failureCount() == 0 ? 0 : 1;
        std::uint32_t seq1 = sent_segments[0].sequence_number;
        std::uint32_t seq2 = sent_segments[1].sequence_number;
        std::uint32_t snd_nxt = seq2 + 100;

        std::vector<std::pair<std::uint32_t, std::uint32_t>> bad_blocks = {
            {seq1 - 50, seq1},        // entirely at/below cumulative ACK
            {seq1, seq1},              // empty (left == right)
            {seq1 + 20, seq1 + 10},    // reversed
            {snd_nxt, snd_nxt + 100},  // beyond snd_nxt (unsent space)
        };
        for (auto [left, right] : bad_blocks) {
            auto result = table.handle(
                key, makeAckWithSack(8080, 54321, 1001, seq1, {{left, right}}), t0);
            // The cumulative ACK itself (== snd_una, a duplicate) is still
            // processed normally -- not rejected because of the bad block.
            CHECK(!result.connection_reset);
        }
        auto snap = table.snapshotOf(key);
        CHECK(snap.has_value());
        if (snap) CHECK(snap->sacked_pending_count == 0);
    }

    // unnegotiated connection: SACK blocks are parsed safely but ignored
    {
        TcpConnectionTable table(8080);
        TcpConnectionKey key{localIp(), 8080, remoteIp(), 54321};
        establish(table, key, 1000, t0); // no SACK
        auto sent = table.makeOutgoingData(key, makeFilledPayload(100), t0);
        CHECK(sent.segments.size() == 1);
        if (sent.segments.size() != 1) return wirestack::test::failureCount() == 0 ? 0 : 1;
        std::uint32_t seq = sent.segments.front().sequence_number;
        auto result = table.handle(
            key, makeAckWithSack(8080, 54321, 1001, seq, {{seq, seq + 100}}), t0);
        CHECK(!result.connection_reset);
        auto snap = table.snapshotOf(key);
        CHECK(snap.has_value());
        if (snap) CHECK(snap->sacked_pending_count == 0);
    }

    // cumulative ACK later retires a previously-SACKed entry exactly once,
    // and freed capacity/RTT accounting follow normal cumulative-ACK rules
    {
        TcpConnectionTable table(8080);
        TcpConnectionKey key{localIp(), 8080, remoteIp(), 54321};
        establishWithSack(table, key, 1000, t0);
        std::vector<TcpSegment> sent_segments;
        for (int i = 0; i < 2; ++i) {
            auto sent = table.makeOutgoingData(key, makeFilledPayload(100), t0);
            if (sent.segments.size() == 1) sent_segments.push_back(sent.segments.front());
        }
        CHECK(sent_segments.size() == 2);
        if (sent_segments.size() != 2) return wirestack::test::failureCount() == 0 ? 0 : 1;
        std::uint32_t seq1 = sent_segments[0].sequence_number;
        std::uint32_t seq2 = sent_segments[1].sequence_number;
        std::uint32_t seq2_end = seq2 + 100;

        table.handle(key, makeAckWithSack(8080, 54321, 1001, seq1, {{seq2, seq2_end}}), t0);
        auto mid = table.snapshotOf(key);
        CHECK(mid.has_value());
        if (mid) CHECK(mid->sacked_pending_count == 1);

        table.handle(key, makeAck(8080, 54321, 1001, seq2_end), t0); // cumulative ACK of both
        auto final_snap = table.snapshotOf(key);
        CHECK(final_snap.has_value());
        if (final_snap) {
            CHECK(final_snap->snd_una == seq2_end);
            CHECK(final_snap->pending_count == 0);
            CHECK(final_snap->sacked_pending_count == 0); // retired, not double-counted
        }
    }

    // RST clears connection state entirely (scoreboard gone with it)
    {
        TcpConnectionTable table(8080);
        TcpConnectionKey key{localIp(), 8080, remoteIp(), 54321};
        establishWithSack(table, key, 1000, t0);
        auto sent = table.makeOutgoingData(key, makeFilledPayload(100), t0);
        CHECK(sent.segments.size() == 1);
        auto snap_before = table.snapshotOf(key);
        CHECK(snap_before.has_value());
        auto rst = makeRst(8080, 54321, snap_before ? snap_before->rcv_nxt : 0);
        table.handle(key, rst, t0);
        CHECK(!table.stateOf(key).has_value());
    }

    // two connections' scoreboards are independent
    {
        TcpConnectionTable table(8080);
        TcpConnectionKey key_a{localIp(), 8080, remoteIp(), 1};
        TcpConnectionKey key_b{localIp(), 8080, remoteIp(), 2};
        establishWithSack(table, key_a, 1000, t0);
        establishWithSack(table, key_b, 2000, t0);
        std::vector<TcpSegment> sent_a_segments;
        for (int i = 0; i < 2; ++i) {
            auto sent = table.makeOutgoingData(key_a, makeFilledPayload(100), t0);
            if (sent.segments.size() == 1) sent_a_segments.push_back(sent.segments.front());
        }
        auto sent_b = table.makeOutgoingData(key_b, makeFilledPayload(100), t0);
        CHECK(sent_a_segments.size() == 2 && sent_b.segments.size() == 1);
        if (sent_a_segments.size() != 2 || sent_b.segments.size() != 1) {
            return wirestack::test::failureCount() == 0 ? 0 : 1;
        }
        std::uint32_t seq_a1 = sent_a_segments[0].sequence_number;
        std::uint32_t seq_a2 = sent_a_segments[1].sequence_number;
        table.handle(key_a,
                     makeAckWithSack(8080, 1, 1001, seq_a1, {{seq_a2, seq_a2 + 100}}), t0);
        auto snap_a = table.snapshotOf(key_a);
        auto snap_b = table.snapshotOf(key_b);
        CHECK(snap_a.has_value() && snap_b.has_value());
        if (snap_a && snap_b) {
            CHECK(snap_a->sacked_pending_count == 1);
            CHECK(snap_b->sacked_pending_count == 0); // untouched
        }
    }

    // ================= Milestone: NewReno recovery timeout/RST clearing =================

    // RTO clears SACK marks and recovery-transmitted markers
    {
        TcpConnectionTable table(8080);
        TcpConnectionKey key{localIp(), 8080, remoteIp(), 54321};
        establishWithSack(table, key, 1000, t0);
        std::vector<TcpSegment> sent_segments;
        for (int i = 0; i < 2; ++i) {
            auto sent = table.makeOutgoingData(key, makeFilledPayload(100), t0);
            if (sent.segments.size() == 1) sent_segments.push_back(sent.segments.front());
        }
        CHECK(sent_segments.size() == 2);
        if (sent_segments.size() != 2) return wirestack::test::failureCount() == 0 ? 0 : 1;
        std::uint32_t seq1 = sent_segments[0].sequence_number;
        std::uint32_t seq2 = sent_segments[1].sequence_number;

        table.handle(key, makeAckWithSack(8080, 54321, 1001, seq1, {{seq2, seq2 + 100}}), t0);
        auto before = table.snapshotOf(key);
        CHECK(before.has_value());
        if (before) CHECK(before->sacked_pending_count == 1);

        auto due = table.pollRetransmissions(t0 + kInitialRto);
        CHECK(due.retransmissions.size() == 1); // segment 1 (oldest) times out
        auto after = table.snapshotOf(key);
        CHECK(after.has_value());
        if (after) {
            CHECK(after->sacked_pending_count == 0);
            CHECK(after->recovery_retransmitted_count == 0);
            CHECK(!after->in_fast_recovery);
        }
    }

    // ================= Milestone: selective retransmission with SACK =================

    // segments 1..7; 3,5,6,7 fully SACKed; 2 and 4 missing. Duplicate ACK
    // 3 retransmits segment 2; a further SACK-bearing duplicate ACK skips
    // segment 3 (already SACKed) and retransmits segment 4; neither is
    // selected twice; cumulative ACK later retires everything.
    {
        TcpConnectionTable table(8080);
        TcpConnectionKey key{localIp(), 8080, remoteIp(), 54321};
        establishWithSack(table, key, 1000, t0);
        std::vector<TcpSegment> sent_segments;
        for (int i = 0; i < 7; ++i) {
            auto sent = table.makeOutgoingData(key, makeFilledPayload(100), t0);
            if (sent.segments.size() == 1) sent_segments.push_back(sent.segments.front());
        }
        CHECK(sent_segments.size() == 7);
        if (sent_segments.size() != 7) return wirestack::test::failureCount() == 0 ? 0 : 1;
        std::uint32_t seq1 = sent_segments[0].sequence_number;
        std::uint32_t seq2 = sent_segments[1].sequence_number;
        std::uint32_t seq3 = sent_segments[2].sequence_number;
        std::uint32_t seq4 = sent_segments[3].sequence_number;
        std::uint32_t seq5 = sent_segments[4].sequence_number;
        std::uint32_t seq7_end = sent_segments[6].sequence_number + 100;

        // ACK pinned at seq2 (segment 1 received, segment 2 missing),
        // reporting segments 3 and 5-7 received via SACK. The first such
        // ACK genuinely advances snd_una (retiring segment 1) and is not
        // itself a duplicate ACK; three further identical ACKs are.
        std::vector<std::pair<std::uint32_t, std::uint32_t>> blocks = {
            {seq3, seq3 + 100}, {seq5, seq7_end}};
        table.handle(key, makeAckWithSack(8080, 54321, 1001, seq2, blocks), t0);
        table.handle(key, makeAckWithSack(8080, 54321, 1001, seq2, blocks), t0);
        table.handle(key, makeAckWithSack(8080, 54321, 1001, seq2, blocks), t0);
        auto dup3 = table.handle(key, makeAckWithSack(8080, 54321, 1001, seq2, blocks), t0);
        CHECK(dup3.fast_retransmit.has_value());
        if (dup3.fast_retransmit) CHECK(dup3.fast_retransmit->sequence_number == seq2);

        auto after_dup3 = table.snapshotOf(key);
        CHECK(after_dup3.has_value());
        if (after_dup3) {
            CHECK(after_dup3->in_fast_recovery);
            CHECK(after_dup3->snd_una == seq2); // segment 1 retired by the cumulative ACK
            CHECK(after_dup3->sacked_pending_count == 4); // 3,5,6,7
            CHECK(after_dup3->recovery_retransmitted_count == 1); // segment 2
        }

        // A further SACK-bearing duplicate ACK (still pinned at seq2):
        // segment 3 is skipped (already SACKed), segment 4 is selected.
        auto dup4 = table.handle(key, makeAckWithSack(8080, 54321, 1001, seq2, blocks), t0);
        CHECK(dup4.fast_retransmit.has_value());
        if (dup4.fast_retransmit) CHECK(dup4.fast_retransmit->sequence_number == seq4);

        auto after_dup4 = table.snapshotOf(key);
        CHECK(after_dup4.has_value());
        if (after_dup4) {
            CHECK(after_dup4->recovery_retransmitted_count == 2); // segments 2 and 4
            CHECK(after_dup4->pending_count == 6); // segment 1 already retired; SACK removes none
        }

        // Cumulative ACK retires everything and exits recovery normally.
        table.handle(key, makeAck(8080, 54321, 1001, seq7_end), t0);
        auto final_snap = table.snapshotOf(key);
        CHECK(final_snap.has_value());
        if (final_snap) {
            CHECK(final_snap->snd_una == seq7_end);
            CHECK(final_snap->pending_count == 0);
            CHECK(!final_snap->in_fast_recovery);
        }
    }

    // ================= Milestone: receiver SACK block generation =================

    // one out-of-order fragment produces one SACK block with exact edges
    {
        TcpConnectionTable table(8080);
        TcpConnectionKey key{localIp(), 8080, remoteIp(), 54321};
        auto server_isn = establishWithSack(table, key, 8000, t0);

        TcpSegment gapped;
        gapped.source_port = 54321;
        gapped.destination_port = 8080;
        gapped.sequence_number = 8001 + 10; // 10-byte gap
        gapped.acknowledgment_number = server_isn + 1;
        gapped.flags.ack = true;
        gapped.window_size = 65535;
        gapped.payload = makeFilledPayload(15, std::byte{'g'});

        auto result = table.handle(key, gapped, t0);
        CHECK(result.reply.has_value());
        if (result.reply) {
            CHECK(result.reply->acknowledgment_number == 8001); // pinned at the gap
            auto parsed = wirestack::parseTcpOptions(result.reply->options);
            CHECK(std::holds_alternative<wirestack::TcpParsedOptions>(parsed));
            if (auto* opts = std::get_if<wirestack::TcpParsedOptions>(&parsed)) {
                CHECK(opts->sack_blocks.size() == 1);
                if (opts->sack_blocks.size() == 1) {
                    CHECK(opts->sack_blocks[0].left_edge == 8011);
                    CHECK(opts->sack_blocks[0].right_edge == 8026);
                }
            }
        }
    }

    // two disjoint fragments, most-recent-first ordering; gap fill and
    // cumulative release removes the released fragment from later reports
    {
        TcpConnectionTable table(8080);
        TcpConnectionKey key{localIp(), 8080, remoteIp(), 54321};
        auto server_isn = establishWithSack(table, key, 8000, t0);

        auto sendGapped = [&](std::uint32_t seq, std::size_t len) {
            TcpSegment seg;
            seg.source_port = 54321;
            seg.destination_port = 8080;
            seg.sequence_number = seq;
            seg.acknowledgment_number = server_isn + 1;
            seg.flags.ack = true;
            seg.window_size = 65535;
            seg.payload = makeFilledPayload(len, std::byte{'g'});
            return table.handle(key, seg, t0);
        };

        // First fragment: [8011, 8021)
        sendGapped(8001 + 10, 10);
        // Second, most-recent fragment: [8031, 8041)
        auto second = sendGapped(8001 + 30, 10);
        CHECK(second.reply.has_value());
        if (second.reply) {
            auto parsed = wirestack::parseTcpOptions(second.reply->options);
            if (auto* opts = std::get_if<wirestack::TcpParsedOptions>(&parsed)) {
                CHECK(opts->sack_blocks.size() == 2);
                if (opts->sack_blocks.size() == 2) {
                    CHECK(opts->sack_blocks[0].left_edge == 8031); // most recent first
                    CHECK(opts->sack_blocks[1].left_edge == 8011);
                }
            }
        }

        // Fill the first gap: [8001, 8011) -- releases the first fragment,
        // rcv_nxt advances to 8021; only the second fragment remains.
        auto filled = sendGapped(8001, 10);
        CHECK(!filled.accepted_payload.empty());
        auto after = table.snapshotOf(key);
        CHECK(after.has_value());
        if (after) CHECK(after->rcv_nxt == 8021);
        if (filled.reply) {
            auto parsed = wirestack::parseTcpOptions(filled.reply->options);
            if (auto* opts = std::get_if<wirestack::TcpParsedOptions>(&parsed)) {
                CHECK(opts->sack_blocks.size() == 1);
                if (opts->sack_blocks.size() == 1) CHECK(opts->sack_blocks[0].left_edge == 8031);
            }
        }
    }

    // duplicate/overlapping arrivals do not create duplicate blocks
    // (first-arrival-wins trimming keeps the fragment set canonical)
    {
        TcpConnectionTable table(8080);
        TcpConnectionKey key{localIp(), 8080, remoteIp(), 54321};
        auto server_isn = establishWithSack(table, key, 8000, t0);

        auto sendGapped = [&](std::uint32_t seq, std::size_t len) {
            TcpSegment seg;
            seg.source_port = 54321;
            seg.destination_port = 8080;
            seg.sequence_number = seq;
            seg.acknowledgment_number = server_isn + 1;
            seg.flags.ack = true;
            seg.window_size = 65535;
            seg.payload = makeFilledPayload(len, std::byte{'g'});
            return table.handle(key, seg, t0);
        };

        sendGapped(8001 + 10, 10);       // [8011, 8021)
        auto dup = sendGapped(8001 + 10, 10); // exact duplicate
        CHECK(dup.reply.has_value());
        if (dup.reply) {
            auto parsed = wirestack::parseTcpOptions(dup.reply->options);
            if (auto* opts = std::get_if<wirestack::TcpParsedOptions>(&parsed)) {
                CHECK(opts->sack_blocks.size() == 1); // still exactly one fragment
            }
        }
        auto snap = table.snapshotOf(key);
        CHECK(snap.has_value());
        if (snap) CHECK(snap->reassembly_fragment_count == 1);
    }

    // unnegotiated connection emits no SACK option on a gapped arrival
    {
        TcpConnectionTable table(8080);
        TcpConnectionKey key{localIp(), 8080, remoteIp(), 54321};
        auto server_isn = establish(table, key, 8000, t0); // no SACK

        TcpSegment gapped;
        gapped.source_port = 54321;
        gapped.destination_port = 8080;
        gapped.sequence_number = 8001 + 10;
        gapped.acknowledgment_number = server_isn + 1;
        gapped.flags.ack = true;
        gapped.window_size = 65535;
        gapped.payload = makeFilledPayload(15, std::byte{'g'});

        auto result = table.handle(key, gapped, t0);
        CHECK(result.reply.has_value());
        if (result.reply) CHECK(result.reply->options.empty());
    }

    // a SACK-bearing ACK that also carries acceptable payload and opens
    // send allowance -- every scheduled segment must still acknowledge
    // the FINAL post-payload rcv_nxt, not a stale one (regression for the
    // ordering fix in commits 8032653/08e00aa; see docs/tcp.md)
    {
        TcpConnectionTable table(8080);
        TcpConnectionKey key{localIp(), 8080, remoteIp(), 54321};
        auto server_isn = establishWithWindow(table, key, 8000, 0, t0);
        (void)server_isn;

        // Renegotiate SACK via a fresh table since establishWithWindow
        // doesn't negotiate it -- build one directly instead.
        TcpConnectionTable table2(8080);
        TcpConnectionKey key2{localIp(), 8080, remoteIp(), 54322};
        std::vector<std::byte> sack_opts = {std::byte{2}, std::byte{4}, std::byte{0x05},
                                             std::byte{0xb4}, std::byte{4}, std::byte{2}};
        auto syn_ack =
            table2.handle(key2, makeSynWithOptions(8080, 54322, 8000, sack_opts), t0).reply;
        std::uint32_t server_isn2 = syn_ack ? syn_ack->sequence_number : 0;
        table2.handle(key2,
                       makeWindowUpdate(8080, 54322, 8001, server_isn2 + 1, 0), t0);

        auto queued = makeFilledPayload(40, std::byte{'q'});
        auto sent = table2.makeOutgoingData(key2, queued, t0);
        CHECK(sent.segments.empty()); // zero window: nothing sent yet

        // Segment carries payload (accepted, advances rcv_nxt) and opens
        // the send window at once.
        TcpSegment client_segment;
        client_segment.source_port = 54322;
        client_segment.destination_port = 8080;
        client_segment.sequence_number = 8001;
        client_segment.acknowledgment_number = server_isn2 + 1;
        client_segment.flags.ack = true;
        client_segment.window_size = 500;
        client_segment.payload = makeFilledPayload(15, std::byte{'d'});

        auto result = table2.handle(key2, client_segment, t0);
        CHECK(!result.accepted_payload.empty());
        CHECK(!result.scheduled.empty());
        auto snap = table2.snapshotOf(key2);
        CHECK(snap.has_value());
        if (snap) {
            for (const auto& seg : result.scheduled) {
                CHECK(seg.acknowledgment_number == snap->rcv_nxt); // final, post-payload rcv_nxt
            }
        }
    }

    return wirestack::test::failureCount() == 0 ? 0 : 1;
}
