// Composed pure-packet-path tests for the outbound HTTP/1.0 client:
// active open -> real SYN/SYN-ACK/ACK bytes -> exact GET request bytes ->
// real Linux-style HTTP response bytes -> TCP receive/reassembly -> HTTP
// response parsing -> peer FIN -> Wirestack close, all through the real
// Ethernet/IPv4/TCP wire format (real checksums), with no TapDevice
// involved. Mirrors main.cpp's own dispatch
// (TcpConnectionTable::handle -> handleHttpClient) without depending on
// main.cpp itself.

#include "wirestack/ethernet.hpp"
#include "wirestack/http.hpp"
#include "wirestack/http_client.hpp"
#include "wirestack/ipv4.hpp"
#include "wirestack/mac_address.hpp"
#include "wirestack/tcp.hpp"
#include "wirestack/tcp_connection.hpp"

#include "test_util.hpp"

#include <map>

using namespace wirestack;

namespace {

constexpr TcpClock::time_point t0{};

Ipv4Address localIp() {
    return *Ipv4Address::parse("10.0.0.2");
}
Ipv4Address remoteIp() {
    return *Ipv4Address::parse("10.0.0.1");
}
MacAddress localMac() {
    return *MacAddress::parse("02:00:00:00:00:02");
}
MacAddress remoteMac() {
    return *MacAddress::parse("aa:bb:cc:dd:ee:ff");
}

std::vector<std::byte> toBytes(std::string_view text) {
    std::vector<std::byte> out;
    out.reserve(text.size());
    for (char c : text) {
        out.push_back(static_cast<std::byte>(static_cast<unsigned char>(c)));
    }
    return out;
}

std::vector<std::byte> wrap(const TcpSegment& segment, Ipv4Address src_ip, MacAddress src_mac,
                             Ipv4Address dst_ip, MacAddress dst_mac) {
    auto tcp_bytes = serializeTcpSegment(segment, src_ip, dst_ip);
    if (!std::holds_alternative<std::vector<std::byte>>(tcp_bytes)) return {};
    Ipv4Packet ip;
    ip.ttl = 64;
    ip.protocol = 6;
    ip.source = src_ip;
    ip.destination = dst_ip;
    ip.payload = std::get<std::vector<std::byte>>(tcp_bytes);
    auto ip_bytes = serializeIpv4Packet(ip);
    if (!std::holds_alternative<std::vector<std::byte>>(ip_bytes)) return {};
    EthernetFrame frame;
    frame.destination = dst_mac;
    frame.source = src_mac;
    frame.ether_type = static_cast<std::uint16_t>(EtherType::Ipv4);
    frame.payload = std::get<std::vector<std::byte>>(ip_bytes);
    return serializeEthernetFrame(frame);
}

struct ParsedWire {
    bool ok = false;
    MacAddress eth_src, eth_dst;
    Ipv4Address ip_src, ip_dst;
    TcpSegment tcp;
};

ParsedWire parseWire(std::span<const std::byte> bytes) {
    ParsedWire out;
    auto eth = parseEthernetFrame(bytes);
    auto* frame = std::get_if<EthernetFrame>(&eth);
    if (!frame) return out;
    auto ip = parseIpv4Packet(frame->payload);
    auto* packet = std::get_if<Ipv4Packet>(&ip);
    if (!packet) return out;
    auto tcp = parseTcpSegment(packet->payload, packet->source, packet->destination);
    auto* segment = std::get_if<TcpSegment>(&tcp);
    if (!segment) return out;
    out.ok = true;
    out.eth_src = frame->source;
    out.eth_dst = frame->destination;
    out.ip_src = packet->source;
    out.ip_dst = packet->destination;
    out.tcp = *segment;
    return out;
}

TcpSegment makePeerSynAck(std::uint16_t peer_port, std::uint16_t local_port,
                           std::uint32_t peer_isn, std::uint32_t ack, std::uint16_t window,
                           std::uint16_t peer_mss) {
    TcpSegment seg;
    seg.source_port = peer_port;
    seg.destination_port = local_port;
    seg.sequence_number = peer_isn;
    seg.acknowledgment_number = ack;
    seg.flags.syn = true;
    seg.flags.ack = true;
    seg.window_size = window;
    seg.urgent_pointer = 0;
    seg.options = {
        std::byte{2}, std::byte{4}, static_cast<std::byte>((peer_mss >> 8) & 0xff),
        static_cast<std::byte>(peer_mss & 0xff),
    };
    while (seg.options.size() % 4 != 0) {
        seg.options.push_back(std::byte{0});
    }
    return seg;
}

TcpSegment makeDataSegment(std::uint16_t peer_port, std::uint16_t local_port, std::uint32_t seq,
                            std::uint32_t ack, std::uint16_t window,
                            std::span<const std::byte> payload) {
    TcpSegment seg;
    seg.source_port = peer_port;
    seg.destination_port = local_port;
    seg.sequence_number = seq;
    seg.acknowledgment_number = ack;
    seg.flags.ack = true;
    seg.window_size = window;
    seg.payload.assign(payload.begin(), payload.end());
    return seg;
}

TcpSegment makeFin(std::uint16_t peer_port, std::uint16_t local_port, std::uint32_t seq,
                    std::uint32_t ack, std::uint16_t window) {
    TcpSegment seg;
    seg.source_port = peer_port;
    seg.destination_port = local_port;
    seg.sequence_number = seq;
    seg.acknowledgment_number = ack;
    seg.flags.ack = true;
    seg.flags.fin = true;
    seg.window_size = window;
    return seg;
}

// A small harness reproducing exactly what handleHttpClient in main.cpp
// does, so this test proves the same logic the runtime uses without
// linking main.cpp (which has no library target to link against).
struct ClientHarness {
    TcpConnectionTable table{8080};
    TcpConnectionKey key{localIp(), 49200, remoteIp(), 9090};
    HttpClientSession session;

    explicit ClientHarness(std::string target, std::uint16_t remote_port = 9090) {
        key.remote_port = remote_port;
        session.remote_ip = remoteIp();
        session.remote_port = remote_port;
        session.host_header = remoteIp().toString() + ":" + std::to_string(remote_port);
        session.target = std::move(target);
    }

    std::vector<std::vector<std::byte>> deliver(const TcpSegment& inbound,
                                                 TcpClock::time_point now) {
        std::vector<std::vector<std::byte>> out;
        auto result = table.handle(key, inbound, now);
        if (result.reply)
            out.push_back(wrap(*result.reply, localIp(), localMac(), remoteIp(), remoteMac()));
        if (result.fast_retransmit)
            out.push_back(
                wrap(*result.fast_retransmit, localIp(), localMac(), remoteIp(), remoteMac()));
        for (const auto& seg : result.scheduled)
            out.push_back(wrap(seg, localIp(), localMac(), remoteIp(), remoteMac()));

        if (result.connection_established && !session.request_enqueued) {
            auto request = buildHttpGetRequest(session.host_header, session.target);
            if (request) {
                auto sent = table.makeOutgoingData(key, *request, now);
                if (!sent.error) {
                    session.request_enqueued = true;
                    for (const auto& seg : sent.segments)
                        out.push_back(wrap(seg, localIp(), localMac(), remoteIp(), remoteMac()));
                } else {
                    session.failed = true;
                }
            } else {
                session.failed = true;
            }
        }

        if (session.response_complete) {
            // Completion is not proof the peer has nothing more to send
            // -- mirrors handleHttpClient in main.cpp.
            if (!result.accepted_payload.empty()) {
                session.failed = true;
            }
        } else if (!session.failed) {
            if (!result.accepted_payload.empty()) {
                appendHttpClientBytes(session, result.accepted_payload);
            }
            if (result.peer_closed) session.peer_fin_seen = true;

            if (session.response_overflowed) {
                session.failed = true;
            } else {
                auto parsed = parseHttpResponse(session.response_buffer, session.peer_fin_seen);
                if (parsed.status == HttpResponseParseStatus::Complete) {
                    session.response_complete = true;
                    session.status_code = *parsed.status_code;
                    session.body = std::move(parsed.body);
                } else if (parsed.status != HttpResponseParseStatus::Incomplete) {
                    session.failed = true;
                }
            }
        }

        if ((session.response_complete || session.failed) && !session.close_initiated) {
            session.close_initiated = true;
            auto close_result = table.beginClose(key, now);
            if (close_result.fin)
                out.push_back(
                    wrap(*close_result.fin, localIp(), localMac(), remoteIp(), remoteMac()));
        }
        return out;
    }
};


// --- Section 22: full packet-path proof ---------------------------------

void testFullClientPacketPath() {
    ClientHarness h("/");

    auto connect_result = h.table.beginConnect(h.key, t0);
    CHECK(connect_result.accepted);
    if (connect_result.accepted == false) return;
    std::uint32_t local_isn = connect_result.syn->sequence_number;

    auto syn_bytes = wrap(*connect_result.syn, localIp(), localMac(), remoteIp(), remoteMac());
    auto parsed_syn = parseWire(syn_bytes);
    CHECK(parsed_syn.ok);
    CHECK(parsed_syn.tcp.flags.syn);
    CHECK(parsed_syn.tcp.flags.ack == false);

    constexpr std::uint32_t kPeerIsn = 4000000;
    auto peer_syn_ack = makePeerSynAck(9090, 49200, kPeerIsn, local_isn + 1, 65535, 1460);
    auto syn_ack_bytes = wrap(peer_syn_ack, remoteIp(), remoteMac(), localIp(), localMac());
    auto parsed_syn_ack = parseWire(syn_ack_bytes);
    CHECK(parsed_syn_ack.ok);

    auto out1 = h.deliver(parsed_syn_ack.tcp, t0);
    CHECK(h.table.stateOf(h.key) == TcpState::Established);
    CHECK(h.session.request_enqueued);
    bool found_request = false;
    std::string expected_request =
        "GET / HTTP/1.0\r\nHost: 10.0.0.1:9090\r\nConnection: close\r\n\r\n";
    for (const auto& bytes : out1) {
        auto parsed = parseWire(bytes);
        CHECK(parsed.ok);
        if (parsed.ok) {
            CHECK(parsed.eth_dst == remoteMac());
            CHECK(parsed.ip_dst == remoteIp());
            CHECK(parsed.tcp.destination_port == 9090);
            CHECK(parsed.tcp.source_port == 49200);
            if (parsed.tcp.payload.empty() == false) {
                CHECK(found_request == false);
                found_request = true;
                CHECK(parsed.tcp.payload == toBytes(expected_request));
                CHECK(parsed.tcp.sequence_number == local_isn + 1);
            }
        }
    }
    CHECK(found_request);

    std::string response_head = "HTTP/1.0 200 OK\r\nContent-Length: 5\r\n\r\n";
    std::string body = "hello";
    std::uint32_t peer_seq = kPeerIsn + 1;
    std::uint32_t local_ack = local_isn + 1 + static_cast<std::uint32_t>(expected_request.size());

    auto part1 = toBytes(response_head.substr(0, 20));
    auto seg1 = makeDataSegment(9090, 49200, peer_seq, local_ack, 65535, part1);
    auto wire1 = wrap(seg1, remoteIp(), remoteMac(), localIp(), localMac());
    auto parsed1 = parseWire(wire1);
    CHECK(parsed1.ok);
    h.deliver(parsed1.tcp, t0);
    CHECK(h.session.response_complete == false);
    peer_seq += static_cast<std::uint32_t>(part1.size());

    std::string rest = response_head.substr(20) + body;
    auto part2 = toBytes(rest);
    auto seg2 = makeDataSegment(9090, 49200, peer_seq, local_ack, 65535, part2);
    auto wire2 = wrap(seg2, remoteIp(), remoteMac(), localIp(), localMac());
    auto parsed2 = parseWire(wire2);
    CHECK(parsed2.ok);
    auto out2 = h.deliver(parsed2.tcp, t0);
    CHECK(h.session.response_complete);
    CHECK(h.session.status_code == 200);
    CHECK(h.session.body == toBytes(body));
    peer_seq += static_cast<std::uint32_t>(part2.size());

    CHECK(h.table.stateOf(h.key) == TcpState::FinWait1 ||
          h.table.stateOf(h.key) == TcpState::FinWait2);
    bool found_local_fin = false;
    for (const auto& bytes : out2) {
        auto parsed = parseWire(bytes);
        if (parsed.ok && parsed.tcp.flags.fin) found_local_fin = true;
    }
    CHECK(found_local_fin);

    std::uint32_t local_fin_seq = local_ack;
    auto peer_fin = makeFin(9090, 49200, peer_seq, local_fin_seq + 1, 65535);
    auto fin_wire = wrap(peer_fin, remoteIp(), remoteMac(), localIp(), localMac());
    auto parsed_fin = parseWire(fin_wire);
    CHECK(parsed_fin.ok);
    auto result = h.table.handle(h.key, parsed_fin.tcp, t0);
    CHECK(result.peer_closed);
    CHECK(h.table.stateOf(h.key).has_value() == false ||
          h.table.stateOf(h.key) == TcpState::TimeWait);

    CHECK(h.session.request_enqueued);
    CHECK(h.session.response_complete);
}

// --- Section 30: server/client separation regression --------------------

void testActiveFinWithNoBytesDoesNotProduceHttp400() {
    ClientHarness h("/");
    auto connect_result = h.table.beginConnect(h.key, t0);
    CHECK(connect_result.accepted);
    std::uint32_t local_isn = connect_result.syn->sequence_number;
    auto peer_syn_ack = makePeerSynAck(9090, 49200, 5000000, local_isn + 1, 65535, 1460);
    h.deliver(peer_syn_ack, t0);
    CHECK(h.session.request_enqueued);

    std::string expected_request =
        "GET / HTTP/1.0\r\nHost: 10.0.0.1:9090\r\nConnection: close\r\n\r\n";
    std::uint32_t local_ack = local_isn + 1 + static_cast<std::uint32_t>(expected_request.size());

    auto peer_fin = makeFin(9090, 49200, 5000001, local_ack, 65535);
    auto out = h.deliver(peer_fin, t0);
    CHECK(h.session.failed);
    for (const auto& bytes : out) {
        auto parsed = parseWire(bytes);
        if (parsed.ok) {
            std::string_view text(reinterpret_cast<const char*>(parsed.tcp.payload.data()),
                                   parsed.tcp.payload.size());
            CHECK(text.find("400") == std::string_view::npos);
            CHECK(text.find("HTTP/1.0") == std::string_view::npos);
        }
    }
}

void testActiveInvalidPayloadDoesNotProduceHttp400() {
    ClientHarness h("/");
    auto connect_result = h.table.beginConnect(h.key, t0);
    std::uint32_t local_isn = connect_result.syn->sequence_number;
    auto peer_syn_ack = makePeerSynAck(9090, 49200, 6000000, local_isn + 1, 65535, 1460);
    h.deliver(peer_syn_ack, t0);
    CHECK(h.session.request_enqueued);

    std::string expected_request =
        "GET / HTTP/1.0\r\nHost: 10.0.0.1:9090\r\nConnection: close\r\n\r\n";
    std::uint32_t local_ack = local_isn + 1 + static_cast<std::uint32_t>(expected_request.size());

    auto garbage = toBytes("not an http response at all\r\n\r\n");
    auto seg = makeDataSegment(9090, 49200, 6000001, local_ack, 65535, garbage);
    auto out = h.deliver(seg, t0);
    CHECK(h.session.failed);
    for (const auto& bytes : out) {
        auto parsed = parseWire(bytes);
        if (parsed.ok) {
            std::string_view text(reinterpret_cast<const char*>(parsed.tcp.payload.data()),
                                   parsed.tcp.payload.size());
            CHECK(text.find("400") == std::string_view::npos);
        }
    }
}

// --- Section 28: request retransmission proof ---------------------------

void testRequestRetransmittedIdenticallyOnTimeout() {
    ClientHarness h("/");
    auto connect_result = h.table.beginConnect(h.key, t0);
    std::uint32_t local_isn = connect_result.syn->sequence_number;
    auto peer_syn_ack = makePeerSynAck(9090, 49200, 7000000, local_isn + 1, 65535, 1460);
    h.deliver(peer_syn_ack, t0);
    CHECK(h.session.request_enqueued);

    auto before = h.table.snapshotOf(h.key);
    CHECK(before.has_value());
    if (!before.has_value()) return;
    std::uint32_t snd_nxt_before = before->snd_nxt;

    auto due = h.table.pollRetransmissions(t0 + kInitialRto);
    CHECK(due.retransmissions.size() == 1);
    if (due.retransmissions.size() != 1) return;

    const TcpSegment& retransmitted = due.retransmissions.front().segment;
    std::string expected_request =
        "GET / HTTP/1.0\r\nHost: 10.0.0.1:9090\r\nConnection: close\r\n\r\n";
    CHECK(retransmitted.payload == toBytes(expected_request));
    CHECK(retransmitted.sequence_number == local_isn + 1);

    auto after = h.table.snapshotOf(h.key);
    CHECK(after.has_value());
    if (after.has_value()) {
        CHECK(after->snd_nxt == snd_nxt_before);
    }

    CHECK(h.session.request_enqueued);
    CHECK(h.session.response_complete == false);

    std::uint32_t local_ack = local_isn + 1 + static_cast<std::uint32_t>(expected_request.size());
    auto ack_only = makeDataSegment(9090, 49200, 7000001, local_ack, 65535, {});
    h.table.handle(h.key, ack_only, t0 + kInitialRto);
    auto final_snapshot = h.table.snapshotOf(h.key);
    CHECK(final_snapshot.has_value());
    if (final_snapshot.has_value()) {
        CHECK(final_snapshot->snd_una == local_ack);
        CHECK(final_snapshot->pending_count == 0);
    }
}

// --- Section 29: reordering + exactly-once HTTP delivery -----------------

void testReorderedResponseDeliveredOnce() {
    ClientHarness h("/");
    auto connect_result = h.table.beginConnect(h.key, t0);
    std::uint32_t local_isn = connect_result.syn->sequence_number;
    auto peer_syn_ack = makePeerSynAck(9090, 49200, 8000000, local_isn + 1, 65535, 1460);
    h.deliver(peer_syn_ack, t0);
    std::string expected_request =
        "GET / HTTP/1.0\r\nHost: 10.0.0.1:9090\r\nConnection: close\r\n\r\n";
    std::uint32_t local_ack = local_isn + 1 + static_cast<std::uint32_t>(expected_request.size());

    std::string response = "HTTP/1.0 200 OK\r\nContent-Length: 9\r\n\r\nsegmented";
    std::string a = response.substr(0, 30);
    std::string rest = response.substr(30);
    std::string b = rest.substr(0, rest.size() / 2);
    std::string c = rest.substr(rest.size() / 2);

    std::uint32_t seq_a = 8000001;
    std::uint32_t seq_b = seq_a + static_cast<std::uint32_t>(a.size());
    std::uint32_t seq_c = seq_b + static_cast<std::uint32_t>(b.size());

    auto seg_c = makeDataSegment(9090, 49200, seq_c, local_ack, 65535, toBytes(c));
    h.deliver(seg_c, t0);
    CHECK(h.session.response_buffer.empty());

    auto seg_a = makeDataSegment(9090, 49200, seq_a, local_ack, 65535, toBytes(a));
    h.deliver(seg_a, t0);
    CHECK(h.session.response_complete == false);
    CHECK(h.session.response_buffer == toBytes(a));

    auto seg_c_dup = makeDataSegment(9090, 49200, seq_c, local_ack, 65535, toBytes(c));
    h.deliver(seg_c_dup, t0);
    CHECK(h.session.response_buffer == toBytes(a));

    auto seg_b = makeDataSegment(9090, 49200, seq_b, local_ack, 65535, toBytes(b));
    h.deliver(seg_b, t0);
    CHECK(h.session.response_complete);
    CHECK(h.session.status_code == 200);
    CHECK(h.session.body == toBytes(std::string("segmented")));
}

// --- Section 32: bytes received after completion, real wire path --------

void testPostCompletionByteRejectedRealSegment() {
    ClientHarness h("/");
    auto connect_result = h.table.beginConnect(h.key, t0);
    std::uint32_t local_isn = connect_result.syn->sequence_number;
    constexpr std::uint32_t kPeerIsn = 9000000;
    auto peer_syn_ack = makePeerSynAck(9090, 49200, kPeerIsn, local_isn + 1, 65535, 1460);
    h.deliver(peer_syn_ack, t0);
    std::string expected_request =
        "GET / HTTP/1.0\r\nHost: 10.0.0.1:9090\r\nConnection: close\r\n\r\n";
    std::uint32_t local_ack = local_isn + 1 + static_cast<std::uint32_t>(expected_request.size());

    std::string response = "HTTP/1.0 200 OK\r\nContent-Length: 5\r\n\r\nhello";
    std::uint32_t peer_seq = kPeerIsn + 1;
    auto response_seg = makeDataSegment(9090, 49200, peer_seq, local_ack, 65535, toBytes(response));
    h.deliver(response_seg, t0);
    CHECK(h.session.response_complete);
    CHECK(!h.session.failed);
    CHECK(h.session.body == toBytes(std::string("hello")));
    peer_seq += static_cast<std::uint32_t>(response.size());

    // Wirestack has already sequenced its own FIN (state FinWait1/
    // FinWait2), but the peer can still legitimately send more payload
    // before acknowledging that FIN -- a real, otherwise-acceptable
    // in-order data segment carrying one extra byte on an
    // already-complete response. It must be rejected, not silently
    // absorbed as if the connection were still cleanly successful.
    auto extra_seg = makeDataSegment(9090, 49200, peer_seq, local_ack, 65535, toBytes("X"));
    auto wire = wrap(extra_seg, remoteIp(), remoteMac(), localIp(), localMac());
    auto parsed_extra = parseWire(wire);
    CHECK(parsed_extra.ok);
    auto out = h.deliver(parsed_extra.tcp, t0);
    (void)out;
    CHECK(h.session.failed);
    // The original exact body is not corrupted by the rejected byte.
    CHECK(h.session.body == toBytes(std::string("hello")));
}

} // namespace

int main() {
    testFullClientPacketPath();
    testActiveFinWithNoBytesDoesNotProduceHttp400();
    testActiveInvalidPayloadDoesNotProduceHttp400();
    testRequestRetransmittedIdenticallyOnTimeout();
    testReorderedResponseDeliveredOnce();
    testPostCompletionByteRejectedRealSegment();
    return wirestack::test::failureCount() == 0 ? 0 : 1;
}
