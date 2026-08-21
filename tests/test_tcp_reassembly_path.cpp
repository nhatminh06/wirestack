// Composed pure-packet-path tests for out-of-order receive reassembly:
// an HTTP request delivered in reverse-ish order through the real wire
// format (proving HTTP stays unaware of the reordering), and a generic
// loss/gap/duplicate scenario (segment A, then C, a duplicate C, then
// the missing B). Follows the established composed-test shape (no
// TapDevice, no root).

#include "wirestack/ethernet.hpp"
#include "wirestack/http.hpp"
#include "wirestack/ipv4.hpp"
#include "wirestack/mac_address.hpp"
#include "wirestack/tcp.hpp"
#include "wirestack/tcp_connection.hpp"

#include "test_util.hpp"

#include <map>

using namespace wirestack;

namespace {

std::vector<std::byte> toBytes(std::string_view text) {
    std::vector<std::byte> out;
    out.reserve(text.size());
    for (char c : text) {
        out.push_back(static_cast<std::byte>(static_cast<unsigned char>(c)));
    }
    return out;
}

MacAddress clientMac() {
    return *MacAddress::parse("aa:bb:cc:dd:ee:ff");
}
Ipv4Address clientIp() {
    return *Ipv4Address::parse("10.0.0.1");
}

std::vector<std::byte> buildFrame(const TcpSegment& segment, Ipv4Address source_ip,
                                   Ipv4Address dest_ip, MacAddress source_mac,
                                   MacAddress dest_mac) {
    auto tcp_bytes = serializeTcpSegment(segment, source_ip, dest_ip);
    Ipv4Packet ip_packet;
    ip_packet.ttl = 64;
    ip_packet.protocol = 6;
    ip_packet.source = source_ip;
    ip_packet.destination = dest_ip;
    ip_packet.payload = std::get<std::vector<std::byte>>(tcp_bytes);

    auto ip_bytes = serializeIpv4Packet(ip_packet);
    EthernetFrame frame;
    frame.destination = dest_mac;
    frame.source = source_mac;
    frame.ether_type = static_cast<std::uint16_t>(EtherType::Ipv4);
    frame.payload = std::get<std::vector<std::byte>>(ip_bytes);

    return serializeEthernetFrame(frame);
}

// Client 10.0.0.1/aa:bb:cc:dd:ee:ff:54321 -> server 10.0.0.2/
// 02:00:00:00:00:02:8080, client_isn=1000, offering MSS=1460 and Window
// Scale=2 -- a modern real client's SYN would carry both, and
// negotiating scaling here is what makes "window shrinks while
// buffering / reopens on release" provable at these small HTTP-request
// buffer sizes (an unscaled window stays pinned at 65535 until tens of
// thousands of bytes are buffered). Built through the real serializer,
// not hand-hex, to avoid a manually-computed checksum.
std::vector<std::byte> knownSynFrame() {
    TcpSegment syn;
    syn.source_port = 54321;
    syn.destination_port = 8080;
    syn.sequence_number = 1000;
    syn.acknowledgment_number = 0;
    syn.flags.syn = true;
    syn.window_size = 65535;
    syn.urgent_pointer = 0;
    syn.options = {std::byte{2}, std::byte{4}, std::byte{0x05}, std::byte{0xb4},
                    std::byte{1}, std::byte{3}, std::byte{3}, std::byte{2}};

    return buildFrame(syn, *Ipv4Address::parse("10.0.0.1"), *Ipv4Address::parse("10.0.0.2"),
                       *MacAddress::parse("aa:bb:cc:dd:ee:ff"),
                       *MacAddress::parse("02:00:00:00:00:02"));
}

struct ParsedFrame {
    EthernetFrame eth;
    Ipv4Packet ip;
    TcpSegment tcp;
};

std::optional<ParsedFrame> parseFrame(std::span<const std::byte> bytes) {
    auto eth_result = parseEthernetFrame(bytes);
    auto* frame = std::get_if<EthernetFrame>(&eth_result);
    CHECK(frame != nullptr);
    if (frame == nullptr) return std::nullopt;

    auto ip_result = parseIpv4Packet(frame->payload);
    auto* ip_packet = std::get_if<Ipv4Packet>(&ip_result);
    CHECK(ip_packet != nullptr);
    if (ip_packet == nullptr) return std::nullopt;

    auto tcp_result =
        parseTcpSegment(ip_packet->payload, ip_packet->source, ip_packet->destination);
    auto* segment = std::get_if<TcpSegment>(&tcp_result);
    CHECK(segment != nullptr);
    if (segment == nullptr) return std::nullopt;

    return ParsedFrame{*frame, *ip_packet, *segment};
}

struct Handshake {
    TcpSegment syn;
    std::uint32_t server_isn;
};

std::optional<Handshake> establishViaWire(TcpConnectionTable& connections,
                                           const TcpConnectionKey& key,
                                           TcpClock::time_point now) {
    auto syn = parseFrame(knownSynFrame());
    if (!syn) return std::nullopt;

    auto syn_ack = connections.handle(key, syn->tcp, now).reply;
    if (!syn_ack) return std::nullopt;
    std::uint32_t server_isn = syn_ack->sequence_number;

    TcpSegment final_ack;
    final_ack.source_port = syn->tcp.source_port;
    final_ack.destination_port = syn->tcp.destination_port;
    final_ack.sequence_number = syn->tcp.sequence_number + 1;
    final_ack.acknowledgment_number = server_isn + 1;
    final_ack.flags.ack = true;
    final_ack.window_size = 65535;
    connections.handle(key, final_ack, now);

    if (connections.stateOf(key) != TcpState::Established) return std::nullopt;
    return Handshake{syn->tcp, server_isn};
}

TcpReceiveResult deliverRange(TcpConnectionTable& connections, const TcpConnectionKey& key,
                               const Handshake& hs, Ipv4Address local_ip, MacAddress local_mac,
                               std::uint32_t sequence_number, std::string_view chunk,
                               TcpClock::time_point now) {
    TcpSegment client_segment;
    client_segment.source_port = hs.syn.source_port;
    client_segment.destination_port = hs.syn.destination_port;
    client_segment.sequence_number = sequence_number;
    client_segment.acknowledgment_number = 0; // unused by the receive path
    client_segment.flags.ack = true;
    client_segment.window_size = 65535;
    client_segment.payload = toBytes(chunk);

    auto frame_bytes = buildFrame(client_segment, clientIp(), local_ip, clientMac(), local_mac);
    auto parsed = parseFrame(frame_bytes);
    CHECK(parsed.has_value());
    if (!parsed) return {};
    return connections.handle(key, parsed->tcp, now);
}

} // namespace

int main() {
    auto local_ip = *Ipv4Address::parse("10.0.0.2");
    auto local_mac = *MacAddress::parse("02:00:00:00:00:02");
    constexpr TcpClock::time_point t0{};

    // --- Reverse-order HTTP request through the real wire format ---
    {
        TcpConnectionTable connections(8080);
        std::map<TcpConnectionKey, HttpConnectionState> http_sessions;
        TcpConnectionKey key{local_ip, 8080, clientIp(), 54321};

        auto hs = establishViaWire(connections, key, t0);
        CHECK(hs.has_value());
        if (!hs) return wirestack::test::failureCount() == 0 ? 0 : 1;

        std::string_view range1 = "GET / HTTP/1.0\r\n";      // 16 bytes
        std::string_view range2 = "Host: wirestack\r\n";     // 17 bytes
        std::string_view range3 = "\r\n";                    // 2 bytes
        std::uint32_t base = hs->syn.sequence_number + 1;
        std::uint32_t seq1 = base;
        std::uint32_t seq2 = base + static_cast<std::uint32_t>(range1.size());
        std::uint32_t seq3 = seq2 + static_cast<std::uint32_t>(range2.size());

        // Window before any buffering (Window Scale negotiated, so this
        // is measurable even for the small buffer sizes used below --
        // an unscaled window would stay pinned at 65535 until tens of
        // thousands of bytes were buffered).
        auto snap_before = connections.snapshotOf(key);
        CHECK(snap_before.has_value());
        std::uint16_t full_window = snap_before ? snap_before->advertised_window : 0;

        // Deliver the final range first.
        auto r3 = deliverRange(connections, key, *hs, local_ip, local_mac, seq3, range3, t0);
        CHECK(r3.accepted_payload.empty());
        CHECK(r3.reply.has_value());
        if (r3.reply) CHECK(r3.reply->acknowledgment_number == base); // gap still at the start
        auto snap_after_r3 = connections.snapshotOf(key);
        CHECK(snap_after_r3.has_value());
        if (snap_after_r3) {
            CHECK(snap_after_r3->advertised_window < full_window); // shrunk while buffering
        }

        // Deliver the middle range.
        auto r2 = deliverRange(connections, key, *hs, local_ip, local_mac, seq2, range2, t0);
        CHECK(r2.accepted_payload.empty());
        CHECK(r2.reply.has_value());
        if (r2.reply) CHECK(r2.reply->acknowledgment_number == base); // duplicate ACKs identify the gap
        CHECK(http_sessions.find(key) == http_sessions.end()); // HTTP receives nothing so far

        // Deliver the first range: the gap closes, releasing the whole
        // request in one call.
        auto r1 = deliverRange(connections, key, *hs, local_ip, local_mac, seq1, range1, t0);
        CHECK(r1.accepted_payload == toBytes("GET / HTTP/1.0\r\nHost: wirestack\r\n\r\n"));

        auto snap_after_release = connections.snapshotOf(key);
        CHECK(snap_after_release.has_value());
        if (snap_after_release && full_window != 0) {
            CHECK(snap_after_release->advertised_window == full_window); // window reopened
        }

        appendHttpBytes(http_sessions[key], r1.accepted_payload);
        auto parsed_request = parseHttpRequest(http_sessions[key].buffer);
        CHECK(parsed_request.status == HttpParseStatus::Complete);
        CHECK(parsed_request.request.has_value());
        if (!parsed_request.request) return wirestack::test::failureCount() == 0 ? 0 : 1;
        CHECK(parsed_request.request->target == "/");

        auto response = selectResponse(*parsed_request.request);
        CHECK(response.status == HttpStatus::Ok200);
        auto response_bytes = serializeHttpResponse(response);
        auto expected_200 = toBytes(
            "HTTP/1.0 200 OK\r\n"
            "Content-Type: text/plain; charset=utf-8\r\n"
            "Content-Length: 21\r\n"
            "Connection: close\r\n"
            "\r\n"
            "Hello from Wirestack\n");
        CHECK(response_bytes == expected_200); // exact 200, produced exactly once

        http_sessions[key].responded = true;
        auto sent = connections.makeOutgoingData(key, response_bytes, t0);
        CHECK(!sent.segments.empty());
        if (sent.segments.empty()) return wirestack::test::failureCount() == 0 ? 0 : 1;
        const auto& sent_segment = sent.segments.front();

        auto resp_frame = buildFrame(sent_segment, local_ip, clientIp(), local_mac, clientMac());
        auto parsed_resp = parseFrame(resp_frame); // validates checksums
        CHECK(parsed_resp.has_value());
        if (parsed_resp) CHECK(parsed_resp->tcp.payload == response_bytes);

        auto fin_result = connections.beginClose(key, t0);
        CHECK(fin_result.accepted);
        auto fin = fin_result.fin;
        CHECK(fin.has_value());
        CHECK(connections.stateOf(key) == TcpState::FinWait1);

        // Finish the FIN lifecycle.
        if (fin) {
            TcpSegment client_ack;
            client_ack.source_port = hs->syn.source_port;
            client_ack.destination_port = hs->syn.destination_port;
            client_ack.sequence_number = seq3 + static_cast<std::uint32_t>(range3.size());
            client_ack.acknowledgment_number = fin->sequence_number + 1;
            client_ack.flags.ack = true;
            client_ack.window_size = 65535;
            connections.handle(key, client_ack, t0);
            CHECK(connections.stateOf(key) == TcpState::FinWait2);

            TcpSegment client_fin;
            client_fin.source_port = hs->syn.source_port;
            client_fin.destination_port = hs->syn.destination_port;
            client_fin.sequence_number = client_ack.sequence_number;
            client_fin.acknowledgment_number = fin->sequence_number + 1;
            client_fin.flags.ack = true;
            client_fin.flags.fin = true;
            client_fin.window_size = 65535;
            auto result = connections.handle(key, client_fin, t0);
            CHECK(result.peer_closed);
            CHECK(connections.stateOf(key) == TcpState::TimeWait);
        }
    }

    // --- Loss/gap scenario: A, C, duplicate C, then B ---
    {
        TcpConnectionTable connections(8080);
        TcpConnectionKey key{local_ip, 8080, clientIp(), 54322};
        auto hs = establishViaWire(connections, key, t0);
        CHECK(hs.has_value());
        if (!hs) return wirestack::test::failureCount() == 0 ? 0 : 1;

        std::uint32_t base = hs->syn.sequence_number + 1;
        std::string_view a = "AAA";
        std::string_view b = "BBB";
        std::string_view c = "CCC";
        std::uint32_t seq_a = base;
        std::uint32_t seq_b = base + 3;
        std::uint32_t seq_c = base + 6;

        auto ra = deliverRange(connections, key, *hs, local_ip, local_mac, seq_a, a, t0);
        CHECK(ra.accepted_payload == toBytes("AAA")); // A delivered once

        auto rc1 = deliverRange(connections, key, *hs, local_ip, local_mac, seq_c, c, t0);
        CHECK(rc1.accepted_payload.empty()); // C buffered, not yet contiguous
        auto snap_after_c = connections.snapshotOf(key);
        CHECK(snap_after_c.has_value());
        if (snap_after_c) CHECK(snap_after_c->reassembly_buffered_bytes == 3);

        auto rc2 = deliverRange(connections, key, *hs, local_ip, local_mac, seq_c, c, t0);
        CHECK(rc2.accepted_payload.empty()); // duplicate C adds no memory
        auto snap_after_dup_c = connections.snapshotOf(key);
        CHECK(snap_after_dup_c.has_value());
        if (snap_after_dup_c) CHECK(snap_after_dup_c->reassembly_buffered_bytes == 3); // unchanged
        if (rc2.reply) CHECK(rc2.reply->acknowledgment_number == seq_b); // ACK stays at start of B

        auto rb = deliverRange(connections, key, *hs, local_ip, local_mac, seq_b, b, t0);
        CHECK(rb.accepted_payload == toBytes("BBBCCC")); // B arrival releases B+C in order

        auto final_snapshot = connections.snapshotOf(key);
        CHECK(final_snapshot.has_value());
        if (final_snapshot) CHECK(final_snapshot->rcv_nxt == seq_c + 3); // final ACK covers A+B+C
    }

    return wirestack::test::failureCount() == 0 ? 0 : 1;
}
