// Composed pure-packet-path tests for the HTTP/1.0 GET demonstration:
// a successful segmented request, a malformed request, and response
// retransmission -- all through the real Ethernet/IPv4/TCP wire format,
// mirroring main.cpp's own dispatch (TCP accept -> HTTP buffer -> parse
// -> response -> TCP send -> FIN close) without TapDevice or root.

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

std::vector<std::byte> knownSynFrame() {
    std::vector<std::byte> out;
    for (std::uint8_t v : {
             0x02, 0x00, 0x00, 0x00, 0x00, 0x02, // Ethernet destination: Wirestack
             0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, // Ethernet source: host
             0x08, 0x00,                         // EtherType: IPv4
             0x45, 0x00, 0x00, 0x28, 0x1c, 0x46, 0x40, 0x00, 0x40, 0x06, 0x0a, 0x88, 0x0a, 0x00,
             0x00, 0x01, 0x0a, 0x00, 0x00, 0x02, 0xd4, 0x31, 0x1f, 0x90, 0x00, 0x00, 0x03, 0xe8,
             0x00, 0x00, 0x00, 0x00, 0x50, 0x02, 0xff, 0xff, 0xa4, 0x36, 0x00, 0x00,
         }) {
        out.push_back(static_cast<std::byte>(v));
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
                                           const TcpConnectionKey& key, TcpClock::time_point now) {
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

// Delivers `payload` as one client TCP segment at `sequence_number`, runs
// it through `connections`, and appends any accepted bytes into the HTTP
// session for `key` -- exactly what main.cpp's handleTcp does, minus the
// TapDevice/logging concerns.
TcpReceiveResult deliverAndBuffer(TcpConnectionTable& connections,
                                   std::map<TcpConnectionKey, HttpConnectionState>& sessions,
                                   const TcpConnectionKey& key, const Handshake& hs,
                                   std::uint32_t sequence_number, std::string_view payload,
                                   bool fin, TcpClock::time_point now) {
    TcpSegment client_segment;
    client_segment.source_port = hs.syn.source_port;
    client_segment.destination_port = hs.syn.destination_port;
    client_segment.sequence_number = sequence_number;
    client_segment.acknowledgment_number = hs.server_isn + 1;
    client_segment.flags.ack = true;
    client_segment.flags.fin = fin;
    client_segment.window_size = 65535;
    client_segment.payload = toBytes(payload);

    auto frame_bytes = buildFrame(client_segment, clientIp(), *Ipv4Address::parse("10.0.0.2"),
                                   clientMac(), *MacAddress::parse("02:00:00:00:00:02"));
    auto parsed = parseFrame(frame_bytes);
    CHECK(parsed.has_value());
    if (!parsed) return {};

    auto result = connections.handle(key, parsed->tcp, now);
    if (!result.accepted_payload.empty()) {
        appendHttpBytes(sessions[key], result.accepted_payload);
    }
    return result;
}

} // namespace

int main() {
    auto local_ip = *Ipv4Address::parse("10.0.0.2");
    auto local_mac = *MacAddress::parse("02:00:00:00:00:02");
    constexpr TcpClock::time_point t0{};

    // --- Pure HTTP packet-path: success, segmented across two TCP sends ---
    {
        TcpConnectionTable connections(8080);
        std::map<TcpConnectionKey, HttpConnectionState> http_sessions;
        TcpConnectionKey key{local_ip, 8080, clientIp(), 54321};

        auto hs = establishViaWire(connections, key, t0);
        CHECK(hs.has_value());
        if (!hs) return wirestack::test::failureCount() == 0 ? 0 : 1;

        // Segment 1: "GET / HT" -- incomplete, no response yet.
        auto result1 = deliverAndBuffer(connections, http_sessions, key, *hs,
                                         hs->syn.sequence_number + 1, "GET / HT", false, t0);
        CHECK(result1.accepted_payload == toBytes("GET / HT")); // delivered, not echoed
        auto parse1 = parseHttpRequest(http_sessions[key].buffer);
        CHECK(parse1.status == HttpParseStatus::Incomplete);
        CHECK(connections.snapshotOf(key)->pending_count == 0); // nothing sent yet

        // Segment 2: completes the request.
        auto result2 = deliverAndBuffer(connections, http_sessions, key, *hs,
                                         hs->syn.sequence_number + 1 + 8,
                                         "TP/1.0\r\nHost: wirestack\r\n\r\n", false, t0);
        CHECK(!result2.accepted_payload.empty());

        auto parse2 = parseHttpRequest(http_sessions[key].buffer);
        CHECK(parse2.status == HttpParseStatus::Complete);
        CHECK(parse2.request.has_value());
        if (!parse2.request) return wirestack::test::failureCount() == 0 ? 0 : 1;
        CHECK(parse2.request->target == "/");

        auto response = selectResponse(*parse2.request);
        CHECK(response.status == HttpStatus::Ok200);
        auto response_bytes = serializeHttpResponse(response);
        auto expected_200 = toBytes(
            "HTTP/1.0 200 OK\r\n"
            "Content-Type: text/plain; charset=utf-8\r\n"
            "Content-Length: 21\r\n"
            "Connection: close\r\n"
            "\r\n"
            "Hello from Wirestack\n");
        CHECK(response_bytes == expected_200);

        http_sessions[key].responded = true;
        auto sent = connections.makeOutgoingData(key, response_bytes, t0);
        CHECK(sent.has_value());
        if (!sent) return wirestack::test::failureCount() == 0 ? 0 : 1;
        CHECK(sent->sequence_number == hs->server_isn + 1); // no prior sends

        auto fin = connections.beginClose(key, t0);
        CHECK(fin.has_value());
        if (!fin) return wirestack::test::failureCount() == 0 ? 0 : 1;
        CHECK(fin->sequence_number ==
              sent->sequence_number + static_cast<std::uint32_t>(sent->payload.size()));
        CHECK(connections.stateOf(key) == TcpState::FinWait1);

        // Re-parse both outgoing segments through the real wire format.
        auto resp_frame = buildFrame(*sent, local_ip, clientIp(), local_mac, clientMac());
        auto parsed_resp = parseFrame(resp_frame);
        CHECK(parsed_resp.has_value());
        if (parsed_resp) {
            CHECK(parsed_resp->eth.source == local_mac);
            CHECK(parsed_resp->eth.destination == clientMac());
            CHECK(parsed_resp->ip.source == local_ip);
            CHECK(parsed_resp->ip.destination == clientIp());
            CHECK(parsed_resp->tcp.source_port == 8080);
            CHECK(parsed_resp->tcp.destination_port == hs->syn.source_port);
            CHECK(parsed_resp->tcp.payload == response_bytes);
            CHECK(parsed_resp->tcp.sequence_number == sent->sequence_number);
        }

        auto fin_frame = buildFrame(*fin, local_ip, clientIp(), local_mac, clientMac());
        auto parsed_fin = parseFrame(fin_frame);
        CHECK(parsed_fin.has_value());
        if (parsed_fin) {
            CHECK(parsed_fin->tcp.flags.fin);
            CHECK(parsed_fin->tcp.flags.ack);
            CHECK(parsed_fin->tcp.sequence_number == fin->sequence_number);
        }

        // Client's cumulative ACK of the response and the FIN.
        TcpSegment client_ack;
        client_ack.source_port = hs->syn.source_port;
        client_ack.destination_port = hs->syn.destination_port;
        client_ack.sequence_number = hs->syn.sequence_number + 1 + 8 +
                                      static_cast<std::uint32_t>(
                                          std::string_view("TP/1.0\r\nHost: wirestack\r\n\r\n")
                                              .size());
        client_ack.acknowledgment_number = fin->sequence_number + 1;
        client_ack.flags.ack = true;
        client_ack.window_size = 65535;
        auto ack_frame = buildFrame(client_ack, clientIp(), local_ip, clientMac(), local_mac);
        auto parsed_ack = parseFrame(ack_frame);
        CHECK(parsed_ack.has_value());
        if (parsed_ack) {
            connections.handle(key, parsed_ack->tcp, t0);
        }
        CHECK(connections.stateOf(key) == TcpState::FinWait2);
        CHECK(connections.snapshotOf(key)->pending_count == 0); // response + FIN both retired

        // Client's own FIN.
        TcpSegment client_fin;
        client_fin.source_port = hs->syn.source_port;
        client_fin.destination_port = hs->syn.destination_port;
        client_fin.sequence_number = client_ack.sequence_number;
        client_fin.acknowledgment_number = fin->sequence_number + 1;
        client_fin.flags.ack = true;
        client_fin.flags.fin = true;
        client_fin.window_size = 65535;
        auto client_fin_frame =
            buildFrame(client_fin, clientIp(), local_ip, clientMac(), local_mac);
        auto parsed_client_fin = parseFrame(client_fin_frame);
        CHECK(parsed_client_fin.has_value());
        if (!parsed_client_fin) return wirestack::test::failureCount() == 0 ? 0 : 1;

        auto result3 = connections.handle(key, parsed_client_fin->tcp, t0);
        CHECK(result3.peer_closed);
        CHECK(connections.stateOf(key) == TcpState::TimeWait);
        CHECK(result3.reply.has_value());
        if (result3.reply) {
            CHECK(result3.reply->acknowledgment_number == client_fin.sequence_number + 1);
        }

        auto expired = connections.pollRetransmissions(t0 + kTimeWaitDuration);
        CHECK(expired.time_wait_expired.size() == 1);
        CHECK(!connections.stateOf(key).has_value());
        for (const auto& expired_key : expired.time_wait_expired) {
            http_sessions.erase(expired_key);
        }
        CHECK(http_sessions.find(key) == http_sessions.end()); // HTTP session removed
    }

    // --- Error packet-path: malformed request -> 400 -> close ---
    {
        TcpConnectionTable connections(8080);
        std::map<TcpConnectionKey, HttpConnectionState> http_sessions;
        TcpConnectionKey key{local_ip, 8080, clientIp(), 54322};

        auto hs = establishViaWire(connections, key, t0);
        CHECK(hs.has_value());
        if (!hs) return wirestack::test::failureCount() == 0 ? 0 : 1;

        // Double space between method and target: malformed.
        auto result = deliverAndBuffer(connections, http_sessions, key, *hs,
                                        hs->syn.sequence_number + 1, "GET  / HTTP/1.0\r\n\r\n",
                                        false, t0);
        CHECK(!result.accepted_payload.empty());
        auto parsed = parseHttpRequest(http_sessions[key].buffer);
        CHECK(parsed.status == HttpParseStatus::Malformed);

        auto response = makeBadRequestResponse();
        auto response_bytes = serializeHttpResponse(response);
        auto expected_400 = toBytes(
            "HTTP/1.0 400 Bad Request\r\n"
            "Content-Type: text/plain; charset=utf-8\r\n"
            "Content-Length: 12\r\n"
            "Connection: close\r\n"
            "\r\n"
            "Bad Request\n");
        CHECK(response_bytes == expected_400);
        CHECK(response_bytes != toBytes("GET  / HTTP/1.0\r\n\r\n")); // not echoed

        http_sessions[key].responded = true;
        auto sent = connections.makeOutgoingData(key, response_bytes, t0);
        CHECK(sent.has_value());
        auto fin = connections.beginClose(key, t0);
        CHECK(fin.has_value());
        CHECK(connections.stateOf(key) == TcpState::FinWait1);
        if (!sent || !fin) return wirestack::test::failureCount() == 0 ? 0 : 1;

        auto resp_frame = buildFrame(*sent, local_ip, clientIp(), local_mac, clientMac());
        auto parsed_resp = parseFrame(resp_frame);
        CHECK(parsed_resp.has_value());
        if (parsed_resp) CHECK(parsed_resp->tcp.payload == response_bytes);

        TcpSegment client_ack;
        client_ack.source_port = hs->syn.source_port;
        client_ack.destination_port = hs->syn.destination_port;
        client_ack.sequence_number = hs->syn.sequence_number + 1 +
                                      static_cast<std::uint32_t>(
                                          std::string_view("GET  / HTTP/1.0\r\n\r\n").size());
        client_ack.acknowledgment_number = fin->sequence_number + 1;
        client_ack.flags.ack = true;
        client_ack.window_size = 65535;
        auto ack_frame = buildFrame(client_ack, clientIp(), local_ip, clientMac(), local_mac);
        auto parsed_ack = parseFrame(ack_frame);
        CHECK(parsed_ack.has_value());
        if (parsed_ack) connections.handle(key, parsed_ack->tcp, t0);
        CHECK(connections.stateOf(key) == TcpState::FinWait2);

        TcpSegment client_fin;
        client_fin.source_port = hs->syn.source_port;
        client_fin.destination_port = hs->syn.destination_port;
        client_fin.sequence_number = client_ack.sequence_number;
        client_fin.acknowledgment_number = fin->sequence_number + 1;
        client_fin.flags.ack = true;
        client_fin.flags.fin = true;
        client_fin.window_size = 65535;
        auto client_fin_frame =
            buildFrame(client_fin, clientIp(), local_ip, clientMac(), local_mac);
        auto parsed_client_fin = parseFrame(client_fin_frame);
        CHECK(parsed_client_fin.has_value());
        if (parsed_client_fin) {
            auto result_fin = connections.handle(key, parsed_client_fin->tcp, t0);
            CHECK(result_fin.peer_closed);
        }
        CHECK(connections.stateOf(key) == TcpState::TimeWait); // closes through real TCP state machine

        CHECK(http_sessions.find(key) != http_sessions.end()); // not lost while connection lives
        CHECK(http_sessions[key].responded); // does not remain "unprocessed"
    }

    // --- Retransmission regression: HTTP response uses ordinary TCP retransmission ---
    {
        TcpConnectionTable connections(8080);
        std::map<TcpConnectionKey, HttpConnectionState> http_sessions;
        TcpConnectionKey key{local_ip, 8080, clientIp(), 54323};

        auto hs = establishViaWire(connections, key, t0);
        CHECK(hs.has_value());
        if (!hs) return wirestack::test::failureCount() == 0 ? 0 : 1;

        auto result = deliverAndBuffer(connections, http_sessions, key, *hs,
                                        hs->syn.sequence_number + 1, "GET / HTTP/1.0\r\n\r\n",
                                        false, t0);
        CHECK(!result.accepted_payload.empty());
        auto parsed = parseHttpRequest(http_sessions[key].buffer);
        CHECK(parsed.status == HttpParseStatus::Complete);
        if (!parsed.request) return wirestack::test::failureCount() == 0 ? 0 : 1;

        auto response_bytes = serializeHttpResponse(selectResponse(*parsed.request));
        auto sent = connections.makeOutgoingData(key, response_bytes, t0); // intentionally dropped
        CHECK(sent.has_value());
        auto fin = connections.beginClose(key, t0);
        CHECK(fin.has_value());
        if (!sent || !fin) return wirestack::test::failureCount() == 0 ? 0 : 1;

        auto before = connections.snapshotOf(key);
        auto due = connections.pollRetransmissions(t0 + kInitialRto);
        CHECK(due.retransmissions.size() == 1);
        if (due.retransmissions.size() == 1) {
            CHECK(due.retransmissions[0].segment.payload == response_bytes);
            CHECK(due.retransmissions[0].segment.sequence_number == sent->sequence_number);
        }
        auto after = connections.snapshotOf(key);
        CHECK(before.has_value() && after.has_value());
        if (before && after) {
            CHECK(after->snd_nxt == before->snd_nxt); // did not advance again
        }

        TcpSegment client_ack;
        client_ack.source_port = hs->syn.source_port;
        client_ack.destination_port = hs->syn.destination_port;
        client_ack.sequence_number =
            hs->syn.sequence_number + 1 +
            static_cast<std::uint32_t>(std::string_view("GET / HTTP/1.0\r\n\r\n").size());
        client_ack.acknowledgment_number = fin->sequence_number + 1; // cumulative: response + FIN
        client_ack.flags.ack = true;
        client_ack.window_size = 65535;
        connections.handle(key, client_ack, t0 + kInitialRto);

        auto final_snapshot = connections.snapshotOf(key);
        CHECK(final_snapshot.has_value());
        if (final_snapshot) {
            CHECK(final_snapshot->pending_count == 0);
        }
        CHECK(connections.stateOf(key) == TcpState::FinWait2);
    }

    return wirestack::test::failureCount() == 0 ? 0 : 1;
}
