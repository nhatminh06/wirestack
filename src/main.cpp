#include <algorithm>
#include <array>
#include <chrono>
#include <cstdio>
#include <cstdlib>
#include <limits>
#include <map>
#include <optional>
#include <string>
#include <variant>

#include "wirestack/arp.hpp"
#include "wirestack/arp_cache.hpp"
#include "wirestack/ethernet.hpp"
#include "wirestack/http.hpp"
#include "wirestack/http_client.hpp"
#include "wirestack/icmp.hpp"
#include "wirestack/ipv4.hpp"
#include "wirestack/ipv4_address.hpp"
#include "wirestack/mac_address.hpp"
#include "wirestack/runtime_options.hpp"
#include "wirestack/tap_device.hpp"
#include "wirestack/tcp.hpp"
#include "wirestack/tcp_connection.hpp"
#include "wirestack/udp.hpp"
#include "wirestack/udp_endpoint.hpp"

namespace {

// Ethernet MTU (1500) + 14-byte header + slack for jumbo/oversized frames
// the kernel might still hand us.
constexpr std::size_t kReceiveBufferSize = 2048;

const char* etherTypeLabel(std::uint16_t ether_type) {
    switch (static_cast<wirestack::EtherType>(ether_type)) {
        case wirestack::EtherType::Arp:
            return "arp";
        case wirestack::EtherType::Ipv4:
            return "ipv4";
    }
    return nullptr;
}

void printFrame(const wirestack::EthernetFrame& frame, std::size_t total_bytes) {
    const char* label = etherTypeLabel(frame.ether_type);
    unsigned int ether_type = frame.ether_type;
    if (label != nullptr) {
        std::printf("ethernet src=%s dst=%s type=0x%04x(%s) len=%zu\n",
                    frame.source.toString().c_str(), frame.destination.toString().c_str(),
                    ether_type, label, total_bytes);
    } else {
        std::printf("ethernet src=%s dst=%s type=0x%04x len=%zu\n",
                    frame.source.toString().c_str(), frame.destination.toString().c_str(),
                    ether_type, total_bytes);
    }
}

// Parses the ARP payload, learns the sender mapping into `cache`, and (for
// requests targeting `local_ip`) writes an Ethernet-wrapped ARP reply back
// through `tap`. Returns nothing; failures are reported to stdout/stderr
// directly, matching the rest of the receive loop.
void handleArp(wirestack::TapDevice& tap, wirestack::ArpCache& cache,
               wirestack::Ipv4Address local_ip, wirestack::MacAddress local_mac,
               const wirestack::EthernetFrame& frame) {
    auto parsed = wirestack::parseArpPacket(frame.payload);
    if (!std::holds_alternative<wirestack::ArpPacket>(parsed)) {
        std::printf("arp: dropped malformed packet\n");
        return;
    }

    const auto& request = std::get<wirestack::ArpPacket>(parsed);
    cache.insert(request.sender_ip, request.sender_mac);

    if (request.operation != wirestack::ArpOperation::Request) {
        return;
    }

    std::printf("arp request sender=%s/%s target=%s\n", request.sender_ip.toString().c_str(),
                request.sender_mac.toString().c_str(), request.target_ip.toString().c_str());

    auto reply = wirestack::maybeReply(request, local_ip, local_mac);
    if (!reply) {
        return;
    }

    wirestack::EthernetFrame reply_frame;
    reply_frame.destination = request.sender_mac;
    reply_frame.source = local_mac;
    reply_frame.ether_type = static_cast<std::uint16_t>(wirestack::EtherType::Arp);
    reply_frame.payload = wirestack::serializeArpPacket(*reply);

    auto serialized = wirestack::serializeEthernetFrame(reply_frame);
    auto write_result = tap.write(serialized);
    if (auto* error = std::get_if<std::string>(&write_result)) {
        std::fprintf(stderr, "wirestack: arp reply write failed: %s\n", error->c_str());
        return;
    }

    std::printf("arp reply target=%s/%s\n", reply->target_ip.toString().c_str(),
                reply->target_mac.toString().c_str());
}

// Writes an Echo Reply, wrapped in IPv4 and Ethernet, back through `tap`.
// Ethernet/IPv4 addressing both come directly from the frame/packet just
// received (the sender's MAC and IP are already known from it), not from
// the ARP cache -- there is nothing to look up.
void sendEchoReply(wirestack::TapDevice& tap, wirestack::Ipv4Address local_ip,
                    wirestack::MacAddress local_mac, const wirestack::Ipv4Packet& ip_packet,
                    const wirestack::EthernetFrame& eth_frame, const wirestack::IcmpEcho& request) {
    auto reply = wirestack::makeEchoReply(request);

    wirestack::Ipv4Packet reply_packet;
    reply_packet.ttl = 64;
    reply_packet.protocol = ip_packet.protocol;
    reply_packet.source = local_ip;
    reply_packet.destination = ip_packet.source;
    reply_packet.payload = wirestack::serializeIcmpEcho(reply);

    auto serialized_ipv4 = wirestack::serializeIpv4Packet(reply_packet);
    if (std::holds_alternative<wirestack::Ipv4SerializeError>(serialized_ipv4)) {
        std::printf("ipv4: dropped outgoing packet: payload too large\n");
        return;
    }

    wirestack::EthernetFrame reply_frame;
    reply_frame.destination = eth_frame.source;
    reply_frame.source = local_mac;
    reply_frame.ether_type = static_cast<std::uint16_t>(wirestack::EtherType::Ipv4);
    reply_frame.payload = std::get<std::vector<std::byte>>(serialized_ipv4);

    auto serialized = wirestack::serializeEthernetFrame(reply_frame);
    auto write_result = tap.write(serialized);
    if (auto* error = std::get_if<std::string>(&write_result)) {
        std::fprintf(stderr, "wirestack: icmp echo reply write failed: %s\n", error->c_str());
        return;
    }

    std::printf("icmp echo-reply id=%u seq=%u len=%zu\n", static_cast<unsigned int>(reply.identifier),
                static_cast<unsigned int>(reply.sequence), reply.payload.size());
}

void handleIcmp(wirestack::TapDevice& tap, wirestack::Ipv4Address local_ip,
                wirestack::MacAddress local_mac, const wirestack::Ipv4Packet& ip_packet,
                const wirestack::EthernetFrame& eth_frame) {
    auto parsed = wirestack::parseIcmpEcho(ip_packet.payload);
    if (!std::holds_alternative<wirestack::IcmpEcho>(parsed)) {
        std::printf("icmp: dropped malformed packet\n");
        return;
    }

    const auto& message = std::get<wirestack::IcmpEcho>(parsed);
    if (message.type != wirestack::IcmpEchoType::EchoRequest) {
        return; // an Echo Reply is parsed and ignored, never itself replied to
    }

    std::printf("icmp echo-request id=%u seq=%u len=%zu\n",
                static_cast<unsigned int>(message.identifier),
                static_cast<unsigned int>(message.sequence), message.payload.size());

    sendEchoReply(tap, local_ip, local_mac, ip_packet, eth_frame, message);
}

// Parses the UDP datagram, looks it up in `endpoints`, and (if bound)
// writes an Ethernet/IPv4/UDP-wrapped reply back through `tap`. Ethernet
// and IPv4 addressing come directly from the frame/packet just received,
// same rationale as the ICMP reply path.
void handleUdp(wirestack::TapDevice& tap, wirestack::Ipv4Address local_ip,
               wirestack::MacAddress local_mac, const wirestack::UdpEndpointTable& endpoints,
               const wirestack::Ipv4Packet& ip_packet, const wirestack::EthernetFrame& eth_frame) {
    auto parsed = wirestack::parseUdpDatagram(ip_packet.payload, ip_packet.source,
                                               ip_packet.destination);
    if (!std::holds_alternative<wirestack::UdpDatagram>(parsed)) {
        std::printf("udp: dropped malformed datagram\n");
        return;
    }

    const auto& datagram = std::get<wirestack::UdpDatagram>(parsed);
    std::printf("udp src=%s:%u dst=%s:%u len=%zu\n", ip_packet.source.toString().c_str(),
                static_cast<unsigned int>(datagram.source_port),
                ip_packet.destination.toString().c_str(),
                static_cast<unsigned int>(datagram.destination_port),
                8 + datagram.payload.size());

    auto response = endpoints.deliver(datagram.destination_port, datagram.payload);
    if (!response) {
        return; // no endpoint bound to this port -- not an error
    }

    // Port 0 has no valid meaning as a reply destination; a request with
    // source port 0 is parsed and delivered, but no reply is sent.
    if (datagram.source_port == 0) {
        return;
    }

    wirestack::UdpDatagram reply;
    reply.source_port = datagram.destination_port;
    reply.destination_port = datagram.source_port;
    reply.payload = std::move(*response);

    auto serialized_udp = wirestack::serializeUdpDatagram(reply, local_ip, ip_packet.source);
    if (std::holds_alternative<wirestack::UdpSerializeError>(serialized_udp)) {
        std::printf("udp: dropped outgoing datagram: payload too large\n");
        return;
    }

    wirestack::Ipv4Packet reply_packet;
    reply_packet.ttl = 64;
    reply_packet.protocol = ip_packet.protocol;
    reply_packet.source = local_ip;
    reply_packet.destination = ip_packet.source;
    reply_packet.payload = std::get<std::vector<std::byte>>(serialized_udp);

    auto serialized_ipv4 = wirestack::serializeIpv4Packet(reply_packet);
    if (std::holds_alternative<wirestack::Ipv4SerializeError>(serialized_ipv4)) {
        std::printf("ipv4: dropped outgoing packet: payload too large\n");
        return;
    }

    wirestack::EthernetFrame reply_frame;
    reply_frame.destination = eth_frame.source;
    reply_frame.source = local_mac;
    reply_frame.ether_type = static_cast<std::uint16_t>(wirestack::EtherType::Ipv4);
    reply_frame.payload = std::get<std::vector<std::byte>>(serialized_ipv4);

    auto serialized = wirestack::serializeEthernetFrame(reply_frame);
    auto write_result = tap.write(serialized);
    if (auto* error = std::get_if<std::string>(&write_result)) {
        std::fprintf(stderr, "wirestack: udp reply write failed: %s\n", error->c_str());
        return;
    }

    std::printf("udp echo-reply dst=%s:%u len=%zu\n", reply_packet.destination.toString().c_str(),
                static_cast<unsigned int>(reply.destination_port),
                8 + reply.payload.size());
}

// Serializes `segment` through IPv4/Ethernet and writes it back through
// `tap`, addressed explicitly to `remote_ip`/`remote_mac`. Shared by every
// kind of outgoing TCP segment (SYN-ACK, pure ACK, echoed data, and
// timer-triggered retransmissions, which have no current received frame
// to read addressing from).
void sendTcpSegment(wirestack::TapDevice& tap, wirestack::Ipv4Address local_ip,
                     wirestack::MacAddress local_mac, wirestack::Ipv4Address remote_ip,
                     wirestack::MacAddress remote_mac, const wirestack::TcpSegment& segment) {
    constexpr std::uint8_t kProtocolTcp = 6;

    auto serialized_tcp = wirestack::serializeTcpSegment(segment, local_ip, remote_ip);
    if (std::holds_alternative<wirestack::TcpSerializeError>(serialized_tcp)) {
        std::printf("tcp: dropped outgoing segment: payload too large\n");
        return;
    }

    wirestack::Ipv4Packet reply_packet;
    reply_packet.ttl = 64;
    reply_packet.protocol = kProtocolTcp;
    reply_packet.source = local_ip;
    reply_packet.destination = remote_ip;
    reply_packet.payload = std::get<std::vector<std::byte>>(serialized_tcp);

    auto serialized_ipv4 = wirestack::serializeIpv4Packet(reply_packet);
    if (std::holds_alternative<wirestack::Ipv4SerializeError>(serialized_ipv4)) {
        std::printf("ipv4: dropped outgoing packet: payload too large\n");
        return;
    }

    wirestack::EthernetFrame reply_frame;
    reply_frame.destination = remote_mac;
    reply_frame.source = local_mac;
    reply_frame.ether_type = static_cast<std::uint16_t>(wirestack::EtherType::Ipv4);
    reply_frame.payload = std::get<std::vector<std::byte>>(serialized_ipv4);

    auto serialized = wirestack::serializeEthernetFrame(reply_frame);
    auto write_result = tap.write(serialized);
    if (auto* error = std::get_if<std::string>(&write_result)) {
        std::fprintf(stderr, "wirestack: tcp segment write failed: %s\n", error->c_str());
        return;
    }

    if (segment.flags.syn) {
        std::printf("tcp syn-ack seq=%u ack=%u\n", segment.sequence_number,
                    segment.acknowledgment_number);
    } else if (!segment.payload.empty()) {
        std::printf("tcp data-out dst=%s:%u len=%zu\n", remote_ip.toString().c_str(),
                    static_cast<unsigned int>(segment.destination_port), segment.payload.size());
    } else {
        std::printf("tcp ack seq=%u ack=%u\n", segment.sequence_number,
                    segment.acknowledgment_number);
    }
}

// Convenience wrapper for an immediate reply to a just-received frame:
// Ethernet/IPv4 addressing come directly from it (the sender's MAC and IP
// are already known), same rationale as the ICMP/UDP reply paths.
void sendTcpReply(wirestack::TapDevice& tap, wirestack::Ipv4Address local_ip,
                   wirestack::MacAddress local_mac, const wirestack::Ipv4Packet& ip_packet,
                   const wirestack::EthernetFrame& eth_frame, const wirestack::TcpSegment& segment) {
    sendTcpSegment(tap, local_ip, local_mac, ip_packet.source, eth_frame.source, segment);
}

// Bounded append, mirroring appendHttpBytes (http.hpp) for the response
// side: caps at the combined header+body bound so an active connection's
// client state can never grow unbounded regardless of what the peer sends.
void appendHttpClientBytes(wirestack::HttpClientSession& session,
                            std::span<const std::byte> bytes) {
    constexpr std::size_t kCap =
        wirestack::kMaxHttpResponseHeaderBlockLength + wirestack::kMaxHttpResponseBodyLength;
    if (session.response_buffer.size() >= kCap) {
        return;
    }
    std::size_t room = kCap - session.response_buffer.size();
    std::size_t take = std::min(room, bytes.size());
    session.response_buffer.insert(session.response_buffer.end(), bytes.begin(),
                                    bytes.begin() + static_cast<std::ptrdiff_t>(take));
}

// Drives the active-open HTTP client role for `key`, if `http_client_sessions`
// owns it: enqueues the exact GET request exactly once, on the call whose
// `result.connection_established` reports the handshake just completed;
// feeds newly accepted payload/peer FIN into the bounded response parser;
// and, the moment the response is complete or the parse fails, requests
// the connection's own close through the existing TCP close machinery. A
// connection with no entry in `http_client_sessions` (an --active-open-only
// connection, or the passive server's connections, which are never in this
// map) is left untouched -- ownership is by explicit map membership, never
// inferred from payload/peer_closed/TCP state.
void handleHttpClient(wirestack::TapDevice& tap, wirestack::Ipv4Address local_ip,
                       wirestack::MacAddress local_mac, wirestack::TcpConnectionTable& connections,
                       std::map<wirestack::TcpConnectionKey, wirestack::HttpClientSession>&
                           http_client_sessions,
                       const wirestack::TcpConnectionKey& key,
                       const wirestack::TcpReceiveResult& result,
                       const wirestack::Ipv4Packet& ip_packet,
                       const wirestack::EthernetFrame& eth_frame, wirestack::TcpClock::time_point now) {
    auto it = http_client_sessions.find(key);
    if (it == http_client_sessions.end()) {
        return;
    }
    auto& session = it->second;

    if (result.connection_established && !session.request_enqueued) {
        auto request =
            wirestack::buildHttpGetRequest(session.remote_ip, session.remote_port, session.target);
        if (request) {
            auto sent = connections.makeOutgoingData(key, *request, now);
            if (!sent.error) {
                session.request_enqueued = true;
                for (const auto& segment : sent.segments) {
                    sendTcpReply(tap, local_ip, local_mac, ip_packet, eth_frame, segment);
                }
                std::printf("http-client: GET %s enqueued dst=%s:%u\n", session.target.c_str(),
                            session.remote_ip.toString().c_str(),
                            static_cast<unsigned int>(session.remote_port));
            } else {
                session.failed = true;
                std::printf("http-client: failed to enqueue GET request dst=%s:%u\n",
                            session.remote_ip.toString().c_str(),
                            static_cast<unsigned int>(session.remote_port));
            }
        } else {
            session.failed = true; // unreachable in practice: target validated at CLI parse time
        }
    }

    if (!session.response_complete && !session.failed) {
        if (!result.accepted_payload.empty()) {
            appendHttpClientBytes(session, result.accepted_payload);
        }
        if (result.peer_closed) {
            session.peer_fin_seen = true;
        }

        auto parsed = wirestack::parseHttpResponse(session.response_buffer, session.peer_fin_seen);
        switch (parsed.status) {
            case wirestack::HttpResponseParseStatus::Incomplete:
                break;
            case wirestack::HttpResponseParseStatus::Complete:
                session.response_complete = true;
                session.status_code = *parsed.status_code;
                session.body = std::move(parsed.body);
                std::printf("http-client: response complete status=%d body_len=%zu\n",
                            session.status_code, session.body.size());
                break;
            case wirestack::HttpResponseParseStatus::Malformed:
            case wirestack::HttpResponseParseStatus::TooLarge:
            case wirestack::HttpResponseParseStatus::UnsupportedVersion:
            case wirestack::HttpResponseParseStatus::UnsupportedTransferEncoding:
            case wirestack::HttpResponseParseStatus::Truncated:
                session.failed = true;
                std::printf("http-client: response rejected dst=%s:%u\n",
                            session.remote_ip.toString().c_str(),
                            static_cast<unsigned int>(session.remote_port));
                break;
        }
    }

    if ((session.response_complete || session.failed) && !session.close_initiated) {
        session.close_initiated = true;
        auto close_result = connections.beginClose(key, now);
        if (close_result.fin) {
            sendTcpReply(tap, local_ip, local_mac, ip_packet, eth_frame, *close_result.fin);
        }
    }
}

// Parses the TCP segment, runs it through `connections`, and dispatches
// the result: an immediate reply (SYN-ACK / pure ACK / closed-port RST) is
// sent as-is; newly accepted application payload and an accepted peer FIN
// feed the HTTP server layer (`http_sessions`) only for connections not
// owned by the active-open runtime path (`active_open_key`) -- a
// connection Wirestack itself dialed out is a client of whatever is on
// the other end, not an inbound HTTP request, and must never be handed
// to the passive server's request parser/response policy merely because
// it produced payload or a peer FIN. An active-open connection that IS an
// HTTP client (present in `http_client_sessions`) is instead routed to
// `handleHttpClient` -- routing is always by explicit key/map membership,
// never inferred from payload/peer_closed/TCP state alone. TCP protocol
// logic knows nothing about HTTP either way; `connections.handle`/
// `makeOutgoingData`/`beginClose` know nothing about this distinction.
void handleTcp(wirestack::TapDevice& tap, wirestack::Ipv4Address local_ip,
               wirestack::MacAddress local_mac, wirestack::TcpConnectionTable& connections,
               std::map<wirestack::TcpConnectionKey, wirestack::HttpConnectionState>& http_sessions,
               std::map<wirestack::TcpConnectionKey, wirestack::HttpClientSession>&
                   http_client_sessions,
               const std::optional<wirestack::TcpConnectionKey>& active_open_key,
               const wirestack::Ipv4Packet& ip_packet, const wirestack::EthernetFrame& eth_frame) {
    auto parsed = wirestack::parseTcpSegment(ip_packet.payload, ip_packet.source,
                                              ip_packet.destination);
    if (!std::holds_alternative<wirestack::TcpSegment>(parsed)) {
        std::printf("tcp: dropped malformed segment\n");
        return;
    }

    const auto& segment = std::get<wirestack::TcpSegment>(parsed);
    wirestack::TcpConnectionKey key{local_ip, segment.destination_port, ip_packet.source,
                                     segment.source_port};

    if (segment.flags.syn && !segment.flags.ack) {
        std::printf("tcp syn src=%s:%u seq=%u\n", ip_packet.source.toString().c_str(),
                    static_cast<unsigned int>(segment.source_port), segment.sequence_number);
    }

    auto now = wirestack::TcpClock::now();

    auto state_before = connections.stateOf(key);
    auto result = connections.handle(key, segment, now);
    auto state_after = connections.stateOf(key);

    if (state_before == wirestack::TcpState::SynReceived &&
        state_after == wirestack::TcpState::Established) {
        std::printf("tcp established src=%s:%u\n", ip_packet.source.toString().c_str(),
                    static_cast<unsigned int>(segment.source_port));
    }
    if (result.connection_established) {
        std::printf("tcp active connection established dst=%s:%u local_port=%u\n",
                    ip_packet.source.toString().c_str(),
                    static_cast<unsigned int>(segment.source_port),
                    static_cast<unsigned int>(segment.destination_port));
    }
    if (result.connection_reset && state_before == wirestack::TcpState::SynSent) {
        std::printf("tcp active connection refused dst=%s:%u local_port=%u\n",
                    ip_packet.source.toString().c_str(),
                    static_cast<unsigned int>(segment.source_port),
                    static_cast<unsigned int>(segment.destination_port));
    }

    if (result.reply) {
        sendTcpReply(tap, local_ip, local_mac, ip_packet, eth_frame, *result.reply);
    }

    if (result.fast_retransmit) {
        // A duplicate-ACK-triggered fast retransmission is sent through
        // the same immediate-reply path, addressed using the current
        // received frame -- not the timer/ARP-cache path used by ordinary
        // timeout retransmissions, which have no current frame to read a
        // destination MAC from.
        sendTcpReply(tap, local_ip, local_mac, ip_packet, eth_frame, *result.fast_retransmit);
    }

    // Application-data segments scheduled by this ACK/window update
    // because it opened new peer-window or congestion-window allowance
    // (see docs/tcp.md) -- sent through the same immediate-reply path,
    // addressed using the current received frame.
    for (const auto& scheduled_segment : result.scheduled) {
        sendTcpReply(tap, local_ip, local_mac, ip_packet, eth_frame, scheduled_segment);
    }

    if (!result.accepted_payload.empty()) {
        std::printf("tcp data src=%s:%u len=%zu\n", ip_packet.source.toString().c_str(),
                    static_cast<unsigned int>(segment.source_port),
                    result.accepted_payload.size());
    }
    if (result.peer_closed) {
        std::printf("tcp fin src=%s:%u\n", ip_packet.source.toString().c_str(),
                    static_cast<unsigned int>(segment.source_port));
    }

    if ((!result.accepted_payload.empty() || result.peer_closed) &&
        key != active_open_key) {
        auto& session = http_sessions[key];
        if (!session.responded) {
            if (!result.accepted_payload.empty()) {
                wirestack::appendHttpBytes(session, result.accepted_payload);
            }

            auto parsed = wirestack::parseHttpRequest(session.buffer);
            std::optional<wirestack::HttpResponse> response;
            switch (parsed.status) {
                case wirestack::HttpParseStatus::Incomplete:
                    // Peer EOF before a complete request: respond 400
                    // rather than silently discarding the request.
                    if (result.peer_closed) {
                        response = wirestack::makeBadRequestResponse();
                    }
                    break;
                case wirestack::HttpParseStatus::Complete:
                    response = wirestack::selectResponse(*parsed.request);
                    break;
                case wirestack::HttpParseStatus::Malformed:
                case wirestack::HttpParseStatus::TooLarge:
                    response = wirestack::makeBadRequestResponse();
                    break;
                case wirestack::HttpParseStatus::UnsupportedMethod:
                    response = wirestack::makeMethodNotAllowedResponse();
                    break;
                case wirestack::HttpParseStatus::UnsupportedVersion:
                    response = wirestack::makeVersionNotSupportedResponse();
                    break;
            }

            if (response) {
                session.responded = true;
                auto response_bytes = wirestack::serializeHttpResponse(*response);
                // Enqueues the complete response atomically into TCP's
                // bounded send buffer; `sent.segments` carries whatever
                // the current peer-window/congestion-window allowance
                // lets out immediately -- it may be empty (the response
                // still fully enqueued) if there is no allowance yet, in
                // which case a later ACK/window update schedules the
                // rest (see TcpReceiveResult::scheduled above). HTTP
                // itself has no notion of TCP windows or sequence
                // numbers.
                auto sent = connections.makeOutgoingData(key, response_bytes, now);
                if (!sent.error) {
                    for (const auto& response_segment : sent.segments) {
                        sendTcpReply(tap, local_ip, local_mac, ip_packet, eth_frame,
                                     response_segment);
                    }
                    // Close is requested once the response is fully
                    // accepted into the send buffer, not once it is fully
                    // on the wire -- TCP itself defers the FIN until every
                    // response byte has entered sequence space.
                    auto close_result = connections.beginClose(key, now);
                    if (close_result.fin) {
                        sendTcpReply(tap, local_ip, local_mac, ip_packet, eth_frame,
                                     *close_result.fin);
                    }
                } else {
                    std::printf("http: failed to enqueue response for src=%s:%u\n",
                                ip_packet.source.toString().c_str(),
                                static_cast<unsigned int>(segment.source_port));
                }
            }
        }
    }

    handleHttpClient(tap, local_ip, local_mac, connections, http_client_sessions, key, result,
                      ip_packet, eth_frame, now);

    if (result.connection_reset && state_before != wirestack::TcpState::SynSent) {
        // The SynSent case already printed "active connection refused"
        // above -- this is the passive/synchronized-state reset instead.
        std::printf("tcp: connection reset by peer src=%s:%u\n",
                    ip_packet.source.toString().c_str(),
                    static_cast<unsigned int>(segment.source_port));
    }
    if (result.connection_reset || result.connection_closed) {
        http_sessions.erase(key);
        http_client_sessions.erase(key);
    }
}

// Parses the IPv4 payload and, for well-formed packets addressed to
// `local_ip` with TTL > 0, dispatches to the supported upper-layer
// protocol. Packets for other destinations or with an unsupported protocol
// are valid IPv4 and are silently ignored -- Wirestack is a local endpoint,
// not a router.
void handleIpv4(wirestack::TapDevice& tap, wirestack::Ipv4Address local_ip,
                 wirestack::MacAddress local_mac, wirestack::ArpCache& arp_cache,
                 const wirestack::UdpEndpointTable& endpoints,
                 wirestack::TcpConnectionTable& tcp_connections,
                 std::map<wirestack::TcpConnectionKey, wirestack::HttpConnectionState>&
                     http_sessions,
                 std::map<wirestack::TcpConnectionKey, wirestack::HttpClientSession>&
                     http_client_sessions,
                 const std::optional<wirestack::TcpConnectionKey>& active_open_key,
                 const wirestack::EthernetFrame& frame) {
    auto parsed = wirestack::parseIpv4Packet(frame.payload);
    if (!std::holds_alternative<wirestack::Ipv4Packet>(parsed)) {
        std::printf("ipv4: dropped malformed packet\n");
        return;
    }

    const auto& packet = std::get<wirestack::Ipv4Packet>(parsed);
    std::printf("ipv4 src=%s dst=%s proto=%u len=%zu\n", packet.source.toString().c_str(),
                packet.destination.toString().c_str(), static_cast<unsigned int>(packet.protocol),
                20 + packet.payload.size());

    if (packet.ttl == 0) {
        std::printf("ipv4: dropped packet with ttl=0\n");
        return;
    }
    if (packet.destination != local_ip) {
        return;
    }

    // Opportunistically learn the sender's IP->MAC mapping from any valid
    // local IPv4 traffic, not just ARP -- lets a later timer-triggered
    // TCP retransmission (with no current received frame) still resolve
    // a destination MAC.
    arp_cache.insert(packet.source, frame.source);

    constexpr std::uint8_t kProtocolIcmp = 1;
    constexpr std::uint8_t kProtocolTcp = 6;
    constexpr std::uint8_t kProtocolUdp = 17;
    if (packet.protocol == kProtocolIcmp) {
        handleIcmp(tap, local_ip, local_mac, packet, frame);
    } else if (packet.protocol == kProtocolTcp) {
        handleTcp(tap, local_ip, local_mac, tcp_connections, http_sessions, http_client_sessions,
                  active_open_key, packet, frame);
    } else if (packet.protocol == kProtocolUdp) {
        handleUdp(tap, local_ip, local_mac, endpoints, packet, frame);
    }
}

} // namespace

int main(int argc, char** argv) {
    if (argc < 4) {
        std::fprintf(stderr,
                     "usage: %s <tap-interface-name> <local-ipv4> <local-mac> "
                     "[--active-open <ip>:<port> --source-port <port>] "
                     "[--http-get <ip>:<port> --source-port <port> --target </path>]\n",
                     argv[0]);
        return 1;
    }

    auto local_ip = wirestack::Ipv4Address::parse(argv[2]);
    if (!local_ip) {
        std::fprintf(stderr, "wirestack: invalid local IPv4 address: %s\n", argv[2]);
        return 1;
    }
    auto local_mac = wirestack::MacAddress::parse(argv[3]);
    if (!local_mac) {
        std::fprintf(stderr, "wirestack: invalid local MAC address: %s\n", argv[3]);
        return 1;
    }

    // Runtime-mode options (--active-open / --http-get / --source-port /
    // --target) are validated before the TAP device is opened, so invalid
    // configuration exits deterministically without touching the network
    // and without ever falling back to passive mode -- see
    // RuntimeOptionsParseResult's absent/valid/invalid contract.
    auto runtime_parse = wirestack::parseRuntimeOptions(argc, argv);
    if (runtime_parse.error) {
        std::fprintf(stderr, "wirestack: %s\n", runtime_parse.error->message.c_str());
        return 1;
    }
    const wirestack::RuntimeOptions& runtime_options = *runtime_parse.options;

    auto opened = wirestack::TapDevice::open(argv[1]);
    if (auto* error = std::get_if<wirestack::TapOpenError>(&opened)) {
        std::fprintf(stderr, "wirestack: failed to open TAP: %s\n", error->message.c_str());
        return 1;
    }

    auto& tap = std::get<wirestack::TapDevice>(opened);
    std::printf("wirestack: opened TAP interface %s (ip=%s mac=%s)\n",
                std::string(tap.name()).c_str(), local_ip->toString().c_str(),
                local_mac->toString().c_str());

    wirestack::ArpCache arp_cache;

    constexpr std::uint16_t kEchoPort = 9000;
    wirestack::UdpEndpointTable udp_endpoints;
    udp_endpoints.bind(kEchoPort, [](std::span<const std::byte> request) {
        return std::vector<std::byte>(request.begin(), request.end());
    });

    constexpr std::uint16_t kTcpListenPort = 8080;
    wirestack::TcpConnectionTable tcp_connections(kTcpListenPort);
    // HTTP application state, keyed by the same TCP four-tuple as
    // `tcp_connections` but owned separately -- the TCP connection table
    // has no HTTP knowledge.
    std::map<wirestack::TcpConnectionKey, wirestack::HttpConnectionState> http_sessions;
    // Outbound HTTP/1.0 client state, keyed the same way -- see
    // handleHttpClient. Owned separately from `tcp_connections` (which has
    // no HTTP knowledge) and from `http_sessions` (the inbound server's
    // state; a connection is never in both maps).
    std::map<wirestack::TcpConnectionKey, wirestack::HttpClientSession> http_client_sessions;

    // ActiveOpen and HttpGet share the same active-open slot and are
    // mutually exclusive (enforced by parseRuntimeOptions) -- at most one
    // connection is configured, started exactly once as soon as the peer's
    // MAC is known through the existing ARP cache. Passive by default.
    bool active_open_started = false;
    std::optional<wirestack::TcpConnectionKey> active_open_key;
    if (runtime_options.mode == wirestack::RuntimeMode::ActiveOpen) {
        active_open_key =
            wirestack::TcpConnectionKey{*local_ip, runtime_options.source_port,
                                         runtime_options.remote_ip, runtime_options.remote_port};
        std::printf("tcp: active open pending dst=%s:%u src_port=%u (waiting for peer MAC)\n",
                    runtime_options.remote_ip.toString().c_str(),
                    static_cast<unsigned int>(runtime_options.remote_port),
                    static_cast<unsigned int>(runtime_options.source_port));
    } else if (runtime_options.mode == wirestack::RuntimeMode::HttpGet) {
        active_open_key =
            wirestack::TcpConnectionKey{*local_ip, runtime_options.source_port,
                                         runtime_options.remote_ip, runtime_options.remote_port};
        std::printf("tcp: http-get pending dst=%s:%u src_port=%u target=%s (waiting for peer MAC)\n",
                    runtime_options.remote_ip.toString().c_str(),
                    static_cast<unsigned int>(runtime_options.remote_port),
                    static_cast<unsigned int>(runtime_options.source_port),
                    runtime_options.target.c_str());
    }

    std::array<std::byte, kReceiveBufferSize> buffer{};
    for (;;) {
        // Size the poll timeout to the earliest pending TCP retransmission
        // or zero-window persist deadline (if any) so timers fire even
        // when no packet arrives, without busy-looping.
        int timeout_ms = -1;
        auto retransmission_deadline = tcp_connections.nextRetransmissionDeadline();
        auto persist_deadline = tcp_connections.nextPersistDeadline();
        std::optional<wirestack::TcpClock::time_point> deadline = retransmission_deadline;
        if (persist_deadline && (!deadline || *persist_deadline < *deadline)) {
            deadline = persist_deadline;
        }
        if (deadline) {
            auto now = wirestack::TcpClock::now();
            auto remaining = *deadline > now
                                  ? std::chrono::duration_cast<std::chrono::milliseconds>(
                                        *deadline - now)
                                  : std::chrono::milliseconds{0};
            timeout_ms = static_cast<int>(std::min<std::chrono::milliseconds::rep>(
                remaining.count(), std::numeric_limits<int>::max()));
        }

        auto readable = tap.waitReadable(timeout_ms);
        if (auto* error = std::get_if<std::string>(&readable)) {
            std::fprintf(stderr, "wirestack: %s\n", error->c_str());
            return 1;
        }

        if (std::get<bool>(readable)) {
            auto result = tap.read(buffer);
            if (auto* error = std::get_if<std::string>(&result)) {
                std::fprintf(stderr, "wirestack: %s\n", error->c_str());
                return 1;
            }

            std::size_t n = std::get<std::size_t>(result);
            auto parsed = wirestack::parseEthernetFrame(std::span(buffer).first(n));
            auto* frame = std::get_if<wirestack::EthernetFrame>(&parsed);
            if (frame == nullptr) {
                std::printf("ethernet: dropped malformed frame: truncated header\n");
                continue;
            }

            printFrame(*frame, n);

            auto ether_type = static_cast<wirestack::EtherType>(frame->ether_type);
            if (ether_type == wirestack::EtherType::Arp) {
                handleArp(tap, arp_cache, *local_ip, *local_mac, *frame);
            } else if (ether_type == wirestack::EtherType::Ipv4) {
                handleIpv4(tap, *local_ip, *local_mac, arp_cache, udp_endpoints, tcp_connections,
                           http_sessions, http_client_sessions, active_open_key, *frame);
            }
        }

        if (runtime_options.mode != wirestack::RuntimeMode::Passive && !active_open_started) {
            wirestack::Ipv4Address dial_ip = runtime_options.remote_ip;
            std::uint16_t dial_port = runtime_options.remote_port;
            std::uint16_t dial_source_port = runtime_options.source_port;
            if (auto mac = arp_cache.lookup(dial_ip)) {
                auto now = wirestack::TcpClock::now();
                auto connect_result = tcp_connections.beginConnect(*active_open_key, now);
                active_open_started = true; // one attempt only, regardless of outcome
                if (connect_result.accepted && connect_result.syn) {
                    std::printf("tcp: active open started dst=%s:%u src_port=%u\n",
                                dial_ip.toString().c_str(), static_cast<unsigned int>(dial_port),
                                static_cast<unsigned int>(dial_source_port));
                    sendTcpSegment(tap, *local_ip, *local_mac, dial_ip, *mac, *connect_result.syn);
                    if (runtime_options.mode == wirestack::RuntimeMode::HttpGet) {
                        wirestack::HttpClientSession session;
                        session.remote_ip = runtime_options.remote_ip;
                        session.remote_port = runtime_options.remote_port;
                        session.target = runtime_options.target;
                        http_client_sessions.emplace(*active_open_key, std::move(session));
                    }
                } else {
                    std::printf("tcp: active open rejected dst=%s:%u src_port=%u\n",
                                dial_ip.toString().c_str(), static_cast<unsigned int>(dial_port),
                                static_cast<unsigned int>(dial_source_port));
                }
            }
        }

        auto now = wirestack::TcpClock::now();
        auto due = tcp_connections.pollRetransmissions(now);
        for (const auto& retransmission : due.retransmissions) {
            auto mac = arp_cache.lookup(retransmission.key.remote_ip);
            if (!mac) {
                std::printf("tcp: cannot retransmit to %s:%u: no known MAC address\n",
                            retransmission.key.remote_ip.toString().c_str(),
                            static_cast<unsigned int>(retransmission.key.remote_port));
                continue;
            }
            sendTcpSegment(tap, *local_ip, *local_mac, retransmission.key.remote_ip, *mac,
                           retransmission.segment);
        }
        auto persist_due = tcp_connections.pollPersistProbes(now);
        for (const auto& probe : persist_due.probes) {
            auto mac = arp_cache.lookup(probe.key.remote_ip);
            if (!mac) {
                std::printf("tcp: cannot send persist probe to %s:%u: no known MAC address\n",
                            probe.key.remote_ip.toString().c_str(),
                            static_cast<unsigned int>(probe.key.remote_port));
                continue;
            }
            sendTcpSegment(tap, *local_ip, *local_mac, probe.key.remote_ip, *mac, probe.segment);
        }
        for (const auto& key : due.timed_out) {
            if (active_open_key && key == *active_open_key) {
                std::printf("tcp: active connection to %s:%u timed out after %d retransmissions\n",
                            key.remote_ip.toString().c_str(),
                            static_cast<unsigned int>(key.remote_port), wirestack::kMaxRetransmits);
            } else {
                std::printf("tcp: connection to %s:%u timed out after %d retransmissions\n",
                            key.remote_ip.toString().c_str(),
                            static_cast<unsigned int>(key.remote_port), wirestack::kMaxRetransmits);
            }
            http_sessions.erase(key);
            http_client_sessions.erase(key);
        }
        for (const auto& key : due.time_wait_expired) {
            std::printf("tcp: connection to %s:%u closed after time_wait\n",
                        key.remote_ip.toString().c_str(), static_cast<unsigned int>(key.remote_port));
            http_sessions.erase(key);
            http_client_sessions.erase(key);
        }
    }
}
