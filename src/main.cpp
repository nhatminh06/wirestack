#include <algorithm>
#include <array>
#include <chrono>
#include <cstdio>
#include <limits>
#include <map>
#include <optional>
#include <string>
#include <variant>

#include "wirestack/arp.hpp"
#include "wirestack/arp_cache.hpp"
#include "wirestack/ethernet.hpp"
#include "wirestack/http.hpp"
#include "wirestack/icmp.hpp"
#include "wirestack/ipv4.hpp"
#include "wirestack/ipv4_address.hpp"
#include "wirestack/mac_address.hpp"
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

// Parses the TCP segment, runs it through `connections`, and dispatches
// the result: an immediate reply (SYN-ACK / pure ACK / closed-port RST) is
// sent as-is; newly accepted application payload and an accepted peer FIN
// both feed the HTTP layer (`http_sessions`), which owns request
// buffering/parsing/response-selection entirely on its own -- TCP protocol
// logic knows nothing about HTTP, and `connections.handle`/
// `makeOutgoingData`/`beginClose` know nothing about it either.
void handleTcp(wirestack::TapDevice& tap, wirestack::Ipv4Address local_ip,
               wirestack::MacAddress local_mac, wirestack::TcpConnectionTable& connections,
               std::map<wirestack::TcpConnectionKey, wirestack::HttpConnectionState>& http_sessions,
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

    if (!result.accepted_payload.empty()) {
        std::printf("tcp data src=%s:%u len=%zu\n", ip_packet.source.toString().c_str(),
                    static_cast<unsigned int>(segment.source_port),
                    result.accepted_payload.size());
    }
    if (result.peer_closed) {
        std::printf("tcp fin src=%s:%u\n", ip_packet.source.toString().c_str(),
                    static_cast<unsigned int>(segment.source_port));
    }

    if (!result.accepted_payload.empty() || result.peer_closed) {
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
                auto sent = connections.makeOutgoingData(key, response_bytes, now);
                if (!sent.segments.empty()) {
                    for (const auto& response_segment : sent.segments) {
                        sendTcpReply(tap, local_ip, local_mac, ip_packet, eth_frame,
                                     response_segment);
                    }
                    // Never close before the response segment(s) were
                    // successfully constructed above.
                    auto fin = connections.beginClose(key, now);
                    if (fin) {
                        sendTcpReply(tap, local_ip, local_mac, ip_packet, eth_frame, *fin);
                    }
                } else {
                    std::printf("http: failed to construct response segment for src=%s:%u\n",
                                ip_packet.source.toString().c_str(),
                                static_cast<unsigned int>(segment.source_port));
                }
            }
        }
    }

    if (result.connection_reset) {
        std::printf("tcp: connection reset by peer src=%s:%u\n",
                    ip_packet.source.toString().c_str(),
                    static_cast<unsigned int>(segment.source_port));
    }
    if (result.connection_reset || result.connection_closed) {
        http_sessions.erase(key);
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
        handleTcp(tap, local_ip, local_mac, tcp_connections, http_sessions, packet, frame);
    } else if (packet.protocol == kProtocolUdp) {
        handleUdp(tap, local_ip, local_mac, endpoints, packet, frame);
    }
}

} // namespace

int main(int argc, char** argv) {
    if (argc != 4) {
        std::fprintf(stderr, "usage: %s <tap-interface-name> <local-ipv4> <local-mac>\n",
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

    std::array<std::byte, kReceiveBufferSize> buffer{};
    for (;;) {
        // Size the poll timeout to the earliest pending TCP retransmission
        // deadline (if any) so retransmissions fire even when no packet
        // arrives, without busy-looping.
        int timeout_ms = -1;
        if (auto deadline = tcp_connections.nextRetransmissionDeadline()) {
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
                           http_sessions, *frame);
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
        for (const auto& key : due.timed_out) {
            std::printf("tcp: connection to %s:%u timed out after %d retransmissions\n",
                        key.remote_ip.toString().c_str(), static_cast<unsigned int>(key.remote_port),
                        wirestack::kMaxRetransmits);
            http_sessions.erase(key);
        }
        for (const auto& key : due.time_wait_expired) {
            std::printf("tcp: connection to %s:%u closed after time_wait\n",
                        key.remote_ip.toString().c_str(), static_cast<unsigned int>(key.remote_port));
            http_sessions.erase(key);
        }
    }
}
