#include "wirestack/dns.hpp"
#include "wirestack/ethernet.hpp"
#include "wirestack/tcp_connection.hpp"

#include "test_util.hpp"

#include <array>

using namespace wirestack;

int main() {
    constexpr TcpClock::time_point t0{};
    auto local_ip = *Ipv4Address::parse("10.0.0.2");
    auto remote_ip = *Ipv4Address::parse("10.0.0.1");

    TcpConnectionTable connections(8080);
    TcpConnectionKey key{local_ip, 49152, remote_ip, 80};
    CHECK(connections.beginConnect(key, t0).accepted);

    DnsClientSession dns;
    dns.server_ip = remote_ip;
    dns.hostname = "example.test";
    DnsQuery query{0x1234, dns.hostname};
    CHECK(beginDnsQuery(dns, query, t0).has_value());

    auto parsed = parseEthernetFrame(std::array<std::byte, 13>{});
    CHECK(std::holds_alternative<EthernetParseError>(parsed));

    auto tcp_due = connections.pollRetransmissions(t0 + kInitialRto);
    CHECK(tcp_due.retransmissions.size() == 1);

    auto dns_due = pollDnsTimeout(dns, t0 + kDnsInitialInterval);
    CHECK(dns_due.retransmit.has_value());
    CHECK(!dns_due.timed_out);
    CHECK(dns.transmit_count == 2);

    return wirestack::test::failureCount() == 0 ? 0 : 1;
}
