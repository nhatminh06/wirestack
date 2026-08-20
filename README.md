# wirestack

A userspace TCP/IP network stack in C++20, built from a Linux TAP device up
through Ethernet, ARP, IPv4, ICMP, UDP, TCP, and a minimal HTTP server. This
is a learning project: the goal is understanding the protocols by
implementing them, not feature completeness or performance.

## Status

Milestone 0 (project foundation) through Milestone 7 (TCP timeout-based
retransmission):

| Protocol    | Status                                                          |
|-------------|-------------------------------------------------------------------|
| Ethernet II | implemented                                                       |
| TAP I/O     | implemented                                                       |
| ARP         | implemented                                                       |
| IPv4        | implemented: local, unfragmented, base-header only                |
| ICMP Echo   | implemented                                                       |
| UDP         | implemented: basic unicast + built-in echo endpoint                |
| TCP         | passive handshake, single-segment in-order echo, and bounded timeout retransmission implemented and deterministically tested; live TAP verification still required |
| HTTP        | not implemented                                                   |

- `MacAddress` / `Ipv4Address`: parsing, formatting, equality
- Ethernet II frame parsing and serialization
- Linux TAP device I/O (`wirestack::TapDevice`): open, read, write
- ARP request/reply parsing and serialization, request handling, and a basic
  in-memory `ArpCache`
- IPv4 header parsing/serialization/checksum, local-delivery filtering
- ICMP Echo Request/Reply parsing, serialization, and checksum
- UDP datagram parsing/serialization with the IPv4 pseudo-header checksum, a
  minimal `UdpEndpointTable`, and a built-in echo endpoint on port 9000
- TCP segment parsing/serialization with the IPv4 pseudo-header checksum, a
  4-tuple `TcpConnectionTable`, a passive handshake (LISTEN implicit /
  SYN_RECEIVED / ESTABLISHED), sequence-space tracking, single in-order
  data segment receive with duplicate/out-of-order/overlap rejection,
  cumulative ACK processing, a built-in TCP echo demonstration (not HTTP)
  on a fixed listening port 8080, and bounded timeout-based retransmission
  of SYN-ACK and echoed data with cumulative/partial ACK retirement
- `wirestack` executable: opens a TAP interface with a configured local
  IPv4/MAC, decodes incoming Ethernet frames, answers ARP requests, ICMP
  Echo Requests, UDP datagrams to its echo endpoint, and TCP handshakes and
  echoed data on its listening port
- `tools/tap_send`: writes one fixed Ethernet frame out through a TAP
  interface, to verify the transmit path

See [docs/tap.md](docs/tap.md), [docs/arp.md](docs/arp.md),
[docs/ipv4.md](docs/ipv4.md), [docs/icmp.md](docs/icmp.md),
[docs/udp.md](docs/udp.md), and [docs/tcp.md](docs/tcp.md) for setup,
permissions, and how to test. Real Linux interoperability (ARP resolution,
`ping` receiving Echo Replies, UDP echo, a completed TCP handshake and
echoed data) is manually verifiable but has not been exercised in every
development environment this project has run in — see those docs for exact
commands.

Not implemented: TCP segmentation/reassembly/close/active-open/congestion
control/RTT estimation, HTTP, IPv4 options, fragmentation, routing.

## Structure

```
include/wirestack/   public headers
src/                  implementation, wirestack executable
tests/                unit tests (CTest, no external test framework)
tools/                command-line utilities (tap_send)
docs/                 protocol notes
```

## Build

```bash
cmake -S . -B build
cmake --build build -j
ctest --test-dir build --output-on-failure
```

With AddressSanitizer and UndefinedBehaviorSanitizer:

```bash
cmake -S . -B build-asan -DWIRESTACK_ENABLE_SANITIZERS=ON
cmake --build build-asan -j
ctest --test-dir build-asan --output-on-failure
```

## Running

Opening a TAP device requires `CAP_NET_ADMIN` (root, in practice):

```bash
sudo ./build/wirestack wire0 10.0.0.2 02:00:00:00:00:02
```

See [docs/tap.md](docs/tap.md) for host-side interface configuration and how
to observe frames with `tcpdump`, [docs/arp.md](docs/arp.md) for testing ARP
resolution end to end, [docs/udp.md](docs/udp.md) for testing the UDP echo
endpoint (port 9000), and [docs/tcp.md](docs/tcp.md) for testing the TCP
handshake and echo demonstration (port 8080).
