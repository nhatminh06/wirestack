# wirestack

A userspace TCP/IP network stack in C++20, built from a Linux TAP device up
through Ethernet, ARP, IPv4, ICMP, UDP, TCP, and a minimal HTTP server. This
is a learning project: the goal is understanding the protocols by
implementing them, not feature completeness or performance.

## Status

Milestone 0 (project foundation) through Milestone 12 (Reno-style TCP
congestion control):

| Protocol    | Status                                                          |
|-------------|-------------------------------------------------------------------|
| Ethernet II | implemented                                                       |
| TAP I/O     | implemented                                                       |
| ARP         | implemented                                                       |
| IPv4        | implemented: local, unfragmented, base-header only                |
| ICMP Echo   | implemented                                                       |
| UDP         | implemented: basic unicast + built-in echo endpoint                |
| TCP         | passive handshake with SYN-carried MSS/Window Scale option negotiation, MSS-bounded segmentation within the peer's (possibly scaled) send and congestion window, bounded out-of-order receive reassembly, RTT measurement with adaptive SRTT/RTTVAR/RTO retransmission timing, Reno-style Slow Start/Congestion Avoidance/duplicate-ACK fast retransmit/fast recovery, and passive/active/simultaneous close with TIME_WAIT and reset handling implemented and deterministically tested; live TAP verification still required |
| HTTP        | minimal HTTP/1.0 GET (`/` -> 200, other paths -> 404, one request per connection) implemented and deterministically tested; live curl verification still required |

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
  SYN_RECEIVED / ESTABLISHED) that parses and negotiates a SYN's MSS and
  Window Scale options (IPv4 default 536-byte MSS fallback, Window Scale
  clamped to 14, both fixed for the connection's lifetime), sequence-space
  tracking, MSS-bounded outgoing segmentation (sized to the negotiated
  peer MSS, atomically capped at 128 segments per send) with atomic
  peer-send-window enforcement, bounded out-of-order receive reassembly
  (first-arrival-wins overlap trimming, a 262140-byte/128-fragment
  internal bound, out-of-order FIN retention) with a dynamically
  advertised, correctly scaled-when-negotiated receive window, cumulative
  ACK processing, RTT sampling with Karn's rule (triggered by either a
  timeout or a duplicate-ACK fast retransmit) feeding an adaptive
  SRTT/RTTVAR/RTO estimator (1s/60s bounds) that drives timeout-based
  retransmission of SYN-ACK/data/FIN with cumulative/partial ACK
  retirement, a per-connection Reno-style congestion window (initial
  window sized from the negotiated MSS, Slow Start, Congestion Avoidance,
  precise duplicate-ACK classification, third-duplicate-ACK fast
  retransmit, classic fast recovery, and timeout congestion collapse, all
  gating new application data alongside the peer's advertised window),
  passive/active/simultaneous close
  (FinWait1/FinWait2/CloseWait/Closing/LastAck) with a deterministic
  60-second TIME_WAIT, acceptable-inbound-RST handling, and closed-port
  RST generation
- A bounded, stateless HTTP/1.0 request parser (`wirestack::http`) layered
  above TCP: GET-only, `/` -> 200 with a fixed body, any other valid path
  -> 404, unsupported method -> 405, unsupported version -> 505,
  malformed/oversized/incomplete-at-EOF requests -> 400; one request per
  connection, response and close sent through the existing TCP
  retransmission/FIN machinery
- `wirestack` executable: opens a TAP interface with a configured local
  IPv4/MAC, decodes incoming Ethernet frames, answers ARP requests, ICMP
  Echo Requests, UDP datagrams to its echo endpoint, and serves the
  HTTP/1.0 demonstration on its TCP listening port
- `tools/tap_send`: writes one fixed Ethernet frame out through a TAP
  interface, to verify the transmit path

See [docs/tap.md](docs/tap.md), [docs/arp.md](docs/arp.md),
[docs/ipv4.md](docs/ipv4.md), [docs/icmp.md](docs/icmp.md),
[docs/udp.md](docs/udp.md), [docs/tcp.md](docs/tcp.md), and
[docs/http.md](docs/http.md) for setup, permissions, and how to test. Real
Linux interoperability (ARP resolution, `ping` receiving Echo Replies, UDP
echo, a completed TCP handshake, and a `curl --http1.0` request) is
manually verifiable but has not been exercised in every development
environment this project has run in — see those docs for exact commands.

Not implemented: TCP active-open/NewReno partial-ACK recovery/SACK/
CUBIC/BBR/ECN/timestamps/zero-window probes, HTTP/1.1/keep-alive/
pipelining/request bodies/chunked encoding/TLS, IPv4 options,
fragmentation, routing.

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
endpoint (port 9000), [docs/tcp.md](docs/tcp.md) for the TCP handshake and
close/reset behavior, and [docs/http.md](docs/http.md) for testing the
HTTP/1.0 demonstration on port 8080 with `curl`.
