# Linux TAP interoperability

Reproducible proof, against a real Linux kernel TCP/IP client, that
Wirestack's ARP/ICMP/UDP/TCP/HTTP paths work end to end -- including
timeout retransmission, SYN-ACK loss recovery, and out-of-order TCP
segment delivery, all captured on the wire. This complements the
per-protocol docs (`docs/arp.md`, `docs/icmp.md`, `docs/udp.md`,
`docs/tcp.md`, `docs/http.md`), which describe manual single-command
checks; this document describes the automated harness under
`tools/integration/`.

## Prerequisites

`ip`, `tc`, `tcpdump`, `curl`, `ethtool`, `unshare`, `nsenter`, `python3`,
`arping`. The harness needs `CAP_NET_ADMIN`/`CAP_NET_RAW` in a network
namespace it owns. Passwordless `sudo` is not required; an unprivileged
user namespace gets the same effective capabilities inside its own
namespaces:

```bash
cat /proc/sys/kernel/unprivileged_userns_clone   # must be 1
```

## Running

```bash
cmake -S . -B build && cmake --build build -j
unshare --user --net --map-root-user -- bash tools/integration/run.sh
```

The script must run already inside the `unshare` sandbox shown above --
it checks for uid 0 in its own namespace and exits with an explicit error
otherwise. To exercise the ASan+UBSan build instead:

```bash
cmake -S . -B build-asan -DWIRESTACK_ENABLE_SANITIZERS=ON
cmake --build build-asan -j
unshare --user --net --map-root-user -- env WS_BINARY="$(pwd)/build-asan/wirestack" bash tools/integration/run.sh
```

Exit status is nonzero if any scenario fails, a dependency is missing, or
cleanup cannot remove a harness-owned resource.

## Why `unshare`, not `ip netns add`

`ip netns add` bind-mounts into the shared, systemd-managed
`/var/run/netns`, which an unprivileged mount namespace often cannot
write to. The harness instead uses two nested network namespaces that
never touch that shared directory:

- the **outer** namespace, from `unshare --user --net --map-root-user`,
  where the bridge, TAP device, and Wirestack process live;
- the **client** namespace, a plain `unshare --net -- sleep infinity`
  placeholder process reached with `nsenter --net=/proc/<pid>/ns/net`,
  where the Linux TCP/IP client runs.

Both are fully isolated from the real host network namespace; nothing
here touches host routing, host firewall rules, or a physical interface.

## Topology

```text
client namespace                outer (sandbox) namespace
  ws-client0  <-- veth -->  ws-host0
  10.0.0.1/24                  |
                            ws-int-br (no IPv4 address)
                                |
                            ws-int-tap
                                |
                            wirestack process (10.0.0.2, 02:00:00:00:00:02)
```

MTU 1500 throughout. The bridge carries no IPv4 address, so the ordinary
host network stack never owns 10.0.0.2 or answers on its behalf. TSO,
GSO, GRO, and checksum offload are disabled on `ws-host0`, `ws-client0`,
and `ws-int-tap` (`ethtool -K ... tso off gso off gro off tx off rx off
sg off`) so captured segment boundaries and checksums reflect what was
actually put on the wire, not what the NIC driver later coalesced or
offloaded.

## Resources created

`ws-int-br` (bridge), `ws-int-tap` (TAP, created by Wirestack itself on
open), `ws-host0`/`ws-client0` (veth pair), and the client namespace's
placeholder process. `setup.sh` refuses to run if any of these names
already exist, rather than silently reusing a leftover resource.

## Cleanup

`cleanup.sh` is idempotent and removes only these fixed-name resources:
it stops the Wirestack process and the client-namespace placeholder by
pid (recorded under the evidence directory), then deletes `ws-int-tap`,
`ws-host0`, and `ws-int-br` by name. Deleting the veth pair's host side
also removes its `ws-client0` peer. `run.sh` installs this as an `EXIT`
trap, so it runs whether the suite passes, fails, or is interrupted.
Running `cleanup.sh` again against an already-clean state is a no-op.

## Evidence directory

Each run creates `/tmp/wirestack-integration.XXXXXX` (`mktemp -d`) and
prints its path. It holds, per scenario: a full-length `.pcap`, a
decoded text trace with relative sequence numbers (`.txt`, easiest for
spotting reordering) and one with absolute sequence numbers (`.abs.txt`,
needed for exact wraparound arithmetic), plus the real client command's
own stdout/stderr. `wirestack.out` holds the process's own stdout/stderr
for the whole run. The directory is never deleted by the harness --
only the caller's own `/tmp` retention policy removes it.

## Tests performed

| # | Scenario | Mechanism |
|---|----------|-----------|
| 1 | ARP | `arping` from the client namespace |
| 2 | ICMP | `ping` from the client namespace |
| 3 | UDP | real UDP socket, port 9000, exact echo payload |
| 4 | TCP handshake | real TCP connect, verifies SYN/SYN-ACK options |
| 5 | HTTP + ordinary close | real `curl --http1.0`, exact body/headers, FIN exchange |
| 6 | Closed-port RST (SYN, no ACK) | real `connect()` to an unbound port |
| 7 | Closed-port RST (bare ACK) | a single crafted ACK segment (`IP_HDRINCL` raw socket, real bytes over the real wire -- not a substitute for kernel interoperability, since a bare-ACK-with-no-prior-connection segment cannot be produced through the ordinary socket API) |
| 8 | HTTP response timeout retransmission | `tc netem loss 100%` on `ws-host0` egress |
| 9 | SYN-ACK loss and recovery | `tc netem loss 100%` on `ws-host0` egress, applied before the first SYN |
| 10 | Reordering and receiver SACK | `tc netem ... reorder 100% gap 2` on `ws-client0` egress |

## Packet-loss mechanism (scenarios 8 and 9)

`tc qdisc add dev ws-host0 root netem loss 100%` drops 100% of egress
traffic on `ws-host0` -- the Wirestack-to-client direction only, since
`ws-host0`'s egress is exactly the direction the bridge forwards
Wirestack's frames toward the client. Capture is taken simultaneously at
`ws-int-tap` (upstream of the drop point -- shows every segment Wirestack
actually transmitted, including ones later dropped) and at `ws-host0`
(downstream -- shows what the client side actually received). This lets
the harness assert "Wirestack sent the original response, byte-identical
to the eventual retransmission" using the TAP capture, independent of
whether the netem-affected capture happens to also see the doomed
original (kernel behavior here is not guaranteed and is not relied on).

Scenario 9 applies the drop before the client's first SYN, so the very
first SYN-ACK is guaranteed lost; scenario 8 first lets a real connection
complete normally, then applies the drop, then sends the HTTP request,
so only the request/response exchange -- not the handshake -- is
affected.

## Reordering mechanism (scenario 10)

`tc qdisc add dev ws-client0 root netem delay 60ms reorder 100% gap 2`
delays every packet by 60ms except every second one, which is sent
immediately -- a deterministic technique (`man tc-netem`, `gap`), not a
probabilistic reorder percentage relied on to eventually happen. A
GET request with a 3000-byte ignored header (`X-Pad: aaaa...`, following
the same recipe as the manual procedure in `docs/tcp.md`) splits into
three real, MSS-bounded TCP segments; the middle or last one overtakes
an earlier one on the wire. The harness asserts this directly from the
capture: a data segment starting at a nonzero relative sequence offset
must appear on the wire before the segment starting at offset zero, and
Wirestack's ACK for it must carry a SACK option for the retained
out-of-order range while cumulative ACK stays at `rcv_nxt`.

## Expected results

All ten scenarios pass. See `docs/tcp.md` for the exact reset field
construction and `docs/http.md` for the exact response bytes asserted.

## Troubleshooting

- `conflicting pre-existing interface`: a previous run's resources were
  not cleaned up -- run `tools/integration/cleanup.sh` (inside the same
  kind of `unshare` sandbox) and retry.
- `must run as uid 0 inside a sandbox...`: the script was invoked
  without the `unshare --user --net --map-root-user --` wrapper.
- A scenario fails intermittently under heavy host load: the harness
  waits on real process/file readiness signals (tcpdump's own "listening
  on" message, the TAP interface appearing, etc.) rather than fixed
  sleeps for structural synchronization, but the loss/reorder scenarios
  still depend on wall-clock timing relative to Wirestack's 1-second
  initial RTO (`kInitialRto` in `include/wirestack/tcp_connection.hpp`)
  and are not immune to a sufficiently starved scheduler.
- Evidence from a failed run is never deleted; the printed evidence
  directory path is the starting point for diagnosis.

## Coverage limitations

- **Sender-side multi-segment SACK recovery is not live-qualified.** The
  current HTTP response (`docs/http.md`) is 120 bytes, well under one
  MSS, so the real application never gives Wirestack a multi-segment
  send to selectively retransmit from live. Sender-side SACK-driven
  recovery remains proven only by the deterministic wire-format tests in
  `tests/test_tcp_sack_path.cpp` and `tests/test_tcp_newreno_path.cpp`.
  Receiver-side SACK generation (advertising SACK blocks for retained
  out-of-order data) *is* live-qualified -- see scenario 10.
- TCP active open, keep-alive, HTTP/1.1, and TLS are out of scope for
  this milestone and are not exercised here (see `README.md`).
- The harness proves behavior inside its own isolated topology; it does
  not substitute for testing against a real physical NIC or a real
  routed network.
