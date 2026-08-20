# ARP

## Supported form

Only the Ethernet + IPv4 ARP packet form: hardware type 1 (Ethernet),
protocol type 0x0800 (IPv4), hardware size 6, protocol size 4. Any other
combination is a well-formed-but-unsupported packet (`ArpParseError`), not a
crash and not silently reinterpreted.

The parser accepts payloads of 28 bytes or more — Ethernet may pad a short
ARP frame up to the interface's minimum frame size, and the extra bytes are
not part of the logical ARP packet.

## Local IP/MAC configuration

Wirestack takes its IPv4 address and MAC address as command-line arguments:

```bash
sudo ./build/wirestack wire0 10.0.0.2 02:00:00:00:00:02
```

There is no default — both must be given explicitly.

## Request/reply flow

On a received ARP packet:

1. the sender IP/MAC is learned into the in-memory `ArpCache` (any valid
   packet, request or reply — never from a malformed one)
2. if it's a request, `sender=IP/MAC target=IP` is logged
3. if the request's target IP matches Wirestack's configured IP, a reply is
   built (sender = Wirestack's IP/MAC, target = the requester's IP/MAC),
   wrapped in an Ethernet frame (destination = requester's MAC, source =
   Wirestack's MAC, EtherType 0x0806), and written back through the TAP
   device
4. requests for any other IP produce no reply

Wirestack never initiates a request itself ("who has") — it only answers.

## Testing

Manual, since opening a TAP device requires `CAP_NET_ADMIN`:

```bash
# terminal 1
sudo ./build/wirestack wire0 10.0.0.2 02:00:00:00:00:02

# terminal 2
sudo ip addr add 10.0.0.1/24 dev wire0
sudo ip link set wire0 up
sudo ip neigh del 10.0.0.2 dev wire0 2>/dev/null || true

# terminal 3
sudo tcpdump -eni wire0 arp

# terminal 4
ping -c1 10.0.0.2
```

Expected `tcpdump` output:

```text
ARP, Request who-has 10.0.0.2 tell 10.0.0.1
ARP, Reply 10.0.0.2 is-at 02:00:00:00:00:02
```

Then:

```bash
ip neigh show 10.0.0.2 dev wire0
```

should show `02:00:00:00:00:02` (state may be `REACHABLE`, `STALE`, or
`DELAY` depending on timing — the mapping is what matters).

`ping` itself will not receive an Echo Reply — IPv4/ICMP are not
implemented yet. ARP resolution succeeding and ICMP not responding are both
expected at this stage.

To confirm Wirestack does not answer for addresses it doesn't own, request
another address in the subnet (e.g. `arping -I wire0 10.0.0.99` if
available, or any other neighbor-discovery trigger) and confirm no reply
appears in `tcpdump`.

## Limitations

- No outbound ARP resolution: Wirestack never sends its own "who has"
  requests.
- No cache eviction/aging — entries persist for the process lifetime.
- No gratuitous ARP handling beyond normal request/reply parsing.
- Single interface only.
