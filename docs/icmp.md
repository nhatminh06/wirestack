# ICMP

## Supported form

Echo Request (type 8) and Echo Reply (type 0) only, code 0. Any other type
or a nonzero code is a well-formed-but-unsupported/invalid ICMP message
(`IcmpParseError::UnsupportedType` / `InvalidCode`), not a crash.

## Checksum

Covers the entire ICMP message — type, code, checksum field, identifier,
sequence, and payload — with no IPv4 pseudo-header (unlike UDP/TCP). Uses
the same `wirestack::internetChecksum` as IPv4's header checksum; see
[docs/ipv4.md](ipv4.md) for the validation convention. A bad checksum drops
the message.

## Echo Reply behavior

Wirestack only replies to Echo Requests addressed to its own IPv4 (checked
at the IPv4 layer, see docs/ipv4.md). The reply preserves the request's
identifier, sequence number, and payload exactly, changing only the type
(8 → 0); code stays 0. An incoming Echo Reply is parsed and ignored —
Wirestack never sends its own Echo Requests, so there is no reply-to-a-reply
behavior to implement.

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
sudo tcpdump -eni wire0 'arp or icmp'

# terminal 4
ping -c4 10.0.0.2
ping -c1 -s17 10.0.0.2   # odd-sized payload
```

Expected: an ARP request/reply pair (see [docs/arp.md](arp.md)), then four
ICMP Echo Request/Reply pairs, then `ping` reporting 0% packet loss.

## Limitations

- Echo Request/Reply only — no Destination Unreachable, Time Exceeded,
  Redirect, Timestamp, or other ICMP types.
- No rate limiting.
