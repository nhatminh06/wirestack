# IPv4

## Supported form

Base 20-byte header only (version 4, IHL 5). Any other IHL is a
well-formed-but-unsupported header, not a crash — IHL > 5 (options present)
returns `Ipv4ParseError::UnsupportedOptions` rather than silently parsing
around option bytes.

Fragmentation is not supported: a packet with the More Fragments flag set,
or a nonzero fragment offset, is rejected as `Ipv4ParseError::Fragmented`.
The Don't Fragment flag alone does not cause rejection — it has no effect
on parsing, since Wirestack never fragments anything itself.

`Ipv4Packet` does not store the raw flags/fragment-offset word or the
version/IHL fields: they're validated during parsing but have no reader
afterward (every packet Wirestack constructs is inherently unfragmented,
version 4, IHL 5).

## Checksum

The standard Internet checksum (RFC 1071), shared with ICMP via
`wirestack::internetChecksum` (`include/wirestack/checksum.hpp`). Convention:
summing a header with a correct checksum field already in place yields 0
after complementing. To generate a checksum, sum with the checksum field
zeroed, then write the (complemented) result into that field.

A bad header checksum is `Ipv4ParseError::BadChecksum`; the packet is
dropped, not acted on.

## Local delivery only

Wirestack is a local IPv4 endpoint, not a router. A well-formed packet is
processed further only when its destination address matches Wirestack's
configured local IPv4 (given on the command line) and its TTL is nonzero.
Packets for any other destination, or with TTL 0, are silently ignored —
not forwarded, not replied to, not logged as errors (this is expected
behavior for ordinary broadcast/multicast traffic on the segment, not a
fault condition).

An unsupported upper-layer protocol (anything but ICMP) is still a valid
IPv4 packet — it's accepted and ignored, not treated as malformed.

## Ethernet padding

Ethernet may pad a short frame beyond the IPv4 packet's own declared
`total_length`. The parser reads exactly `total_length - 20` payload bytes
starting after the header; anything past `total_length` in the input span
is never treated as IPv4 payload.

## Limitations

- No IPv4 options processing.
- No fragmentation or reassembly.
- No routing/forwarding.
- Base header only; ECN/DSCP bits are carried through but not interpreted.
