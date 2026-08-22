# DNS (bounded A-record resolution for the outbound HTTP client)

A minimal, one-shot DNS client (`dns.hpp`/`dns.cpp`) resolves a single
hostname to one IPv4 A record over Wirestack's own UDP/IPv4/Ethernet
stack, so `--http-get` can take a hostname instead of only a literal
IPv4 address. DNS logic has no TCP or HTTP knowledge; `main.cpp` is the
only place that connects a resolved address to an active-open TCP
connection.

## What this is not

Not a general resolver. No AAAA/IPv6, no CNAME following (a CNAME-only
response is treated as `NoAnswer`, not resolved), no recursive or
iterative resolution, no caching (positive or negative), no EDNS, no
DNSSEC, no DNS over TCP or TLS, no `/etc/resolv.conf`, no search
domains, no multiple resolvers or resolver rotation, no mDNS/LLMNR. One
configured server, one hostname lookup per process, one question, A/IN
over UDP only, classic messages up to 512 bytes.

## CLI

```bash
./build/wirestack wire0 10.0.0.2 02:00:00:00:00:02 \
  --http-get wirestack.test:9094 --dns-server 10.0.0.1:5353 \
  --source-port 49300 --target /
```

`--http-get`'s destination is tried as a literal IPv4 address first
(`Ipv4Address::parse`); only if that fails is it validated as a
hostname. `--dns-server <ip>:<port>` is required exactly when the
destination is a hostname, and rejected in every other case: a literal
IPv4 destination, `--active-open` (which never accepts a hostname,
DNS-configured or not), or passive mode. Duplicate `--dns-server`, a
missing value, or a malformed server address/port are all rejected.
All of this is validated by `parseRuntimeOptions` before the TAP device
is opened -- invalid input never falls back to passive mode (see
`runtime_options.hpp`'s `RuntimeOptionsParseResult` contract).

Literal IPv4 `--http-get` is unchanged and sends no DNS traffic at all.

## Hostname rules

ASCII only; total length 1-253 bytes; labels separated by `.`; each
label 1-63 bytes, letters/digits/hyphens only, never starting or ending
with `-`; no empty labels (so a trailing dot is rejected, not silently
stripped); no whitespace or control bytes; no CR/LF/NUL/colon; no IPv6
literals. A valid hostname is lowercased (`normalizeHostname` in
`dns.hpp`) before use in the query, the response question comparison,
and the Host header.

## Query encoding

`serializeDnsQuery` builds a standard 12-byte header (ID from the
client session; QR=0, Opcode=0, RD=1; QDCOUNT=1, ANCOUNT=NSCOUNT=
ARCOUNT=0) followed by QNAME/QTYPE=A(1)/QCLASS=IN(1), written as
explicit big-endian fields -- no packed structs, no reinterpret_cast
over the wire buffer. Rejects a message that would exceed 512 bytes.

Exact independent vector (transaction ID `0x1234`, hostname
`example.test`, hand-computed, not derived from Wirestack itself):

```text
12 34 01 00 00 01 00 00 00 00 00 00
07 65 78 61 6d 70 6c 65
04 74 65 73 74
00
00 01
00 01
```

## Response parsing

`parseDnsResponse` reads from a bounded byte span and validates, in
order: minimum 12-byte header and maximum 512-byte packet; QR is a
response; Opcode is zero; QDCOUNT is exactly one; total record count
(ANCOUNT+NSCOUNT+ARCOUNT) is at most 64 (`kMaxDnsRecordCount`), checked
before any record is parsed; transaction ID matches; the question name
matches the normalized hostname, QTYPE is A, QCLASS is IN; TC is clear;
RCODE. Every record read is bounds-checked against the actual packet --
a declared RDLENGTH or record count is never trusted past what the
buffer actually contains, and no allocation is ever sized directly from
an attacker-controlled count. Outcomes are an explicit enum: `Resolved`,
`NoAnswer`, `NxDomain`, `ServerFailure`, `Refused`, `Malformed`,
`Truncated`, `WrongTransaction`, `WrongQuestion`.

Order matters: transaction ID and question are checked before RCODE, so
an NXDOMAIN/SERVFAIL/REFUSED response for the *wrong* query is correctly
ignored (`WrongTransaction`/`WrongQuestion`), not treated as this
session's failure.

Exact independent vector (ID `0x1234`, question `example.test A IN`,
compressed-pointer answer `example.test A 10.0.0.1 TTL=60`):

```text
12 34 81 80 00 01 00 01 00 00 00 00
07 65 78 61 6d 70 6c 65
04 74 65 73 74
00
00 01
00 01
c0 0c
00 01
00 01
00 00 00 3c
00 04
0a 00 00 01
```

`parseDnsResponse` on this vector returns `Resolved` with address
`10.0.0.1`.

## Compression safety

Name decoding (`decodeName` in `dns.cpp`) handles ordinary labels,
uncompressed names, compression pointers, a literal-label prefix
followed by a pointer, and bounded pointer chains, tracking two cursors
that must never be confused: the position where the *record's own*
encoded name field ends (`bytes_in_record`, used by the caller to
resume parsing that record's remaining fields) and the pointer-chase
cursor used only internally while following pointers. A pointer must
reference strictly earlier in the packet than its own position; combined
with a fixed hop bound (`kMaxDnsPointerHops` = 16), this makes a
self-pointer or a pointer loop structurally rejected -- each hop
strictly decreases the cursor, so at most `kMaxDnsPointerHops` hops are
ever followed regardless of how the packet is constructed. Also
rejected: a label declared longer than 63 bytes (structurally
impossible to express except through a reserved label-tag form, which
is rejected directly), a truncated label or incomplete pointer, a
pointer targeting outside the packet, a decoded name over 253 bytes, and
an unterminated name (truncation before either a zero label or a valid
pointer is found).

## A-record selection

An acceptable answer requires all of: it appears in the Answer section
(never Authority or Additional, even if otherwise well-formed and
matching); its owner name equals the queried hostname exactly (after
decompression); TYPE is A; CLASS is IN; RDLENGTH is exactly 4. The first
acceptable answer in wire order is selected; a structurally valid but
non-matching record (wrong owner, wrong type, wrong class, wrong
RDLENGTH) is parsed (to keep the record cursor correct) and then
ignored. A CNAME-only response, or a response with zero answers,
produces `NoAnswer` -- never `Resolved`. TTL is parsed (so the record's
own byte layout is validated) but never stored or used for caching.

## DNS client session and retry timing

`DnsClientSession` (`dns.hpp`) holds exactly: the configured server
IPv4/port, a fixed local UDP source port (`kDnsClientSourcePort` =
53000 -- Wirestack has no general ephemeral-port allocator yet, so this
is a hardcoded constant independent of the TCP source port configured
via `--source-port`), the normalized hostname, the transaction ID, the
exact serialized query bytes (so every retransmission is byte-identical
to the first), a transmit count, the next retry deadline, and a
terminal state (`Pending`/`Resolved`/`Failed`) plus the resolved address
or failure reason once terminal.

Fixed schedule, driven by the same poll-based event loop as TCP
retransmission (no timer thread, no busy loop): initial query at t=0s;
retry 1 at t=1s; retry 2 at t=3s (backoff doubles, capped at 4s); if
still unresolved, terminal timeout at t=7s with no fourth query. The DNS
deadline is folded into `main.cpp`'s existing `poll()` timeout alongside
the TCP retransmission and persist deadlines (`std::min` of whichever
deadlines are armed).

Response eligibility (`handleDnsResponse`) requires all of: source IPv4
equals the configured server; source UDP port equals the configured
server port; destination UDP port equals the local DNS client port;
transaction ID matches the outstanding query; question matches the
normalized hostname/A/IN. Anything else (wrong source, wrong port, wrong
transaction, wrong question, or a structurally malformed/truncated
datagram) is ignored and the session keeps waiting for its own timeout
-- it is never treated as this session's answer, and it never resets or
extends the retry timer. A response arriving after the session already
reached `Resolved`/`Failed` is likewise ignored (`handleDnsResponse`
returns `false` once state is no longer `Pending`), so a duplicate or
late reply can never create a second TCP connection.

## Failure policy

NXDOMAIN, REFUSED, and SERVFAIL are all terminal failures (distinct
`DnsResponseOutcome` values, and thus distinct log reasons). A NOERROR
response with no matching A answer is a terminal `NoAnswer`. Exhausting
all 3 transmissions without any eligible response is a terminal timeout
(logged as `reason=Timeout`, which carries no DNS RCODE). No DNS failure
ever falls back to passive mode, connects to `0.0.0.0` or the DNS
server's own address, starts TCP before resolution completes, or reuses
stale session state -- `main.cpp`'s active-open dial loop only runs once
`dial_target_ip` has been set, which only happens on the single
`handleDnsResponse` call that transitions the session to `Resolved`.

Exactly one terminal line is printed and flushed:

```text
dns-client: resolved wirestack.test -> 10.0.0.1
dns-client: resolution failed host=wirestack.test reason=NXDOMAIN
```

## HTTP Host header

The TCP connection dials the *resolved* IPv4 address, but the HTTP
`Host` header carries the original authority text -- `wirestack.test:9094`,
never `10.0.0.1:9094`. `HttpClientSession::host_header` is a plain
string built once, before resolution even completes (`hostname + ":" +
port`), completely independent of `HttpClientSession::remote_ip`, which
is the actual TCP destination used only for logging.
`buildHttpGetRequest` itself takes only a host-header string, not an
IPv4 address -- it has no notion of "the destination" at all, literal or
resolved. For a literal IPv4 destination, `host_header` is unchanged
from Milestone 17: `<ip>:<port>`.

## UDP/DNS packet paths

Outgoing: DNS query bytes -> `serializeUdpDatagram` -> `serializeIpv4Packet`
-> `serializeEthernetFrame` -> TAP, exactly the same layering as any
other outgoing UDP datagram (`sendUdpPacket` in `main.cpp`).

Incoming: TAP -> `parseEthernetFrame` -> `parseIpv4Packet` ->
`parseUdpDatagram` (ordinary UDP header/checksum validation, unchanged)
-> `handleDnsClientUdp` checks the *destination port* against the DNS
client's fixed local port before doing anything else. A match is
handed to `handleDnsResponse` and never reaches the UDP echo endpoint
table (`UdpEndpointTable`, port 9000); anything that doesn't match falls
through to the ordinary `handleUdp` dispatch unchanged. Existing UDP
port 9000 echo behavior is untouched.

## Manual verification procedure

For a reproducible, automated version of this check with packet-capture
evidence, see `tools/integration/dns_http_get.sh` and
[docs/interoperability.md](interoperability.md).

```bash
# terminal 2 (inside the harness's client namespace): a Python DNS server
# on 10.0.0.1:5353 answering wirestack.test with 10.0.0.1, and an
# HTTP/1.0 server on 10.0.0.1:9094.

# terminal 1
sudo ./build/wirestack wire0 10.0.0.2 02:00:00:00:00:02 \
  --http-get wirestack.test:9094 --dns-server 10.0.0.1:5353 \
  --source-port 49300 --target /
```

Expected stdout: `dns-client: query sent host=wirestack.test id=...`,
then `dns-client: resolved wirestack.test -> 10.0.0.1`, then the same
active-open/HTTP-client lines Milestone 17 already produces, addressed
to `10.0.0.1:9094` with `Host: wirestack.test:9094`.

## Limitations

- A/IN over UDP only; no AAAA, no DNS over TCP/TLS/HTTPS.
- Exactly one configured DNS server, one hostname lookup per process,
  one DNS question.
- Only a direct matching A answer is accepted; no CNAME following (a
  CNAME-only response is `NoAnswer`, never resolved through it).
- No caching, positive or negative; every process run resolves fresh.
- No EDNS, no DNSSEC.
- Fixed local DNS UDP source port (53000) -- Wirestack still has no
  general ephemeral-port allocator.
- Hostname resolution exists only for the outbound HTTP client's
  destination; nothing else in Wirestack resolves hostnames.
- The existing ARP/neighbor-resolution limitation is unchanged: sending
  the DNS query still requires the server's MAC to already be in the
  ARP cache (learned passively; Wirestack sends no ARP requests of its
  own), and the same is true of the resolved HTTP destination's MAC
  once resolution completes.
- Not a general-purpose resolver, not RFC-complete, not suitable for use
  beyond this local, cooperating, single-server test setup.
