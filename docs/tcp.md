# TCP

## Current support

Passive three-way handshake, single-segment in-order application data
transfer with a built-in echo demonstration, bounded timeout-based
retransmission of SYN-ACK/data/FIN, passive/active/simultaneous close with
a deterministic TIME_WAIT, and acceptable-inbound-RST/closed-port-RST
handling, over IPv4, on a single fixed listening port (8080). No active
open, no segmentation, no reassembly, no congestion control.

`TcpSegment` holds source/destination ports, sequence/acknowledgment
numbers, flags, window size, urgent pointer, and the raw `options` and
`payload` byte ranges. Data offset and checksum are not stored -- both are
derived/validated wire values, the same pattern already used for
`Ipv4Packet` and `UdpDatagram`. Options are preserved verbatim (needed to
locate the payload correctly) but never interpreted; a normal Linux SYN
commonly carries options (MSS, window scale, SACK-permitted, timestamps),
and the parser safely skips over them without understanding their
semantics.

## Current state machine

```text
(no entry) --SYN--> SYN_RECEIVED --valid ACK--> ESTABLISHED

ESTABLISHED --app FIN--> FIN_WAIT_1 --ACK of FIN--> FIN_WAIT_2 --peer FIN--> TIME_WAIT
FIN_WAIT_1 --peer FIN (not ACKing local FIN)--> CLOSING --ACK of FIN--> TIME_WAIT
FIN_WAIT_1 --peer FIN that also ACKs local FIN--> TIME_WAIT

ESTABLISHED --peer FIN--> CLOSE_WAIT --app FIN--> LAST_ACK --ACK of FIN--> (removed)

TIME_WAIT --60s elapsed--> (removed)
any synchronized state --acceptable RST--> (removed)
```

LISTEN is implicit: a connection key with no table entry is either
unbound or simply hasn't received a SYN yet. No `TcpState::Listen` or
`TcpState::Closed` tombstone object is stored -- a connection that closes
cleanly or resets is erased from the table, not marked closed. `TcpState`
has eight values: `SynReceived`, `Established`, `FinWait1`, `FinWait2`,
`CloseWait`, `Closing`, `LastAck`, `TimeWait`.

## Checksum behavior

Same Internet checksum (`wirestack::internetChecksum`) and pseudo-header
shape UDP already established (source IPv4, destination IPv4, zero byte,
protocol, length), with protocol 6 and length equal to the full TCP
segment length. Unlike UDP, TCP has no "checksum omitted" exemption for a
zero checksum field -- every segment's checksum is validated
unconditionally.

## Connection identity

The four-tuple `(local_ip, local_port, remote_ip, remote_port)`. Two
remote peers connecting to the same listening port produce two
independent connection entries with independently drawn initial sequence
numbers.

## Handshake flow

1. SYN to the listening port with no existing connection: a new entry is
   created (state `SynReceived`, remote ISN = the SYN's sequence number,
   local ISN = a freshly drawn value), and a SYN-ACK is returned
   (sequence = local ISN, acknowledgment = remote ISN + 1).
2. A repeated SYN for an existing `SynReceived` connection (matching
   sequence number) retransmits the same stored SYN-ACK rather than
   drawing a new ISN or creating a second entry.
3. A valid final ACK (acknowledgment number = local ISN + 1, sequence
   number = remote ISN + 1) transitions the connection to `Established`.
   No reply is sent for a valid final ACK.
4. Any other traffic for the listening port -- an ACK with no prior SYN,
   an ACK with the wrong acknowledgment number, a segment for an unknown
   connection, or a segment for any port other than 8080 -- is silently
   dropped. No RST is generated for closed ports; no ICMP is generated.

### Initial sequence number

Wirestack's local ISN comes from a small incrementing counter internal to
`TcpConnectionTable`, isolated behind one private method
(`nextIsn()`). This is explicitly **not** a secure or RFC 6528-style ISN
generator -- it exists only to give each connection a distinct,
deterministic starting sequence number for testing, and can be replaced
later without touching handshake logic.

### Window field

The outgoing SYN-ACK always advertises a fixed window (65535). There is no
receive-window accounting or flow control; the field is transmitted but
not backed by real buffer-space tracking.

## Established-state data transfer

### Sequence-space state

On the handshake-completing ACK, three fields are initialized from the
client's initial sequence number (`C`) and Wirestack's initial sequence
number (`S`), each already validated during the handshake:

```text
rcv_nxt = C + 1   -- next client sequence number expected
snd_una = S + 1   -- oldest unacknowledged Wirestack sequence number
snd_nxt = S + 1   -- next sequence number Wirestack will send
```

### Receiving application data

A segment is only considered for payload delivery when the connection is
Established, ACK is set, and SYN/FIN/RST are all clear (any of those three
flags on an Established segment drops it entirely, payload included --
none of them are implemented). PSH is optional; delivery does not depend
on it. An ACK number beyond `snd_nxt` invalidates the whole segment (no
state change, no delivery). A valid ACK number advances `snd_una` when
it's ahead of the current value; a duplicate or stale ACK leaves it
unchanged.

For a non-empty payload:

- `segment.sequence_number == rcv_nxt` (in-order, new data): the payload
  is exposed to the caller exactly once, and `rcv_nxt` advances by the
  payload length.
- any other sequence number -- duplicate, out-of-order, or overlapping --
  is treated identically: nothing is delivered, `rcv_nxt` is unchanged,
  and a duplicate ACK for the current `rcv_nxt` is generated. There is no
  out-of-order buffering and no overlap classification; this is
  intentionally the smallest correct behavior, not reassembly.

An ordinary ACK-only Established segment (empty payload, valid ACK
number) updates ack-processing state and produces no reply -- replying to
every ACK would create an ACK loop.

### Sending application data and generating ACKs

A pure ACK (`sequence_number = snd_nxt`, `acknowledgment_number =
rcv_nxt`, flags ACK only, empty payload) consumes no sequence space and
is used only for the duplicate/out-of-order/overlapping-data case above.

An outgoing data segment (`sequence_number = snd_nxt`,
`acknowledgment_number = rcv_nxt`, flags PSH|ACK, payload as given)
advances `snd_nxt` by the payload length once the segment is
successfully constructed; it is rejected (state unchanged) for an unknown
or not-yet-Established connection, an empty payload, or a payload that
would push the segment past the 65535-byte pseudo-header length limit.
One call produces at most one segment -- no segmentation.

Sequence comparisons use 32-bit unsigned arithmetic with a
wraparound-safe signed-difference check, under the assumption that the
tracked send/receive window stays under half of the 32-bit sequence
space.

### Echo demonstration

Wirestack's TCP layer has no knowledge of any application or close
policy -- `TcpReceiveResult::peer_closed` is reported, not acted on,
inside `tcp_connection.cpp`. `main.cpp` implements the smallest possible
policy on port 8080: whatever payload is accepted (from `Established` or
`CloseWait`) is passed unmodified to `makeOutgoingData` and sent back;
once that echo has been sent, an accepted peer FIN triggers
`beginClose`, initiating Wirestack's own close after the echo, never
before or instead of it -- so a FIN arriving together with a final
payload still gets that payload echoed. This is a TCP echo demonstration,
not an HTTP server -- Wirestack does not parse or understand HTTP
requests sent to port 8080.

## Retransmission

### What is queued

Every outgoing segment that consumes TCP sequence space -- the SYN-ACK,
and each `PSH|ACK` data segment from `makeOutgoingData` -- is registered
in a per-connection pending queue, in the order sent, each entry owning
its own copy of the payload bytes. Pure ACKs (generated for
duplicate/out-of-order/overlapping data) consume no sequence space and
are never queued or timed.

### Cumulative and partial ACK retirement

A valid ACK (`snd_una < ack <= snd_nxt`, using the same wraparound-safe
comparison as the rest of sequence-space tracking) retires every pending
entry it fully covers, in order, from the front of the queue. If the ACK
lands inside the oldest remaining entry, that entry is trimmed in place:
its sequence start advances to the ACK value and its payload is trimmed
to the unacknowledged suffix -- already-acknowledged bytes are never
retransmitted. A duplicate (`ack == snd_una`) or stale (behind `snd_una`)
ACK leaves the queue untouched; an ACK beyond `snd_nxt` is rejected
entirely (no state change) before retirement is even considered.

### Clock and RTO policy

Retransmission timing uses `std::chrono::steady_clock`
(`wirestack::TcpClock`) so it is unaffected by wall-clock changes.
`handle()`, `makeOutgoingData()`, and `pollRetransmissions()` all take an
explicit `time_point`, so tests drive timing deterministically (fixed
synthetic instants, advanced by explicit durations) without sleeping or
depending on machine speed.

```text
initial RTO:          1 second
backoff:               double after each timeout-triggered retransmission
maximum RTO:           8 seconds
maximum retransmits:   5 (after the original, non-counted send)
```

This is an explicit educational policy, not RFC 6298 -- there is no RTT
sampling, no smoothed RTT/variance, and no Karn's algorithm.

### Retransmitting

`pollRetransmissions(now)` returns every pending entry whose deadline
(`last_sent + rto`) has passed. A retransmission reuses the entry's
stored sequence start, flags, and (already-trimmed) payload; for data,
the acknowledgment field is refreshed to the connection's *current*
`rcv_nxt` (the client may have sent more data since the original send).
It never advances `snd_nxt` or `snd_una`, and never re-delivers
application data to the echo policy -- a retransmission is not a new
logical send. A duplicate incoming SYN re-arms the pending SYN-ACK's
deadline from the duplicate's arrival time without consuming any of the
5-retransmission budget.

### Timeout exhaustion

Once a pending entry has already been retransmitted 5 times, its next
expired deadline removes the connection from the table entirely and
reports it to the caller -- no FIN, no RST, just a local abort. This is
intentionally not a graceful close.

### Delayed-reply addressing

TCP connection state stores no MAC addresses. A timer-triggered
retransmission has no current received frame to read a destination MAC
from, so `main.cpp` looks it up in the existing `ArpCache`, which now
learns IP->MAC mappings from any valid local IPv4 traffic (not just ARP
packets) so a mapping is available even if the peer's last ARP exchange
has aged out of relevance. If no mapping is known, the retransmission
attempt is skipped (logged) but still counts toward the 5-retry budget --
otherwise a persistently-unreachable peer would retry forever.

## Connection close

### FIN sequence accounting

FIN consumes exactly one sequence number, on top of any payload in the
same segment: `sequence consumption = payload.size() + (SYN?1:0) +
(FIN?1:0)`. RST and a pure ACK consume none. A locally-sent FIN is queued
through the same `PendingTransmission` mechanism as SYN-ACK and data (a
`bool is_fin` flag alongside the existing `is_syn`), so it is
retransmitted, cumulatively/partially ACK-retired, and backed off exactly
like any other queued segment -- no separate FIN-ACK arithmetic exists.
FIN and SYN both occupy a 1-wide sequence range, so neither can ever be
partially ACKed; only a data entry's payload is ever trimmed.

### Peer-initiated (passive) close

A valid in-order FIN (`segment.sequence_number == rcv_nxt`) is accepted
exactly like in-order data, then additionally consumes one more sequence
number and exposes peer EOF (`TcpReceiveResult::peer_closed`) exactly
once -- a duplicate or out-of-order FIN is indistinguishable from
duplicate/out-of-order data and gets the same duplicate-ACK treatment,
never a second `peer_closed`. `Established` moves to `CloseWait`. The
connection is not removed and its pending queue is untouched: the
application may still call `makeOutgoingData` (now also valid in
`CloseWait`, not just `Established`) before initiating its own close --
half-close, matching what a future request/response protocol needs. When
the application is ready, `beginClose` sends the local FIN and moves
`CloseWait -> LastAck`; the peer's ACK of that FIN removes the connection
silently (no reply, no application event). An ACK that doesn't cover the
FIN leaves the connection in `LastAck` unchanged.

### Application-initiated (active) close

`TcpConnectionTable::beginClose(key, now)` builds a `FIN|ACK` segment
(`sequence_number = snd_nxt`, `acknowledgment_number = rcv_nxt`, no
payload), queues it, advances `snd_nxt` by one, and moves `Established ->
FinWait1`. It rejects (returns `nullopt`, no state change) every other
state, including a second call in `FinWait1` itself -- calling it twice
never creates a second FIN. The peer's ACK of the local FIN moves
`FinWait1 -> FinWait2`; the peer's subsequent FIN in `FinWait2` is
accepted, ACKed, and enters `TimeWait`.

### Simultaneous close

If the peer's FIN arrives in `FinWait1` without also acknowledging the
local FIN, the connection moves to `Closing`; a later ACK of the local FIN
then moves `Closing -> TimeWait`. If a single segment received in
`FinWait1` both carries an acceptable FIN and validly ACKs the local FIN,
the connection reaches `TimeWait` directly in one call -- this requires no
special-case code: the ACK-driven `FinWait1 -> FinWait2` transition and
the FIN-driven `FinWait2 -> TimeWait` transition are both evaluated (in
that order) within the same `handle()` call, and simply compose.

### TIME_WAIT

A fixed, non-adaptive 60-second duration (`wirestack::kTimeWaitDuration`),
timed on the same `TcpClock` (`steady_clock`) as retransmission, and
included in `nextRetransmissionDeadline()` so the TAP event loop's
`poll()` still wakes up for expiry with no packets arriving. A
retransmitted peer FIN received while in `TimeWait` (same sequence number
as the original) does not re-signal EOF, does not change any sequence
state, and is not queued -- it gets a freshly built pure ACK and restarts
the 60-second deadline. Any other traffic in `TimeWait` (a SYN, a
non-empty payload, an ordinary ACK) is dropped. When the deadline expires,
the connection is removed with no further traffic.

## Reset handling

### Inbound RST

Accepted only when its sequence number exactly matches what the
connection currently expects: `rcv_nxt` in every synchronized state
(`Established`, `FinWait1`, `FinWait2`, `CloseWait`, `Closing`, `LastAck`,
`TimeWait`), or `remote_isn + 1` (the outstanding SYN-ACK's expected ACK)
in `SynReceived`. An accepted RST removes the connection immediately,
discards its pending queue, delivers no payload, and never produces a
response -- Wirestack never replies to an RST with another RST, and never
implements challenge ACKs. An unacceptable RST changes nothing.

### Closed-port RST

Generated for a segment addressed to an unbound local port, or a bound
port with no matching connection where the segment is not a valid new
SYN (an ACK, payload, FIN, or SYN|ACK against an unknown four-tuple).
Standard narrow construction: if the incoming segment has ACK set, the
reset carries `sequence_number = incoming.acknowledgment_number` and RST
only; otherwise `sequence_number = 0`, `acknowledgment_number =
incoming.sequence_number + payload.size() + (SYN?1:0) + (FIN?1:0)` (plain
wraparound `uint32_t` addition), and RST|ACK. Never generated in response
to an incoming RST, and never creates connection state or a retransmission
entry.

## Manual verification procedure

Opening a TAP device requires `CAP_NET_ADMIN`:

```bash
# terminal 1
sudo ./build/wirestack wire0 10.0.0.2 02:00:00:00:00:02

# terminal 2
sudo ip addr add 10.0.0.1/24 dev wire0
sudo ip link set wire0 up
ping -c1 10.0.0.2   # confirm ARP + ICMP still work first

# terminal 3
sudo tcpdump -eni wire0 'tcp port 8080'

# terminal 4
nc 10.0.0.2 8080
# type: hello wirestack
```

Expected in tcpdump: `Flags [S]` from the client, `Flags [S.]` from
Wirestack, `Flags [.]` from the client -- a complete three-way handshake
-- followed by the client's data segment, Wirestack's `Flags [P.]`
carrying the identical bytes back plus the acknowledgment, and the
client's final ACK. In the terminal running `nc`, the typed line should
be echoed back immediately. Do not use `curl`: HTTP is not implemented,
and echoing an HTTP request back is not a valid HTTP response.

To exercise close: in the `nc` terminal, close stdin (e.g. Ctrl-D). Expect
`Flags [F.]` from the client, Wirestack's `Flags [.]` ACKing it, then
Wirestack's own `Flags [F.]`, and the client's final `Flags [.]`. To
exercise reset generation, connect to an unbound port instead:

```bash
nc 10.0.0.2 8081
```

Expect a `Flags [S]` from the client immediately followed by `Flags [R.]`
from Wirestack; `nc` should report the connection refused/reset. Do not
apply loss injection (`tc`, network namespaces, iptables rules) against a
shared or production interface -- this procedure assumes an isolated TAP
device with no other traffic.

## Known limitations

- No RTT sampling or smoothing -- the RTO policy is a fixed
  1s/2s/4s/8s-capped backoff, not RFC 6298.
- No fast retransmit (duplicate-ACK triggered) -- only timeout triggers
  retransmission.
- No congestion control.
- No dynamic receive window (fixed value only).
- No active open (Wirestack never initiates a connection).
- No challenge ACK; an unacceptable RST is simply dropped.
- No TCP option negotiation or interpretation (MSS, window scale, SACK,
  timestamps are all safely skipped, never acted on).
- No out-of-order buffering, overlap merging, or reassembly -- duplicate,
  out-of-order, and overlapping data are all dropped (with a duplicate
  ACK), never combined into a receive buffer.
- No segmentation -- one accepted input segment produces at most one
  outgoing segment; larger transfers are not split.
- Single built-in echo endpoint on port 8080; no general application
  registration.

## Next TCP work

Minimal HTTP/1.0 GET parsing and a static response over the now-verified
TCP lifecycle.
