# TCP

## Current support

Passive three-way handshake with SYN-carried MSS/Window Scale option
negotiation, MSS-bounded outgoing segmentation within the peer's
advertised (and, when negotiated, scaled) send window, bounded
out-of-order receive reassembly with duplicate/overlap trimming, RTT
measurement with an adaptive SRTT/RTTVAR/RTO estimator driving
timeout-based retransmission of SYN-ACK/data/FIN, passive/active/
simultaneous close with a deterministic TIME_WAIT, and
acceptable-inbound-RST/closed-port-RST handling, over IPv4, on a single
fixed listening port (8080). No active open, no congestion control, no
fast retransmit, no SACK, no timestamps. Port 8080 hosts the minimal
HTTP/1.0 demonstration described in [docs/http.md](http.md), not a raw
byte echo -- this file covers only TCP itself.

`TcpSegment` holds source/destination ports, sequence/acknowledgment
numbers, flags, window size, urgent pointer, and the raw `options` and
`payload` byte ranges. Data offset and checksum are not stored -- both are
derived/validated wire values, the same pattern already used for
`Ipv4Packet` and `UdpDatagram`. Options are preserved verbatim on every
parsed segment; `parseTcpOptions` (`tcp.hpp`/`tcp.cpp`) is a separate,
stateless byte-level scan applied only to a bare SYN's options during
connection creation -- see "TCP options" below.

## TCP options

`parseTcpOptions(options)` returns a `TcpParsedOptions{maximum_segment_size,
window_scale}` (each `std::optional`) or a `TcpOptionParseError`. A
single left-to-right cursor scan: kind 0 (End of List) stops parsing
immediately; kind 1 (No-Operation) advances one byte; every other kind
requires a length byte (`MissingLength` if absent), `length >= 2`
(`InvalidLength`), and enough remaining bytes for the declared length
(`TruncatedOption`) before it is read. Kind 2 (MSS) requires `length ==
4` and a nonzero 16-bit value (`InvalidMss` otherwise); kind 3 (Window
Scale) requires `length == 3`; a second occurrence of either is
`DuplicateMss`/`DuplicateWindowScale`. Any other well-formed kind is
safely skipped using its own declared length without being interpreted.
No index ever advances past `options.size()`.

Negotiation happens exactly once, in `handle()`'s bare-SYN branch, from
that SYN's own `parseTcpOptions` result:

- A parse error produces no connection, no SYN-ACK, and no RST -- the
  segment is simply dropped.
- `peer_mss = maximum_segment_size.value_or(536)` -- the IPv4 default
  peer MSS fallback: 536 bytes when the SYN omits MSS entirely.
  `effective_send_mss = min(1460, peer_mss)`, the MSS actually used to
  size Wirestack's own outgoing segments to this peer.
- If `window_scale` is present, `window_scaling_enabled = true`,
  `peer_window_scale = min(window_scale, 14)` (RFC 1323's own clamp),
  `local_window_scale = 2` (Wirestack's fixed local shift). Otherwise all
  three stay at `false`/`0`/`0` and every window on this connection stays
  a plain unscaled 16-bit value.

A later non-SYN segment's options (if any) are never parsed for
negotiation purposes -- negotiation is a one-time, SYN-only decision. A
duplicate SYN for an existing `SynReceived` connection replays the
already-stored SYN-ACK unchanged regardless of what options the
duplicate itself carries; negotiated state is never touched twice.

Wirestack's outgoing SYN-ACK always advertises its own path MSS (1460),
never the peer's offered value: `02 04 05 b4`. When
`window_scaling_enabled`, it also advertises `01 03 03 02` (NOP + kind=3
length=3 shift=2) immediately after, giving an 8-byte option block (TCP
header 28 bytes, Data Offset 7); without negotiation, the option block is
just the 4 MSS bytes (TCP header 24 bytes, Data Offset 6). Neither the
SYN-ACK's own window field, nor a retransmission of it, is ever scaled --
window scaling first applies starting with the handshake's own completing
ACK.

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

The outgoing SYN-ACK advertises the current advertised receive window
(see "Receive windows and reassembly" below) -- 65535 for a fresh
connection with nothing buffered, shrinking as out-of-order bytes
accumulate.

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
synchronized (`Established` or `CloseWait`, plus `FinWait1`/`FinWait2`
for a peer FIN still to arrive), ACK is set, and SYN is clear (a SYN on
an already-synchronized segment drops it entirely; RST is handled
separately -- see "Reset handling"). PSH is optional; delivery does not
depend on it. An ACK number beyond `snd_nxt` invalidates the whole
segment (no state change, no delivery, no reassembly buffering, no FIN
retention). A valid ACK number advances `snd_una` when it's ahead of the
current value and updates the peer send window (see below); a duplicate
or stale ACK leaves both unchanged.

For a non-empty payload or a FIN, the segment is trimmed to the current
receive window and handed to the reassembly buffer -- see "Receive
windows and reassembly" for the full left-trim/right-trim/buffer/release
algorithm. `accepted_payload` is non-empty only when this call made new
bytes contiguous with `rcv_nxt`, whether because the segment itself
arrived in order or because it closed the last gap needed to release
previously buffered out-of-order bytes (possibly several fragments'
worth, concatenated).

An ordinary ACK-only Established/CloseWait segment (empty payload, no
FIN, valid ACK number) updates ack-processing state and produces no
reply -- replying to every ACK would create an ACK loop. A segment that
releases no new contiguous bytes (duplicate, still-gapped, or entirely
outside the window) gets a duplicate ACK reflecting the current
`rcv_nxt` and advertised window instead.

### Sending application data and generating ACKs

A pure ACK (`sequence_number = snd_nxt`, `acknowledgment_number =
rcv_nxt`, flags ACK only, empty payload) consumes no sequence space and
is used only for the no-new-contiguous-bytes case above.

`makeOutgoingData` segments `payload` into `ceil(N / kTcpMss)` PSH|ACK
segments (`kTcpMss` = 1460 bytes -- see "MTU and MSS" below), each with
`acknowledgment_number = rcv_nxt` and the current advertised window, PSH
set only on the final segment, contiguous sequence numbers starting at
`snd_nxt`. The send is atomic (see "Send window" below): either every
byte is accepted and segmented, registering one retransmission-queue
entry per segment and advancing `snd_nxt` once by the total length, or
nothing is queued and `snd_nxt` is unchanged. `beginClose`'s FIN segment
also uses the current advertised window and requires one byte of
available send window, same as any other send.

Sequence comparisons use 32-bit unsigned arithmetic with a
wraparound-safe signed-difference check, under the assumption that the
tracked send/receive window stays under half of the 32-bit sequence
space.

## MTU and MSS

```text
IPv4 MTU:                 1500 bytes
IPv4 header:                20 bytes
TCP header:            20 or 28 bytes  (28 only when Window Scale is negotiated)
local path MSS:           1460 bytes  (wirestack::kTcpMss -- always advertised, never negotiated down)
default peer MSS:          536 bytes  (wirestack::kDefaultPeerMss -- used only when the SYN omits an MSS option)
```

`makeOutgoingData` segments a send into `ceil(N / effective_send_mss)`
chunks, where `effective_send_mss = min(kTcpMss, peer_mss)` was fixed at
handshake time (see "TCP options" above) -- so a peer that omits an MSS
option or advertises less than 1460 gets correspondingly smaller
outgoing segments, while a peer advertising more than 1460 never causes
Wirestack to exceed its own path MSS. A single application send whose
segmentation would need more than `kMaxSegmentsPerSend` (128) segments is
rejected atomically (`TcpSendError::TooLarge`) rather than partially
queued.

## Send window

`Connection` tracks the peer-advertised window as a logical 32-bit value
(`snd_wnd`) and the sequence/ack numbers of the segment that last
legitimately updated it (`snd_wl1`/`snd_wl2`, RFC 793's SND.WL1/WL2), so
a segment that arrives out of order can never replace a newer window
advertisement with a stale one. Every incoming window field is decoded
through `decodePeerWindow`: `window_scaling_enabled ? (raw <<
peer_window_scale) : raw` -- the PEER's own negotiated shift, distinct
from and never to be confused with Wirestack's own `local_window_scale`
(see "Receive windows and reassembly" below). This applies to the
handshake-completing ACK's initial `snd_wnd`
and to every later `updateSendWindow` call -- but never to the SYN or
SYN-ACK's own window fields, which are defined to stay raw/unscaled
regardless of negotiation (RFC 1323). `snd_wnd` is updated on every valid
ACK-bearing segment when `seq > snd_wl1`, or `seq == snd_wl1 and snd_wl2
<= ack`.

```text
flight_size = snd_nxt - snd_una
available    = flight_size >= snd_wnd ? 0 : snd_wnd - flight_size
```

An application send of `N` bytes (`makeOutgoingData`, capped at
`kMaxApplicationSendSize` = 65535 bytes regardless of window) is
permitted only when `N <= available`; a local FIN requires `available
>= 1`. A zero window blocks all new payload and FIN sends but does not
block anything else: ACK and RST processing continue normally, and
already-outstanding (unacknowledged) segments still retransmit on
schedule through the existing timeout machinery -- there is no persist
timer and no zero-window probe, so once the window is genuinely zero and
nothing is outstanding, Wirestack simply waits for the peer to advertise
room; callers must retry a rejected send later themselves, since there is
no internal send queue.

## Receive windows and reassembly

### Capacity

```text
receive capacity:            262140 bytes  (wirestack::kTcpReceiveCapacity, 65535 << 2)
local window scale shift:         2        (wirestack::kLocalWindowScaleShift)
maximum reassembly fragments:   128        (wirestack::kMaxReassemblyFragments)
```

The receive window is `[rcv_nxt, rcv_nxt + advertised_window)`, where the
*logical* `advertised_window = receive capacity - buffered out-of-order
bytes` (an accepted out-of-order FIN counts as one unit of that buffered
space). Wirestack's internal capacity (262140 bytes) is always the same
regardless of negotiation, but the wire-format 16-bit window field is
not: `advertisedWindowFor(connection, apply_scale)` produces `available
>> local_window_scale` when scaling is negotiated and `apply_scale` is
true, or `min(available, 65535)` otherwise (clamped either way to fit
16 bits). `apply_scale` is false for the SYN-ACK and its retransmissions
regardless of negotiation (window scaling never applies to the
handshake), and `connection.window_scaling_enabled` everywhere else (pure
ACK, data, FIN, and their retransmissions). The receive-acceptance
boundary itself always uses the *logical* window (`advertisedLogicalWindowFor`,
the wire value re-expanded through `expandLocalAdvertisedWindow` using
Wirestack's OWN `local_window_scale`) so Wirestack never accepts bytes
beyond what it actually advertised, even though its internal buffer is
larger than 65535 bytes. This is deliberately a separate helper from
`decodePeerWindow` above: reconstructing a window Wirestack itself
advertised must use `local_window_scale`, never the peer's
`peer_window_scale` -- the two shifts are independently negotiated and
can differ (e.g. a peer offering shift 14 while Wirestack's own shift
stays fixed at 2), so applying the wrong one would silently
over-advertise (or, worse, over-accept) by orders of magnitude. A
retransmitted
segment refreshes both its acknowledgment number and its window field
before checksum serialization, the same as the already-existing
acknowledgment-number refresh.

### Trimming and buffering

An incoming segment is left-trimmed to `max(rcv_nxt, segment.sequence_number)`
(already-delivered prefix discarded) and right-trimmed to the window's
right edge (bytes beyond it ignored); if nothing of the payload survives
and no FIN lies in the window, the segment is a pure duplicate/out-of-window
arrival -- nothing stored, nothing delivered, a duplicate ACK sent. The
surviving bytes are inserted into a bounded fragment list using
**first-arrival-wins**: bytes already buffered keep their original value,
and new input only fills previously-missing sequence positions -- this is
a deterministic, limited overlap policy for this milestone, not general
attack-resistant TCP normalization. Fragments are kept sorted and
coalesced whenever they become byte-adjacent, which keeps the steady-state
fragment count low; insertion is bounded by `kMaxReassemblyFragments`
independent of total buffered size (excess new fragments are simply
dropped, which can only shrink what's buffered, never overflow it).

### Release

After insertion, every fragment now contiguous with `rcv_nxt` is released
in order (this can span several previously-buffered fragments already
merged into one by coalescing), advancing `rcv_nxt` and handed to the
caller as one concatenated `accepted_payload` -- out-of-order bytes are
never exposed early. If a retained peer FIN's position has now been
reached, it is consumed (`rcv_nxt += 1`, `peer_closed` set exactly once,
the existing close-state transition applied) in the same call.

### Out-of-order FIN

A FIN is retained (not yet consumed) when it arrives before all
preceding bytes have -- but only in a state where the peer's FIN hasn't
already been consumed (`Established`, `FinWait1`, `FinWait2`); in every
other synchronized state a further FIN flag is necessarily a
retransmission of one already consumed, handled by the ordinary
duplicate-ACK path. The FIN's own sequence position must itself lie
within the receive window to be retained -- a FIN whose preceding
payload was right-edge-trimmed away is never retained, since its
position is already past the window's right edge. A duplicate retained
FIN does not re-signal EOF and does not change sequence state.

### Application layering

Wirestack's TCP layer has no knowledge of any application or close
policy -- `TcpReceiveResult::peer_closed` and `::accepted_payload` are
reported, not acted on, inside `tcp_connection.cpp`. `main.cpp` hands
both to the HTTP layer (see [docs/http.md](http.md)), which owns request
buffering, parsing, response selection, and deciding when to call
`beginClose`. TCP itself never parses HTTP and never decides when a
connection should close.

## Retransmission

### What is queued

Every outgoing segment that consumes TCP sequence space -- the SYN-ACK,
each `PSH|ACK` data segment `makeOutgoingData` emits (one queue entry per
MSS-bounded segment when a send is split), and a locally-initiated FIN --
is registered in a per-connection pending queue, in the order sent, each
entry owning its own copy of the payload bytes. Pure ACKs (generated
whenever a segment releases no new contiguous bytes) consume no sequence
space and are never queued or timed. This is the same queue used
regardless of whether a send produced one segment or several -- there is
no second retry mechanism for segmented data.

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
initial RTO:             1 second   (wirestack::kInitialRto -- before any RTT sample)
minimum RTO:              1 second  (wirestack::kMinRto)
maximum RTO:             60 seconds (wirestack::kMaxRto)
maximum retransmits:      5 (after the original, non-counted send)
```

Each connection carries an adaptive `current_rto`, seeded at
`kInitialRto` and revised by RTT samples (below); every *new* pending
transmission (SYN-ACK, a `makeOutgoingData` chunk, a locally-initiated
FIN) starts its own timeout at the connection's current `current_rto`,
not a fixed global constant. `PendingTransmission` records both
`first_sent_at` (set once, never touched by retransmission) and
`last_sent_at`/`timeout_interval` (updated on each timeout). A timeout
retransmission doubles that entry's own `timeout_interval` (capped at
`kMaxRto`) and also writes the backed-off value into the connection's
`current_rto`, so a later *new* send starts from the more conservative
estimate rather than resetting to the pre-loss value; an already-armed
entry's own deadline is not retroactively rewritten by a later RTT
sample.

### RTT measurement and the adaptive estimator

This is an RFC 6298-style estimator expressed in integer
`TcpClock::duration` arithmetic (no floating point) -- it is a deliberate
approximation of RFC 6298 for this educational stack, not a claim of
full compliance (no ambiguity-tracking beyond Karn's rule, no exponential
backoff of the *estimator* itself, no minimum-RTO tuning knob).

At most one RTT sample is taken per ACK, from the newest pending entry
that ACK fully or partially retires, provided that entry was sent exactly
once (`retransmit_count == 0`) and has a valid `first_sent_at <= now`
(Karn's rule: once any entry has been retransmitted, an ACK covering it
can never produce a sample, even the very next ACK). A pure ACK
(consumes no sequence space, never queued) and an accepted RST never
produce a sample, since neither retires a pending entry. A clean,
non-retransmitted SYN-ACK may provide the very first sample, sampled by
the handshake-completing final ACK.

```text
R = now - first_sent_at                         (the raw sample)
G = 1ms                                          (wirestack::kRtoGranularity)

first sample:
  SRTT   = R
  RTTVAR = R / 2
  RTO    = SRTT + max(G, 4 * RTTVAR)

subsequent sample (uses the OLD SRTT for the RTTVAR update, in this order):
  RTTVAR = (3 * RTTVAR + |SRTT - R|) / 4
  SRTT   = (7 * SRTT + R) / 8
  RTO    = SRTT + max(G, 4 * RTTVAR)

current_rto = clamp(RTO, kMinRto, kMaxRto)
```

Worked example (matches the deterministic tests): a first sample of
`R=200ms` gives `SRTT=200ms, RTTVAR=100ms`, raw `RTO=600ms`, clamped up
to the 1-second floor. A following sample of `R=1000ms` (using the old
200ms/100ms) gives `RTTVAR=275ms, SRTT=300ms, RTO=1400ms` (within
bounds, unclamped).

Negotiation and RTT/RTO state (`peer_mss`, `effective_send_mss`,
`peer_window_scale`, `local_window_scale`, `window_scaling_enabled`,
`has_rtt_sample`, `srtt`, `rttvar`, `current_rto`) are all per-`Connection`
fields -- two connections through the same `TcpConnectionTable` never
share or leak negotiated or timing state.

### Retransmitting

`pollRetransmissions(now)` returns every pending entry whose deadline
(`last_sent + rto`) has passed. A retransmission reuses the entry's
stored sequence start, flags, and (already-trimmed) payload; for data,
the acknowledgment field is refreshed to the connection's *current*
`rcv_nxt` (the client may have sent more data since the original send).
It never advances `snd_nxt` or `snd_una`, and never re-delivers
application data to the layer above TCP -- a retransmission is not a new
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
curl --http1.0 -v http://10.0.0.2:8080/
```

Expected in tcpdump: `Flags [S]` from the client, `Flags [S.]` from
Wirestack, `Flags [.]` from the client -- a complete three-way handshake
-- followed by the client's GET request, Wirestack's `Flags [P.]`
carrying the HTTP response, Wirestack's own `Flags [F.]`, and the
client's final ACK/FIN exchange. See [docs/http.md](http.md) for the
exact expected response bytes and additional HTTP-level test cases
(`/missing`, `--http1.1`). To exercise reset generation, connect to an
unbound port instead:

```bash
nc 10.0.0.2 8081
```

Expect a `Flags [S]` from the client immediately followed by `Flags [R.]`
from Wirestack; `nc` should report the connection refused/reset.

To exercise incoming segmentation, send a request whose header block is
large enough to span multiple TCP segments but still under the 8192-byte
HTTP limit, e.g. a request with an oversized (but ignored) header:

```bash
python3 -c "
import socket
req = b'GET / HTTP/1.0\r\nX-Pad: ' + b'a' * 3000 + b'\r\n\r\n'
s = socket.create_connection(('10.0.0.2', 8080))
s.sendall(req)
print(s.recv(4096))
"
```

Expect tcpdump to show multiple client data segments (each up to 1460
bytes), Wirestack's cumulative ACKs advancing across them, and the exact
`Hello from Wirestack` response once the full request has been
reassembled. Do not apply loss injection or reordering (`tc netem`,
network namespaces) against a shared or production interface -- only a
dedicated, isolated TAP device with no other traffic, removing any such
change afterward.

## Known limitations

- Only MSS and Window Scale options are understood; SACK-permitted and
  timestamps are safely skipped like any other unknown well-formed
  option, never interpreted or acted on.
- No fast retransmit (duplicate-ACK triggered) -- only timeout triggers
  retransmission.
- No congestion control, no slow start, no fast recovery.
- No active open (Wirestack never initiates a connection).
- No challenge ACK; an unacceptable RST is simply dropped.
- The RTT/RTO estimator is an integer-arithmetic approximation of
  RFC 6298 (Karn's rule, SRTT/RTTVAR/RTO, 1s/60s bounds), not a claim of
  full RFC 6298 compliance.
- No zero-window persist timer or probe -- Wirestack waits for the peer
  to advertise room; a rejected send must be retried by the caller.
- No application-level send queue -- an atomic send is either fully
  accepted or fully rejected, never partially buffered internally.
- Overlap/duplicate handling is a deterministic first-arrival-wins policy
  bounded to a 262140-byte internal capacity and 128 fragments, not
  general attack-resistant TCP normalization; the wire-visible advertised
  window still never exceeds 65535 unless Window Scale was negotiated.
- Single application on port 8080 (the HTTP/1.0 demonstration, see
  [docs/http.md](http.md)); no general application registration.

## Next TCP work

TCP slow start, congestion avoidance, duplicate-ACK fast retransmit, and
fast recovery.
