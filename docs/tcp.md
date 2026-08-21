# TCP

## Current support

Passive three-way handshake with SYN-carried MSS/Window Scale option
negotiation, a bounded per-connection application send buffer with
ACK/window-update-driven scheduling into MSS-bounded outgoing
segmentation within the peer's advertised (and, when negotiated, scaled)
send window and a Reno-style congestion window, bounded out-of-order
receive reassembly with duplicate/overlap trimming, RTT measurement with
an adaptive SRTT/RTTVAR/RTO estimator driving timeout-based
retransmission of SYN-ACK/data/FIN, duplicate-ACK fast retransmit,
NewReno-style partial-ACK recovery, and a bounded segment-granular SACK
scoreboard (SACK-Permitted negotiated only from the peer's SYN -- see
"Selective acknowledgment (SACK) and NewReno recovery"), a deterministic
zero-window persist probe, passive/active/simultaneous close (with FIN
deferred until all queued application bytes enter sequence space) and a
deterministic TIME_WAIT, and acceptable-inbound-RST/closed-port-RST
handling, over IPv4, on a single fixed listening port (8080). No active
open, no DSACK, no SACK reneging recovery beyond clearing marks on RTO,
no RFC 6675 pipe algorithm, no CUBIC/BBR, no ECN, no timestamps. Port
8080 hosts the minimal HTTP/1.0 demonstration described in
[docs/http.md](http.md), not a raw byte echo -- this file covers only
TCP itself.

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
window_scale, sack_permitted, sack_blocks}` (the first two
`std::optional`) or a `TcpOptionParseError`. A single left-to-right
cursor scan: kind 0 (End of List) stops parsing immediately; kind 1
(No-Operation) advances one byte; every other kind requires a length byte
(`MissingLength` if absent), `length >= 2` (`InvalidLength`), and enough
remaining bytes for the declared length (`TruncatedOption`) before it is
read. Kind 2 (MSS) requires `length == 4` and a nonzero 16-bit value
(`InvalidMss` otherwise); kind 3 (Window Scale) requires `length == 3`;
kind 4 (SACK-Permitted) requires `length == 2`
(`InvalidSackPermittedLength` otherwise); kind 5 (SACK) requires `length`
in `{10, 18, 26, 34}` (`InvalidSackLength` otherwise) and decodes
`(length - 2) / 8` `TcpSackBlock{left_edge, right_edge}` pairs. A second
occurrence of any of the four is `DuplicateMss`/`DuplicateWindowScale`/
`DuplicateSackPermitted`/`DuplicateSack`. Any other well-formed kind is
safely skipped using its own declared length without being interpreted.
No index ever advances past `options.size()`. See "Selective
acknowledgment (SACK) and NewReno recovery" for SACK negotiation and
established-state SACK block handling; the negotiation description
below covers only MSS and Window Scale, unchanged from before this
milestone.

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
never the peer's offered value: `02 04 05 b4`, followed by SACK-Permitted
and/or Window Scale when negotiated -- see "SYN-ACK option layout" under
"Selective acknowledgment (SACK) and NewReno recovery" for the exact
byte layout of all four combinations. Neither the SYN-ACK's own window
field, nor a retransmission of it, is ever scaled -- window scaling
first applies starting with the handshake's own completing ACK.

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
4. An ACK with the wrong acknowledgment number against an existing
   `SynReceived` connection is silently dropped -- no RST, no ICMP. Any
   other traffic for a port other than 8080, or against no matching
   connection on 8080, gets a closed-port reset instead -- see "Closed-port
   RST" below.

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

The scheduler (see "Send buffering and scheduling" below) segments
queued bytes into `effective_send_mss`-bounded chunks, where
`effective_send_mss = min(kTcpMss, peer_mss)` was fixed at handshake
time (see "TCP options" above) -- so a peer that omits an MSS option or
advertises less than 1460 gets correspondingly smaller outgoing
segments, while a peer advertising more than 1460 never causes Wirestack
to exceed its own path MSS. `kMaxSegmentsPerSend` (128) bounds each
individual scheduling pass rather than the whole enqueue: with a tiny
negotiated peer MSS and a large window/congestion allowance, one ACK's
scheduling pass emits at most 128 segments, and any remainder is simply
scheduled by a later ACK/window update.

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
rwnd_available = flight_size >= snd_wnd ? 0 : snd_wnd - flight_size
cwnd_available = flight_size >= cwnd    ? 0 : cwnd - flight_size
send_available = min(rwnd_available, cwnd_available)
```

An application send of `N` bytes (`makeOutgoingData`, capped at
`kMaxApplicationSendSize` = 65535 bytes regardless of window, a single
enqueue call's own bound) is enqueued atomically regardless of
`send_available` (see "Send buffering and scheduling" below); only
`send_available` bytes of it are scheduled onto the wire immediately, and
the rest waits in the send buffer's unsent queue for a later ACK/window
update. A local FIN requires `rwnd_available >= 1` only -- see
"Congestion control" below for why FIN is not additionally gated by
`cwnd`. A zero window (either one) blocks scheduling new payload bytes
but does not block anything else: ACK and RST processing continue
normally, and already-outstanding (unacknowledged) segments still
retransmit -- whether by timeout or by duplicate-ACK fast retransmit --
regardless of either available value, since a retransmission is not new
data and consumes no additional allowance. When the peer window is
genuinely zero, unsent data is queued, and nothing is outstanding, a
narrow zero-window persist probe eventually fires -- see "Zero-window
persist" below for the exact scope; outstanding data under a zero window
still just waits on ordinary retransmission timing, not persist.

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
`kMaxRto`) and folds the backed-off value into the connection's
`current_rto` via `current_rto = max(current_rto, timeout_interval)` --
never a direct assignment -- so a later *new* send starts from the more
conservative estimate rather than resetting to the pre-loss value, and a
second, younger, still-outstanding entry timing out on its own smaller
per-entry interval can never pull the connection-level estimate back
down below what an earlier entry's timeout had already established. An
already-armed entry's own deadline is not retroactively rewritten by a
later RTT sample.

### RTT measurement and the adaptive estimator

This is an RFC 6298-style estimator expressed in integer
`TcpClock::duration` arithmetic (no floating point) -- it is a deliberate
approximation of RFC 6298 for this educational stack, not a claim of
full compliance (no ambiguity-tracking beyond Karn's rule, no exponential
backoff of the *estimator* itself, no minimum-RTO tuning knob).

At most one RTT sample is taken per ACK, from the newest pending entry
that ACK fully or partially retires, provided that entry was sent exactly
once (`!PendingTransmission::was_retransmitted`), has a valid
`first_sent_at <= now`, and has not already contributed a sample
(`PendingTransmission::rtt_sample_taken`) -- distinct from Karn
eligibility: a partial ACK can sample a still-outstanding entry once,
after which a later ACK of that same entry's remaining bytes is not
eligible again, even though it was never retransmitted. Karn's rule:
once any entry has been retransmitted -- by *either* a timeout or a
duplicate-ACK fast retransmit, see "Congestion control" below -- an ACK
covering it can never produce a sample, even the very next ACK. A pure
ACK (consumes no sequence space, never queued) and an accepted RST never
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
timeout-retransmission budget.

A pending entry now tracks two distinct facts about being retransmitted,
kept deliberately separate (see "Congestion control" below): timeout
retries (`PendingTransmission::timeout_retransmit_count`, incremented
only by an actual RTO expiry here) and Karn ambiguity
(`PendingTransmission::was_retransmitted`, set by *either* a timeout or
a duplicate-ACK fast retransmit). A fast retransmission is never encoded
as a fake timeout -- it never touches `timeout_retransmit_count`, never
doubles `timeout_interval`, and never changes `connection.current_rto`.

### Timeout exhaustion

Once a pending entry's `timeout_retransmit_count` has already reached 5
(a fast retransmission never contributes to this count), its next
expired deadline removes the connection from the table entirely and
reports it to the caller -- no FIN, no RST, just a local abort. This is
intentionally not a graceful close.

### Delayed-reply addressing

TCP connection state stores no MAC addresses. A timer-triggered
(timeout) retransmission has no current received frame to read a
destination MAC from, so `main.cpp` looks it up in the existing
`ArpCache`, which now learns IP->MAC mappings from any valid local IPv4
traffic (not just ARP packets) so a mapping is available even if the
peer's last ARP exchange has aged out of relevance. If no mapping is
known, the retransmission attempt is skipped (logged) but still counts
toward the 5-retry budget -- otherwise a persistently-unreachable peer
would retry forever. A duplicate-ACK-triggered fast retransmission (see
"Congestion control" below) is different: it is produced synchronously
while handling a just-received frame, so `main.cpp` addresses it using
that frame's own source MAC directly, through the same immediate-reply
path as an ordinary SYN-ACK or pure ACK -- it never goes through the
ArpCache/timer path and is not subject to this failure mode.

## Congestion control

An educational Reno-style model: Slow Start, Congestion Avoidance,
duplicate-ACK fast retransmit, and classic fast recovery. Explicitly not
implemented: NewReno partial-ACK recovery, SACK, PRR, CUBIC, BBR, ECN,
limited transmit, congestion-window validation after idle, ACK pacing.
This is a deliberate approximation for this educational stack, not a
claim of full or RFC-compliant Reno.

### State

Per connection, byte units except `recovery_point` (a sequence number):

```text
cwnd                             congestion window
ssthresh                         slow-start threshold
duplicate_ack_count              consecutive qualifying duplicate ACKs
in_fast_recovery                 true from the 3rd duplicate ACK until an advancing ACK
recovery_point                   snd_nxt when fast recovery began (diagnostic only after exit)
congestion_avoidance_acked_bytes accumulator for Congestion Avoidance growth
```

All six are exposed read-only through `TcpConnectionSnapshot` and are
fully independent per connection -- there is no global congestion state.

### Initial window and threshold

Computed once, right after `effective_send_mss` is fixed at connection
creation (see "TCP options" above) -- SYN and SYN-ACK are never gated by
`cwnd`:

```text
SMSS = effective_send_mss
initial_cwnd = min(10 * SMSS, max(2 * SMSS, 14600))    (wirestack::kInitialCongestionWindowFloor = 14600)
initial ssthresh = 65535                                (wirestack::kInitialSsthresh)
```

`initial_cwnd` examples: SMSS 1460 -> 14600; SMSS 1200 -> 12000; SMSS 536
-> 5360; SMSS 1 -> 10. The initial threshold is a fixed, deterministic
project policy -- not derived from the peer's initial window, and not a
claim about every production TCP's default. All arithmetic uses `uint64_t`
intermediates before clamping to `wirestack::kMaxCongestionWindow` (`1 <<
30` bytes, chosen to stay well under half the 32-bit sequence space) so
no growth step can overflow `uint32_t`.

### New-data send limit

Scheduling queued bytes onto the wire is gated by both the peer window
and the congestion window (see "Send window" above for the exact
`send_available` formula); enqueue itself is gated only by send-buffer
capacity, not by either window (see "Send buffering and scheduling"
below). A FIN is gated by the peer window only, not by `cwnd` -- a
narrow, documented choice for this milestone rather than a claim that
FIN should never interact with congestion control. Congestion-window
growth counts only application-data bytes: acknowledging a SYN, a FIN,
or a pure ACK never grows `cwnd`.

### ACK retirement's byte accounting

`retireAcknowledged` returns a small `TcpAckRetirementResult`
(`newly_acked_sequence_space`, `newly_acked_data_bytes`, `ack_advanced`,
`rtt_sample_taken`) so congestion control can size growth without a
second pass over the pending queue. `newly_acked_sequence_space` is
simply `ack - old snd_una` (wraparound-safe, matches the rest of
sequence-space tracking); `newly_acked_data_bytes` is accumulated per
retired/trimmed entry and excludes a SYN or FIN's own control byte (SYN
and FIN both occupy a 1-wide range that can never be partially
acknowledged, so the partial-trim path only ever trims data). A
duplicate or stale ACK reports an all-zero, `ack_advanced=false` result.

### Slow Start and Congestion Avoidance

Chosen once per advancing ACK, outside fast recovery, based on `cwnd`
before that ACK's growth is applied -- never both rules for the same
acknowledged bytes:

```text
Slow Start (cwnd < ssthresh):
  cwnd += min(newly_acked_data_bytes, SMSS)

Congestion Avoidance (cwnd >= ssthresh):
  congestion_avoidance_acked_bytes += newly_acked_data_bytes
  while congestion_avoidance_acked_bytes >= cwnd:
      congestion_avoidance_acked_bytes -= cwnd
      cwnd += SMSS
```

The `while` loop (not a single `if`) safely handles a cumulative ACK that
crosses more than one window's worth of accumulated credit; in practice,
because every legitimate send is itself gated by the then-current `cwnd`,
one ACK can newly-acknowledge at most one window's worth of *new* data
under ordinary operation, so more than one loop iteration is only
reachable when stale, still-outstanding data (e.g. from before a timeout
shrank `cwnd`) is acknowledged. Worked vector (SMSS 1460): initial
`cwnd=14600`; ACK one full segment -> `16060`; ACK another -> `17520`.
`congestion_avoidance_acked_bytes` is reset to 0 whenever a loss event
(fast recovery entry, fast-recovery exit, or timeout collapse) makes
prior accumulated credit invalid.

### Duplicate-ACK definition

An ACK counts as a qualifying duplicate only when *all* of the following
hold: the connection is synchronized; ACK is set; the ACK number equals
`snd_una` exactly (excludes both a stale ACK below it and an advancing
one); the segment carries no payload; SYN, FIN, and RST are all clear;
the advertised peer window is unchanged from what is currently stored
(compared before vs. after `updateSendWindow` runs); and at least one
outstanding pending entry is application data (never SYN- or FIN-only --
an ACK for an outstanding FIN with no outstanding data does not count).
`duplicate_ack_count` resets to 0 whenever the ACK advances `snd_una`,
whenever the peer window changes, or on a timeout loss; it is left
unchanged by a non-qualifying ACK that is neither of those (a stale ACK,
a data-carrying ACK, or a FIN|ACK), since none of those are reset
triggers on their own.

### Third duplicate ACK: fast retransmit and fast recovery entry

```text
flight = snd_nxt - snd_una
ssthresh = max(flight / 2, 2 * SMSS)
recovery_point = snd_nxt
cwnd = ssthresh + 3 * SMSS
in_fast_recovery = true
congestion_avoidance_acked_bytes = 0
```

Then the oldest outstanding application-data pending entry (never SYN or
FIN) is retransmitted immediately: sequence number and (already-trimmed)
payload preserved, acknowledgment number and advertised window refreshed
exactly like an ordinary retransmission, `TcpSegment::flags` reused from
the original send. This is reported through
`TcpReceiveResult::fast_retransmit` -- a field distinct from `reply`,
sent by `main.cpp` through the same immediate-reply path used for a
SYN-ACK or pure ACK, addressed with the *current* received frame's
source MAC (not the timer/ArpCache path -- see "Delayed-reply
addressing"). The entry's `was_retransmitted` is set (Karn ambiguity,
see "RTT measurement" above) and `last_sent_at` is reset to `now`, but
its `timeout_interval` is left untouched (not doubled),
`connection.current_rto` is untouched, `first_sent_at` is untouched, and
`timeout_retransmit_count` is untouched -- a fast retransmission is never
encoded as a fake timeout.

### Additional duplicate ACKs and recovery exit

Every further qualifying duplicate ACK while already in fast recovery
inflates the window (`cwnd += SMSS`, clamped). Without SACK negotiated,
this never triggers another retransmission -- one loss indication
produces exactly one fast retransmission, and NewReno partial-ACK
recovery (below) is what retransmits further losses. With SACK
negotiated, this same duplicate ACK may *also* select one further
eligible retransmission (see "SACK-guided additional duplicate ACKs"
below) -- still at most one retransmission per incoming ACK.

Recovery exits only once the cumulative ACK reaches `recovery_point`
(full ACK, using the project's wraparound-safe sequence comparison):

```text
cwnd = ssthresh
duplicate_ack_count = 0
in_fast_recovery = false
congestion_avoidance_acked_bytes = 0
```

with no additional Slow Start or Congestion Avoidance growth applied to
that same ACK, and every pending entry's `retransmitted_in_recovery`
marker cleared (the episode is over). An advancing ACK that stops short
of `recovery_point` is a NewReno partial ACK instead -- see "NewReno
partial-ACK recovery" below.

### Timeout congestion response

When an established application-data segment (never a SYN-ACK or FIN)
reaches its RTO, once per timeout event, before the existing
retransmission and RTO backoff:

```text
flight = snd_nxt - snd_una
ssthresh = max(flight / 2, 2 * SMSS)
cwnd = SMSS
duplicate_ack_count = 0
in_fast_recovery = false
congestion_avoidance_acked_bytes = 0
```

A SYN-ACK or FIN timeout preserves existing retransmission/backoff
behavior unchanged, without applying this collapse. A repeated
`pollRetransmissions` call at the same timestamp cannot collapse twice:
the entry's `last_sent_at` is set to that timestamp as part of the same
timeout event, so its deadline cannot be due again until strictly later.

### Testing limitation

`kMaxCongestionWindow` (`1 << 30`) is not organically reachable through
the public send/ack API within a practical deterministic test -- reaching
it requires on the order of 700,000 SMSS-sized growth steps. The
deterministic tests instead verify the exact formulas, the boundary
between Slow Start and Congestion Avoidance, and that ordinary growth
never regresses, relying on the `uint64_t`-then-clamp arithmetic
(exercised directly by the initial-window and fast-recovery-entry
formulas) to rule out overflow rather than literally driving `cwnd` to
the bound.

## Selective acknowledgment (SACK) and NewReno recovery

Wirestack implements NewReno-style partial-ACK recovery with a bounded,
segment-granular SACK scoreboard -- not full RFC 2018 SACK, not RFC 6675
pipe-based loss recovery, not PRR, not Limited Transmit, no DSACK, no
SACK reneging recovery beyond clearing marks on RTO.

### Negotiation

SACK is negotiated only from the peer's initial SYN, decided once and
never touched again -- the same one-time-SYN-only pattern as MSS and
Window Scale. `parseTcpOptions` additionally recognizes kind 4
(SACK-Permitted, `length == 2`, otherwise `InvalidSackPermittedLength`; a
second occurrence is `DuplicateSackPermitted`) and kind 5 (SACK,
`length` one of `{10, 18, 26, 34}` for 1-4 blocks, otherwise
`InvalidSackLength`; a second occurrence is `DuplicateSack`), returning
`TcpParsedOptions{..., sack_permitted, sack_blocks}` (`sack_blocks` holds
`TcpSackBlock{left_edge, right_edge}` pairs, `[left_edge, right_edge)`,
at most 4). A SYN carrying a SACK block option is invalid for this
milestone (SACK is only meaningful once a connection has outstanding
data) and creates no connection, exactly like any other malformed SYN. A
later SACK-Permitted option (on a duplicate SYN or any established-state
segment) is parsed but never renegotiates -- `connection.sack_permitted`
is set exactly once, at connection creation.

### SYN-ACK option layout

Fixed order: MSS, SACK-Permitted (only if negotiated), Window Scale
(only if negotiated), then EOL + zero padding to a 4-byte boundary.
`buildSynAckOptions` builds the unpadded bytes and pads generically,
which happens to produce these exact four combinations:

```text
MSS only:                      02 04 05 b4                                     (24-byte header, DO 6)
MSS + Window Scale:            02 04 05 b4 01 03 03 02                         (28-byte header, DO 7)
MSS + SACK-Permitted:          02 04 05 b4 04 02 00 00                         (28-byte header, DO 7)
MSS + SACK-Permitted + WScale: 02 04 05 b4 04 02 01 03 03 02 00 00             (32-byte header, DO 8)
```

A timeout or duplicate-SYN retransmission of the SYN-ACK rebuilds these
same bytes from stored connection state (`buildSynAckOptions` is called
again, not a cached copy) -- MSS, Window Scale, and SACK-Permitted are
therefore always preserved exactly, in the same order, with the same
padding, across any number of retransmissions.

### Receiver SACK block generation

When SACK was negotiated and `connection.out_of_order` is non-empty,
`generateSackBlocks` builds at most 4 blocks, one per retained fragment,
with exact edges (`fragment.sequence_start`, `fragment.sequenceEnd()`) --
never a gap, never bytes already below `rcv_nxt`, never a pending FIN's
sequence space (FIN is tracked separately from `out_of_order` and never
contributes a block), never bytes trimmed outside the receive window or
rejected by the fragment/capacity bounds that already apply to ordinary
reassembly (see "Receive windows and reassembly").

Ordering policy: the fragment associated with the most recently accepted
out-of-order range occupies the first block position, if that fragment
still exists after this call's insert/coalesce (`handleSynchronized`
locates it by scanning `out_of_order` for the fragment now containing the
just-inserted range -- absent if that range was released into `rcv_nxt`
instead, which correctly drops it from the report). The remaining
fragments fill in descending `sequence_start` order. This is a
deterministic, easy-to-verify policy, not a claim of matching any
particular real TCP's exact heuristic. Duplicate/overlapping arrivals
never produce duplicate blocks, because they never produce duplicate
fragments (see "Trimming and buffering" -- first-arrival-wins already
guarantees a canonical fragment set).

### Pure-ACK-only emission policy

SACK blocks are emitted only on `makePureAck`'s output, via
`buildSackOptions(generateSackBlocks(...))`. Never on application-data
segments, FIN segments, timeout retransmissions, or fast/NewReno
recovery retransmissions -- so MSS-bounded data-segment sizing and
retransmission payload boundaries are completely unaffected by SACK.
`buildSackOptions` writes kind 5, `length = 2 + 8*N`, the N block pairs
in network byte order, then EOL + zero padding to a 4-byte boundary --
1/2/3/4 blocks give exactly 12/20/28/36 option bytes (32/40/48/56-byte
TCP headers, Data Offset 8/10/12/14).

`handleSynchronized` previously suppressed a pure ACK whenever scheduled
data or a released payload's own reply already carried a valid ACK
(avoiding a redundant reply). That rule now has one exception: when SACK
is negotiated and out-of-order data is still held, the pure ACK is sent
*in addition* to scheduled data / a released-payload reply, because it
carries SACK information neither of those carries. An ordinary ACK-only
input with nothing to report still gets no reply (no ACK-loop risk
introduced).

### Sender scoreboard: segment-granular, not sub-segment

The existing bounded `pending` entries double as the sender's SACK
scoreboard -- no separate range collection. Two new per-entry fields,
meaningless (always `false`) when `!sack_permitted`:

- `sacked`: set once the entry's *entire* current unacknowledged range is
  covered by the normalized union of valid SACK blocks. Never unset
  except by RTO (clears the whole scoreboard) or by the entry being
  retired by a later cumulative ACK. A block covering only part of an
  entry does **not** mark it `sacked` -- this milestone uses
  pending-segment granularity, not arbitrary sub-ranges, so a partially
  SACKed segment may be retransmitted in full later. This is a
  deliberate, documented limitation, not an oversight.
- `retransmitted_in_recovery`: set by any recovery retransmission of this
  entry (duplicate-ACK-3, an additional SACK-guided duplicate ACK, or a
  NewReno partial ACK), reset at the start of each fresh fast-recovery
  episode (entry into recovery on duplicate ACK 3) and by RTO. Prevents
  selecting the same entry twice within one recovery episode.

`applySackBlocks(connection, cumulative_ack, blocks)` runs on every valid
ACK on a negotiated connection (advancing or not), after
`retireAcknowledged`. A block is semantically usable only if
`left_edge` is strictly after `cumulative_ack`, `right_edge` is strictly
after `left_edge`, and `right_edge` is at or before `snd_nxt` (using the
project's wraparound-safe sequence comparisons) -- this excludes empty
blocks, reversed blocks, DSACK-style blocks at/below the cumulative ACK,
and blocks spanning unsent sequence space. An individually unusable
block is simply dropped; it never invalidates the ACK's normal cumulative
processing. The usable blocks are then sorted and merged (overlapping or
touching blocks combined) before being checked against each pending
entry, so repeated or overlapping reports are idempotent.

`selectRecoveryRetransmission` -- shared by duplicate-ACK-3 entry,
SACK-guided additional duplicate ACKs, and NewReno partial-ACK
retransmission -- returns the oldest pending data entry (never SYN/FIN)
that starts before `recovery_point`, is not `sacked`, and has not already
been `retransmitted_in_recovery`, or `nullptr` if none qualifies (every
outstanding entry already SACKed -- recovery state still changes, just
no retransmission is emitted).

### Cumulative ACK authority

SACK information never performs any of the operations only the
cumulative ACK field performs: it does not advance `snd_una`, does not
remove a pending entry, does not trim pending payload, does not release
application send-buffer capacity, does not grow `cwnd`, does not update
`ssthresh`, and does not take an RTT sample. A later cumulative ACK may
retire an entry that was previously marked `sacked` -- that retirement
releases capacity exactly once, through the ordinary `retireAcknowledged`
path, identically to an entry that was never SACKed at all.

### RTT sampling and Karn's rule

`retireAcknowledged`'s existing eligibility rule (`!was_retransmitted &&
!rtt_sample_taken`) already excludes a SACKed-then-retransmitted entry
for free, since any recovery retransmission sets `was_retransmitted`. No
RTT sample is ever taken from the arrival of a SACK block itself -- only
from an entry's eventual cumulative-ACK retirement, same as before this
milestone.

### NewReno partial-ACK recovery

While in fast recovery, an advancing ACK below `recovery_point` (a
NewReno partial ACK, RFC 6582-style approximation) does not exit
recovery. Instead:

```text
deflated = max(cwnd - newly_acked_sequence_space, SMSS)
if newly_acked_sequence_space >= SMSS:
    deflated += SMSS
cwnd = clamp(deflated)
```

computed in a wide (`uint64_t`) intermediate to avoid underflow before
the `max`. `duplicate_ack_count` resets to 0 (same as any advancing ACK),
`in_fast_recovery` stays `true`, and one further eligible retransmission
is selected via `selectRecoveryRetransmission` and sent through
`fast_retransmit` -- at most one per ACK, same field and same
addressing/scheduling precedence as the duplicate-ACK-3 case. Ordinary
Slow Start / Congestion Avoidance growth is not applied to this same ACK.
This behavior is identical whether or not SACK was negotiated: without
SACK, no entry is ever marked `sacked`, so `selectRecoveryRetransmission`
degenerates to "the oldest entry not yet retransmitted this episode" --
standard NewReno head-of-line retransmission.

### SACK-guided additional duplicate ACKs

An additional qualifying duplicate ACK while already in fast recovery
still inflates `cwnd += SMSS`. When SACK is negotiated, it may *also*
select one further eligible retransmission the same way a partial ACK
does (skipping entries already `sacked` or already
`retransmitted_in_recovery`, bounded to `sequence_start < recovery_point`)
-- still at most one retransmission per incoming ACK.
`applySackBlocks` runs before this selection, so a SACK report riding
the same duplicate ACK that triggers this path is already reflected in
which entries are skipped. Without SACK negotiated, additional duplicate
ACKs never retransmit (existing classic-Reno behavior) -- only a partial
ACK does. This is still not RFC 6675 pipe-estimation-based recovery.

### RTO scoreboard reset

`applyTimeoutCongestionCollapse` additionally clears every pending
entry's `sacked` and `retransmitted_in_recovery` on every RTO of an
application-data segment -- the safe fallback if the peer reneged on a
prior SACK report (SACK reneging recovery beyond this is not
implemented; timeout simply clears the whole segment-granular
scoreboard and falls back to ordinary timeout retransmission). RST
removal and timeout exhaustion both erase the connection (and therefore
its scoreboard) entirely, same as before this milestone.

## Send buffering and scheduling

A bounded, owned, per-connection application send buffer, replacing the
previous atomic-only `makeOutgoingData` (which either fully segmented a
payload immediately or rejected it outright for window/congestion
reasons). There is exactly one send implementation now: enqueue, then
schedule -- `makeOutgoingData` is a thin wrapper over it, and it is also
the entry point ACK-driven scheduling and persist recovery use.

### Capacity

```text
send-buffer capacity: 262144 bytes  (wirestack::kTcpSendBufferCapacity, 256 * 1024)
```

Charged bytes = `unsent.size()` (FIFO backlog not yet in sequence space)
plus the payload size of every non-SYN/FIN pending transmission
(application bytes already in sequence space but not yet acknowledged).
Moving bytes from `unsent` into a pending entry during scheduling does
not change this total -- it is never double-counted, and a retransmission
(timeout or fast) reuses the same pending entry's payload rather than
creating a new one, so it never counts twice either. Capacity is
released only when application bytes are cumulatively or partially
acknowledged (see "Retransmission" above for the underlying trim logic)
or the connection is removed.

### Enqueue

`makeOutgoingData` enqueues atomically: the capacity check happens before
any bytes are copied, and on any rejection (unknown connection; not
Established/CloseWait; close already requested; empty payload; a single
call exceeding `kMaxApplicationSendSize`; or exceeding the buffer's
remaining capacity, `TcpSendError::BufferFull`) no bytes are queued and
no connection state changes. On acceptance, bytes from separate enqueue
calls remain strictly FIFO-ordered, and the scheduler may coalesce
adjacent bytes from different calls into one MSS-sized segment --
application call boundaries have no wire-format meaning.

### Scheduler

Every enqueue and every valid ACK-bearing segment (see "ACK-driven
scheduling" below) attempts to convert queued bytes into segments:

```text
flight          = snd_nxt - snd_una
rwnd_available  = flight >= snd_wnd ? 0 : snd_wnd - flight
cwnd_available  = flight >= cwnd    ? 0 : cwnd - flight
send_available  = min(rwnd_available, cwnd_available)
to_send         = min(send_available, unsent.size(), kMaxSegmentsPerSend * effective_send_mss)
```

The `kMaxSegmentsPerSend * effective_send_mss` term bounds one
scheduling pass to at most `kMaxSegmentsPerSend` (128) segments
regardless of how large `cwnd`/`snd_wnd` have grown -- relevant only
with a tiny negotiated peer MSS; any remainder is simply scheduled by a
later ACK/window update. Each emitted segment gets
`sequence_number = snd_nxt` for that chunk, `acknowledgment_number =
rcv_nxt`, `ACK` set, the current advertised receive window, and the next
FIFO bytes; `PSH` is set only on the segment that drains `unsent`
completely for this pass -- not merely because this pass's allowance was
exhausted while more application data remains queued. One pending
transmission is registered per emitted segment; `snd_nxt` advances by
exactly the emitted total; nothing is emitted (not an error) when no
allowance exists. Once `unsent` is empty, the same pass attempts to
sequence a deferred FIN (see "Connection close" below).

### ACK-driven scheduling

After validating an ACK (existing retirement, RTT, and Reno-growth
processing -- see "Retransmission" and "Congestion control" above,
unchanged), the connection is rescheduled immediately if it remains in
Established/CloseWait and is not about to be removed. The resulting
segments are returned via `TcpReceiveResult::scheduled`, in ascending
sequence order, alongside a possible `fast_retransmit`; `main.cpp` sends
both through the current received frame's immediate-reply path. A
scheduled segment already carries a valid ACK, so `handle()` clears
`reply` whenever `scheduled` is non-empty rather than also emitting a
redundant pure ACK. No application call or timer tick is required for an
advancing ACK (or a fresh window update with `snd_wnd: 0 -> positive`,
validated by the existing SND.WL1/WL2 freshness test) to release queued
bytes -- malformed segments, a bad checksum, a future ACK, a stale ACK,
an unacceptable window update, an invalid RST, and connection removal
all continue to schedule nothing, matching their existing rejection
paths.

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

`TcpConnectionTable::beginClose(key, now)` returns a `TcpCloseResult`
(`accepted`, `fin`). It records close intent (`accepted = true`,
idempotent -- a repeated call while still pending is a harmless no-op)
only from Established or CloseWait; every other state (already closing,
reset, unknown) leaves `accepted = false` and changes nothing. Once
accepted, no further `makeOutgoingData` calls are accepted for this
connection (`NotSendable`). The FIN itself (`sequence_number = snd_nxt`,
`acknowledgment_number = rcv_nxt`, no payload, `Established -> FinWait1`
or `CloseWait -> LastAck`) is sequenced only once the send buffer's
`unsent` queue is empty and at least one byte of peer send window is
available -- never gated by `cwnd`, matching every other FIN
requirement. If bytes are still queued or the window is exhausted,
`beginClose` returns `fin = nullopt`: the close intent is retained, and
the same scheduling pass that eventually drains `unsent` (see "Send
buffering and scheduling" above -- triggered by a later ACK/window
update, not a second `beginClose` call) sequences the FIN automatically,
guaranteeing it never precedes unsent application bytes in sequence
space. Once sequenced, it is queued through the same `PendingTransmission`
mechanism as before (retransmitted, ACK-retired, backed off) exactly
once -- repeated scheduling passes never create a second FIN, since
`local_fin_seq` is checked first. The peer's ACK of the local FIN moves
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

## Zero-window persist

A narrow, deterministic persist mechanism, deliberately scoped to a
single case: probing a genuinely zero peer window when nothing is
already outstanding. It does not probe while data remains outstanding
under a zero window -- that continues to use the ordinary retransmission
timer described above, unchanged; the two timers never compete for the
same connection.

### Eligibility

Persist is armed only when *all* of the following hold, and cancelled
(deadline cleared) the instant any stops holding:

```text
connection is Established or CloseWait
unsent application bytes exist (the send buffer's unsent queue is non-empty)
peer send window snd_wnd == 0
snd_nxt == snd_una (no sequence space outstanding)
no FIN has been sequenced yet
```

`snd_nxt == snd_una` is what separates this from ordinary retransmission:
a zero window with outstanding data is not persist-eligible, and stays
on the existing retransmission timer. Persist does not arm merely
because `cwnd` is full, a *nonzero* peer window is fully consumed, only
a deferred FIN remains, there is no unsent data, or the connection is
outside Established/CloseWait.

`updatePersistState` re-evaluates eligibility after every operation that
can change it (enqueue, ACK/window-update processing, scheduling): if
newly eligible it arms at the initial interval; if no longer eligible it
clears the deadline; if already armed, it leaves the deadline/backoff
untouched -- a zero-window ACK that changes nothing, or a fresh enqueue
while already armed, must not reset the backoff back to the 1-second
floor.

### Backoff

```text
initial interval: 1 second   (wirestack::kInitialPersistInterval)
maximum interval: 60 seconds (wirestack::kMaxPersistInterval)
backoff:          x2, capped, no retry exhaustion
```

Sequence: 1s, 2s, 4s, 8s, 16s, 32s, 60s, 60s, ... indefinitely (unlike
ordinary retransmission, persist never gives up and removes the
connection on its own).

### Probe

`pollPersistProbes(now)` emits one segment per connection whose deadline
has passed, deliberately narrow to the no-outstanding-data case this
milestone covers:

```text
sequence number       = snd_nxt - 1   (wraps naturally: snd_nxt == 0 -> 0xffffffff)
acknowledgment number = rcv_nxt
flags                  = ACK
window                 = current advertised receive window
payload                = the first unsent application byte (copied, not moved)
options                = none
```

The probe consumes no sequence space and creates no `PendingTransmission`
-- it does not advance `snd_nxt` or `snd_una`, does not remove the byte
from `unsent`, does not change buffered-byte accounting, does not touch
`cwnd`/`ssthresh`/duplicate-ACK state, and is not evidence of loss for
Karn's rule or the RTO estimator. Repeated probes before a window update
reuse the same sequence number and the same queued byte. It is never
marked `PSH`.

### Cancellation and reopening

Cancelled by: an acceptable peer-window update making `snd_wnd > 0`
(same SND.WL1/WL2 freshness test as ordinary window updates); the unsent
queue becoming empty; outstanding sequence space appearing; the
connection leaving Established/CloseWait; or connection removal (RST,
timeout exhaustion, close completion, TIME_WAIT expiry). When
`snd_wnd` becomes positive, the very next scheduling pass (see "Send
buffering and scheduling" above) starts normal data at the *unchanged*
`snd_nxt` -- the byte the probe used becomes the first byte of that
normal segment, never lost, skipped, or duplicated. If the same
connection later becomes zero-window-eligible again, persist restarts at
the 1-second floor.

### Timer integration

`nextPersistDeadline()` joins `nextRetransmissionDeadline()` in sizing
the TAP event loop's `poll()` timeout (the smaller of the two). A
timer-fired probe uses the same timer-originated send path as an
ordinary retransmission -- `ArpCache` neighbor lookup, never a received
frame's MAC, since there is no current received frame for a timer event.
TCP connection state stores no MAC addresses either way.

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

## TCP active open

Wirestack can initiate a connection to a listening peer (client-side
three-way handshake), in addition to the passive open covered above.
TCP simultaneous open is not implemented -- a bare SYN received while
Wirestack is in SynSent is dropped, not treated as a second handshake
path.

### API

```cpp
TcpConnectResult beginConnect(const TcpConnectionKey& key, TcpClock::time_point now);
```

The caller supplies the exact four-tuple (local IP, local port, remote
IP, remote port) -- there is no ephemeral-port allocator; the runtime
demonstration below uses one explicitly configured source port.
Rejected (`accepted=false`, `TcpConnectError`) for a zero local or
remote port (`InvalidPort`) or a four-tuple that already has connection
state, active or passive (`DuplicateConnection`). A rejected call
creates no state, consumes no ISN, and queues no transmission.

### SynSent

A new `TcpState::SynSent` value. A successful `beginConnect` inserts a
`Connection` in this state with `local_isn` freshly drawn, `snd_una =
local_isn`, `snd_nxt = local_isn + 1` (the SYN consumes one sequence
number), and no valid peer sequence state yet -- tracked with a
`remote_isn_known` flag rather than treating an arbitrary zero as valid
(a passively-created connection always has this true from construction,
since its `remote_isn` comes from the peer's initial SYN, known
immediately). Every existing state switch in the connection table was
audited: SynSent is dispatched to its own `handleSynSent` before the
shared `handleSynchronized` path, so it can never be silently treated as
Established, SynReceived, or a synchronized close state.

### Active SYN

Built by `makeActiveSyn`: source/destination ports from the key,
sequence number `local_isn`, acknowledgment number 0, `SYN=1` only
(`ACK=0`, `RST=0`, `FIN=0`), empty payload, unscaled window (window
scaling never applies to a SYN's own window field). Its options
(`buildActiveSynOptions`) advertise MSS (`kTcpMss`), SACK-Permitted
(always offered), and Window Scale (always offered,
`kLocalWindowScaleShift`) -- the same local capability constants the
passive SYN-ACK path uses, offered unconditionally here since no peer
options have been seen yet.

### Retransmission

The active SYN uses the existing `PendingTransmission`/timer machinery,
not a second queue. A new `is_active_syn` flag on that entry (alongside
the existing `is_syn`, which a passive SYN-ACK entry also sets)
distinguishes the two roles for `pollRetransmissions`: an active SYN
retransmission always carries `ack=0` and no ACK flag, rebuilds the
exact same option bytes via `buildActiveSynOptions`, and stays unscaled,
while a SYN-ACK retransmission keeps its existing `remote_isn+1`/
`buildSynAckOptions` behavior. Adaptive RTO/backoff, retry-count
exhaustion (removing only the affected connection, freeing the
four-tuple for reuse), and the "never gated by cwnd/rwnd" rule are all
the same generic machinery every other pending entry already uses --
nothing SYN-specific was added there.

### SYN-ACK validation

`handleSynSent` accepts a candidate SYN-ACK only if: the segment carries
`SYN=1, ACK=1`; `RST=0`; `FIN=0`; payload empty;
`acknowledgment_number == snd_nxt` (i.e. exactly `local_isn + 1` --
too low, too high, or equal to `local_isn` itself all fail); and its TCP
options parse structurally (malformed options are rejected before any
state, sequence, or RST mutation, matching the existing rule in
`handleSynchronized`, including for an RST that happens to arrive with
malformed option bytes attached -- see "Reset handling" below). Anything
else in SynSent (an ACK-only segment, a bare SYN from the peer, a FIN or
FIN|ACK, a payload-bearing SYN-ACK, a PSH|ACK) is silently dropped: no
payload delivery, no partial FIN processing, no simultaneous-open state,
no reply. This is a deliberately narrow, documented behavior, not RFC
5961-style challenge-ACK handling.

### Option negotiation

Directionality mirrors the passive path exactly, with the two SYN sides
swapped: the peer's MSS (from its SYN-ACK) limits Wirestack's outgoing
segment size (`effective_send_mss = min(kTcpMss, peer_mss)`, defaulting
to `kDefaultPeerMss` if the peer omitted MSS); the peer's Window Scale
(if present) decodes future peer-advertised windows and simultaneously
enables Wirestack's own already-offered local scale for its own
advertised window; the peer's SACK-Permitted (if present) determines
whether Wirestack may send SACK blocks, the same combined `sack_permitted`
flag the passive path already uses for both directions. None of this
touches connection state until options have already parsed structurally.

### Window initialization

The SYN-ACK's raw `window_size` field initializes `snd_wnd` directly --
window scaling is never applied to a SYN or SYN-ACK's own window field,
even once negotiated, exactly as the passive path already treats its own
SYN-ACK. The next ordinary (non-SYN) ACK is the first segment where the
negotiated peer scale actually applies.

### RTT sampling and Karn's rule

The active SYN's pending entry uses the same `retireAcknowledged` path
every other entry does: a clean (never-retransmitted) SYN takes one RTT
sample on establishment; a SYN retransmitted by timeout is marked
`was_retransmitted` and is therefore never a sampling candidate (Karn's
rule) even though it still establishes normally once the (now
ambiguous) SYN-ACK arrives. No separate RTT estimator was added.

### Final ACK

On a valid SYN-ACK: `remote_isn = segment.sequence_number`, `rcv_nxt =
remote_isn + 1`, `snd_una = snd_nxt = local_isn + 1`, state becomes
Established, and a final ACK is built (source/destination from the key,
`sequence_number = snd_nxt` -- unchanged, consumes no sequence space --
`acknowledgment_number = rcv_nxt`, `ACK` only, post-negotiation
advertised window). It is returned as an ordinary immediate reply and is
**not** added to the retransmission queue, the same way every other pure
ACK in this codebase is never queued.

### Reset/refusal

A Linux closed port answers an active SYN with `RST|ACK`,
`ack=local_isn+1`. `handleSynSent` accepts a reset only when
`flags.rst && flags.ack && acknowledgment_number == snd_nxt`; any other
reset shape (bare RST, wrong ACK) is ignored without mutating the
connection, and -- like every other malformed-options-before-RST path in
this codebase (see the existing `handleSynchronized` fix this preserves)
-- a reset whose accompanying option bytes fail to parse is also ignored
before any mutation. A valid refusal removes the connection (no pending
SYN, no reply is ever sent for an RST) and immediately frees the
four-tuple for a later `beginConnect`; unrelated connections are
untouched.

### Duplicate SYN-ACK after establishment

If the final ACK is lost and the peer retransmits its SYN-ACK, that
retransmission still carries `SYN=1`, which `handleSynchronized` would
otherwise drop unconditionally for every synchronized state. A narrow
exception checks whether the SYN-bearing segment matches this
connection's own completed handshake identity exactly
(`ACK` set, `RST`/`FIN` clear, empty payload, `sequence_number ==
remote_isn`, `acknowledgment_number == local_isn + 1`) and, if so,
replies with a fresh pure ACK for the already-established connection --
no renegotiation, no sequence-space movement, no second establishment.
Any other SYN-bearing segment in a synchronized state is still dropped
exactly as before.

### Runtime demonstration and neighbor-resolution limitation

`wirestack <tap> <ip> <mac> --active-open <ip>:<port> --source-port
<port>` (both flags required together; absent by default, leaving the
passive HTTP listener as the only runtime behavior). main.cpp owns this
policy entirely -- it waits for the peer's MAC to already be present in
the existing ARP cache, calls `beginConnect` exactly once, and sends the
resulting SYN through the existing `sendTcpSegment` path; the SYN-ACK,
RST, and timeout outcomes are then handled by the ordinary receive loop.
**Limitation**: active TCP open is implemented, but the current runtime
demonstration requires the peer MAC to already be present in the ARP
cache (learned opportunistically from any prior ARP or IPv4 traffic from
that peer -- see `handleIpv4`'s `arp_cache.insert` call). Wirestack does
not send an ARP request of its own to actively resolve an unknown
neighbor; there is no autonomous neighbor discovery or routing table.

## Manual verification procedure

For a reproducible, automated version of the checks below -- plus
loss/retransmission, SYN-ACK loss recovery, and reordering with
packet-capture evidence -- see [docs/interoperability.md](interoperability.md).

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
change afterward:

```bash
# terminal 2, on the dedicated wire0 device only -- record and remove
# this qdisc when done
sudo tc qdisc add dev wire0 root netem loss 25%
# ... run the HTTP request above one or more times ...
sudo tc qdisc del dev wire0 root netem
```

Expect tcpdump to occasionally show three duplicate `Flags [.]` ACKs from
the client for the same acknowledgment number, followed by Wirestack
retransmitting the missing segment before any RTO would have expired
(well under the connection's current RTO, visible via the `wirestack`
process's own logging), and the client's next ACK advancing past the
previously-missing segment. `LIVE FAST RETRANSMIT: MANUAL VERIFICATION
REQUIRED` when this has not been exercised in the current environment
(e.g. no `CAP_NET_ADMIN` or usable non-interactive sudo) -- do not
fabricate tcpdump evidence.

A real client (Linux's own TCP) advertises `sackOK` in its SYN by
default, so the same `curl`/`tcpdump` procedure above should show
Wirestack's SYN-ACK echoing `sackOK` too (`tcpdump -vvv` prints the
negotiated options). Repeating the `tc netem loss` procedure with a
larger HTTP body (so more than one segment is outstanding at once) is
expected to occasionally show a client ACK carrying `sack N:M` blocks
alongside a duplicate ACK -- proof of the same selective-retransmission
path exercised by `tests/test_tcp_sack_path.cpp`. `LIVE SACK RECOVERY:
MANUAL VERIFICATION REQUIRED` when this has not been exercised in the
current environment -- do not fabricate tcpdump evidence.

To exercise zero-window persist live, the peer must deliberately
advertise a zero receive window with an empty socket receive buffer
(e.g. `nc -l` reading nothing, or a small Python socket with `SO_RCVBUF`
set to 0 and never calling `recv`) while Wirestack has queued data to
send it -- only attempt this against the same dedicated, isolated TAP
setup, never a shared interface. Expect tcpdump to show the peer's
`Flags [.] win 0`, Wirestack's own one-byte probe roughly one second
later (`seq` one behind its current send sequence, not advancing it),
the peer's repeated zero-window ACK, and -- once the peer's window
genuinely reopens -- Wirestack's normal data resuming at the *same*
sequence number the probe used. `LIVE PERSIST: MANUAL VERIFICATION
REQUIRED` when this has not been exercised in the current environment;
do not fabricate tcpdump evidence, and do not claim persist is
live-proven without seeing all of: the zero-window advertisement, the
probe, and the reopening update.

## Known limitations

- MSS, Window Scale, SACK-Permitted, and SACK are understood; timestamps
  are safely skipped like any other unknown well-formed option, never
  interpreted or acted on.
- Congestion control is a narrow, educational Reno/NewReno-style model
  (Slow Start, Congestion Avoidance, duplicate-ACK fast retransmit,
  NewReno-style partial-ACK recovery, a bounded segment-granular SACK
  scoreboard) -- not a claim of full or RFC-compliant Reno/NewReno/SACK.
  Specifically: SACK coverage is segment-granular, not sub-range -- a
  partially SACKed pending entry may be retransmitted in full; no SACK
  reneging recovery beyond clearing the whole scoreboard on RTO; no
  DSACK; no RFC 6675 pipe-estimation algorithm; no PRR; no Limited
  Transmit; no CUBIC; no BBR; no ECN; no congestion-window validation
  after idle; no ACK pacing.
- Active open (see "TCP active open" above) has no TCP simultaneous
  open, no general ephemeral-port allocator, and the current runtime
  demonstration requires the peer MAC to already be present in the ARP
  cache (no active neighbor resolution).
- No challenge ACK; an unacceptable RST is simply dropped.
- The RTT/RTO estimator is an integer-arithmetic approximation of
  RFC 6298 (Karn's rule, SRTT/RTTVAR/RTO, 1s/60s bounds), not a claim of
  full RFC 6298 compliance.
- Persist probes only the single case documented under "Zero-window
  persist" above: unsent data queued, a genuinely zero peer window, and
  no sequence space already outstanding. Outstanding data under a zero
  window continues to use ordinary retransmission timing, not persist.
- No application-facing asynchronous write API and no partial enqueue --
  `makeOutgoingData` is synchronous and all-or-nothing at enqueue time;
  the send buffer itself is a plain owned `std::vector<std::byte>`, not
  zero-copy.
- An inflated fast-recovery `cwnd` may go unused if the caller has
  nothing queued to send into it (there is still no automatic background
  sender beyond what an ACK/window update schedules).
- `kMaxCongestionWindow` (`1 << 30` bytes) is not organically reachable
  through a practical deterministic test -- see "Testing limitation"
  under "Congestion control" above.
- Overlap/duplicate handling is a deterministic first-arrival-wins policy
  bounded to a 262140-byte internal capacity and 128 fragments, not
  general attack-resistant TCP normalization; the wire-visible advertised
  window still never exceeds 65535 unless Window Scale was negotiated.
  This is the *receive*-side reassembly buffer and is fully independent
  of the new *send*-side buffer above -- distinct names, distinct
  accounting, distinct capacities.
- Single application on port 8080 (the HTTP/1.0 demonstration, see
  [docs/http.md](http.md)); no general application registration.

To exercise active open live, start a plain listener on the peer and
point Wirestack at it (see [docs/interoperability.md](interoperability.md)
for the isolated-namespace version this project's live suite actually
runs):

```bash
# terminal 2 (the peer)
nc -l 10.0.0.1 9090

# terminal 1
sudo ./build/wirestack wire0 10.0.0.2 02:00:00:00:00:02 \
    --active-open 10.0.0.1:9090 --source-port 49152
```

Expect tcpdump on `wire0` to show Wirestack's `Flags [S]` from
10.0.0.2:49152, the peer's `Flags [S.]`, and Wirestack's `Flags [.]`
completing the handshake; `nc` reports the connection accepted. Pointing
`--active-open` at a closed port instead (no listener) is expected to
show the peer's `Flags [R.]` and Wirestack's own printed "active
connection refused" line, with no further SYN retransmission afterward.

## Next TCP work

Minimal outbound HTTP/1.0 client over TCP active open using a literal
IPv4 address.
