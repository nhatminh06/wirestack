# TCP

## Current support

Passive three-way handshake, plus single-segment in-order application
data transfer with a built-in echo demonstration, over IPv4, on a single
fixed listening port (8080). No connection close, no active open, no
retransmission, no segmentation, no reassembly.

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
(no entry)  --SYN-->  SYN_RECEIVED  --valid ACK-->  ESTABLISHED
```

LISTEN is implicit: a connection key with no table entry is either
unbound or simply hasn't received a SYN yet. No `TcpState::Listen` or
`TcpState::Closed` object is stored. No further states exist -- an
Established connection stays Established for the rest of this milestone
(no FIN handling).

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

Wirestack's TCP layer has no knowledge of any application. `main.cpp`
implements the smallest possible policy on port 8080: whatever payload is
accepted from an Established connection is passed unmodified to
`makeOutgoingData` and sent back. This is a TCP echo demonstration, not
an HTTP server -- Wirestack does not parse or understand HTTP requests
sent to port 8080.

### Loss and retransmission

Lost outgoing data (SYN-ACK, ACK, or echoed application data) is not
retransmitted -- there is no timer, no retransmission queue, no RTT
estimation. A duplicate incoming SYN still triggers a SYN-ACK
retransmission (unchanged from Milestone 5); duplicate incoming data
triggers only an ACK, never a repeated echo.

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

## Known limitations

- No retransmission timer or queue -- lost outgoing data (SYN-ACK, ACK, or
  echoed application data) is not retransmitted. Duplicate incoming SYNs
  are still answered on receipt (unchanged from Milestone 5).
- No congestion control.
- No dynamic receive window (fixed value only).
- No FIN / connection close path.
- No active open (Wirestack never initiates a connection).
- No RST generation for closed ports or invalid segments.
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

TCP retransmission queue, retransmission timeout, and deterministic
loss-recovery testing.
