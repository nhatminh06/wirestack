#!/usr/bin/env python3
"""Proves wirestack's SYN-ACK retransmission is RTO-driven, not merely an
immediate reply to a client-retransmitted SYN.

Reads two one-line-per-packet tcpdump text traces (tcpdump -n -tttt -S,
no -v -- that flag switches to a multi-line format per packet and would
break the single-regex-per-line parsing here):

  tap_trace   -- captured at the TAP, upstream of the lossy link. Shows
                 every SYN-ACK wirestack actually transmitted, including
                 ones later dropped.
  host_trace  -- captured downstream of the loss qdisc. Shows only what
                 actually reached the client.

Exits nonzero with a reason on stderr if the evidence does not prove an
RTO-driven retransmission occurred, or if any invariant is violated.
On success prints one line per finding to stdout.
"""
import re
import sys
from datetime import datetime

TS_RE = re.compile(r'^(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}\.\d+)\s+(.*)$')


def parse_ts(ts: str) -> float:
    # A real epoch timestamp (matching `date +%s.%N`'s scale), not just
    # seconds-since-midnight -- callers compare this against wall-clock
    # markers taken outside tcpdump (e.g. when a loss qdisc was
    # added/removed), so the two must be on the same scale.
    return datetime.strptime(ts, "%Y-%m-%d %H:%M:%S.%f").timestamp()


def load(path):
    with open(path) as f:
        return f.readlines()


def main():
    tap_trace, host_trace, server_ip, port, loss_start, loss_end = sys.argv[1:7]
    port = int(port)
    loss_start = float(loss_start)
    loss_end = float(loss_end)

    syn_re = re.compile(r'> ' + re.escape(server_ip) + r'\.' + str(port) + r': Flags \[S\],')
    synack_re = re.compile(re.escape(server_ip) + r'\.' + str(port) + r' > .*: (Flags \[S\.\], .*)$')

    syn_ts = []
    synack_ts = []
    synack_bodies = []
    for line in load(tap_trace):
        m = TS_RE.match(line)
        if not m:
            continue
        ts, rest = m.groups()
        t = parse_ts(ts)
        if syn_re.search(rest):
            syn_ts.append(t)
        sm = synack_re.search(rest)
        if sm:
            synack_ts.append(t)
            synack_bodies.append(sm.group(1))

    if len(synack_ts) < 2:
        print(f"only {len(synack_ts)} SYN-ACK(s) observed at the TAP; no retransmission at all", file=sys.stderr)
        return 1

    # Every captured SYN-ACK must be byte-for-byte the same replayed
    # segment: same seq, flags, MSS/SACK-permitted/window-scale options,
    # and options bytes (captured together as one string here).
    first_body = synack_bodies[0]
    for i, body in enumerate(synack_bodies[1:], start=1):
        if body != first_body:
            print(f"SYN-ACK #{i} differs from #0:\n  #0: {first_body}\n  #{i}: {body}", file=sys.stderr)
            return 1
    if "mss 1460" not in first_body or "sackOK" not in first_body or "wscale" not in first_body:
        print(f"SYN-ACK missing an expected option: {first_body}", file=sys.stderr)
        return 1

    # Invariant: no single client SYN produced more than one immediate
    # (< 0.3s) SYN-ACK reply. If this were violated, synack_count could
    # exceed syn_count purely from duplicate-reply bugs, with no RTO
    # involved at all -- which would make the inequality below worthless.
    IMMEDIATE_WINDOW = 0.3
    syn_ts_sorted = sorted(syn_ts)
    for i, s in enumerate(syn_ts_sorted):
        next_syn = syn_ts_sorted[i + 1] if i + 1 < len(syn_ts_sorted) else float("inf")
        immediate = [a for a in synack_ts if s < a < min(s + IMMEDIATE_WINDOW, next_syn)]
        if len(immediate) > 1:
            print(f"client SYN at {s:.6f} produced {len(immediate)} immediate SYN-ACKs "
                  f"(expected at most 1): {immediate}", file=sys.stderr)
            return 1

    # RTO proof: a SYN-ACK with no client SYN between it and the
    # previous SYN-ACK, separated by a gap far larger than any
    # immediate-reply latency, proves a spontaneous (timer-driven)
    # retransmission -- not a reply to anything the client sent.
    RTO_GAP_THRESHOLD = 0.5  # wirestack's initial RTO is ~1s; well above any local veth RTT
    rto_proven_at = None
    for i in range(1, len(synack_ts)):
        prev, cur = synack_ts[i - 1], synack_ts[i]
        intervening_syn = any(prev < s < cur for s in syn_ts)
        if not intervening_syn and (cur - prev) >= RTO_GAP_THRESHOLD:
            rto_proven_at = (prev, cur, cur - prev)
            break

    dup_syn_replay_observed = len(syn_ts) > 1

    if rto_proven_at is None:
        print("no SYN-ACK gap without an intervening client SYN met the RTO timing threshold "
              f"(>= {RTO_GAP_THRESHOLD}s); evidence is consistent with duplicate-SYN replay only, "
              "which does not prove RTO-driven retransmission", file=sys.stderr)
        return 1

    # Confirm loss actually suppressed delivery: no SYN-ACK reached the
    # client-side (downstream) capture during the loss window, and at
    # least one did afterward.
    host_synack_ts = []
    for line in load(host_trace):
        m = TS_RE.match(line)
        if not m:
            continue
        ts, rest = m.groups()
        if synack_re.search(rest):
            host_synack_ts.append(parse_ts(ts))

    during_loss = [t for t in host_synack_ts if loss_start <= t <= loss_end]
    if during_loss:
        print(f"SYN-ACK reached the client-side capture during the loss window: {during_loss}", file=sys.stderr)
        return 1
    after_loss = [t for t in host_synack_ts if t > loss_end]
    if not after_loss:
        print("no SYN-ACK reached the client-side capture after loss was lifted", file=sys.stderr)
        return 1

    print(f"RTO-driven retransmission: proven (gap {rto_proven_at[2]:.3f}s between "
          f"{rto_proven_at[0]:.6f} and {rto_proven_at[1]:.6f}, no intervening client SYN)")
    print(f"duplicate-SYN replay: {'observed' if dup_syn_replay_observed else 'not observed'} "
          f"({len(syn_ts)} client SYN(s) total)")
    print(f"SYN-ACK count at TAP: {len(synack_ts)}, all identical: seq/flags/options match")
    print(f"loss window suppressed delivery to client: confirmed (0 during, "
          f"{len(after_loss)} after)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
