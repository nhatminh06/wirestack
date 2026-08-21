#!/usr/bin/env python3
"""Proves wirestack's receiver-side SACK advertisement exactly describes
the out-of-order range actually captured on the wire, and that the
connection recovers exactly once after the gap is filled.

Reads a one-line-per-packet tcpdump text trace (tcpdump -n -tttt, relative
sequence numbers -- NOT -S/-vv) of the TAP-side capture from the
reordering scenario. Derives the out-of-order range from the client data
segment that actually arrived first (not a hardcoded literal), then
checks wirestack's ACKs against it.

Exits nonzero with a reason on stderr on any violation. On success prints
the derived range and the observed values to stdout.
"""
import re
import sys

TS_RE = re.compile(r'^(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}\.\d+)\s+(.*)$')
SEQ_RE = re.compile(r'\bseq (\d+):(\d+)\b')
ACK_RE = re.compile(r'\back (\d+)\b')
SACK_RE = re.compile(r'\bsack (\d+) ((?:\{\d+:\d+\})+)')
SACK_BLOCK_RE = re.compile(r'\{(\d+):(\d+)\}')


def parse_ts(ts: str) -> float:
    _, time_ = ts.split(" ")
    h, m, s = time_.split(":")
    return int(h) * 3600 + int(m) * 60 + float(s)


def load(path):
    with open(path) as f:
        return f.readlines()


def main():
    trace_path, client_ip, server_ip, port = sys.argv[1:5]
    port = int(port)

    client_to_server = re.compile(
        re.escape(client_ip) + r'\S* > ' + re.escape(server_ip) + r'\.' + str(port) + r': (.*)$')
    server_to_client = re.compile(
        re.escape(server_ip) + r'\.' + str(port) + r' > ' + re.escape(client_ip) + r'\S*: (.*)$')

    events = []  # (t, direction, rest)
    for line in load(trace_path):
        m = TS_RE.match(line)
        if not m:
            continue
        t = parse_ts(m.group(1))
        rest = m.group(2)
        cm = client_to_server.search(rest)
        if cm:
            events.append((t, "c2s", cm.group(1)))
            continue
        sm = server_to_client.search(rest)
        if sm:
            events.append((t, "s2c", sm.group(1)))

    events.sort(key=lambda e: e[0])

    client_data = [(t, m.group(1), m.group(2)) for t, d, r in events if d == "c2s"
                   for m in [SEQ_RE.search(r)] if m]

    if not client_data:
        print("no client data segments found in capture", file=sys.stderr)
        return 1

    first_t, first_start, first_end = client_data[0]
    first_start, first_end = int(first_start), int(first_end)

    if first_start == 1:
        print("no reordering observed: first client data segment on the wire "
              "already starts at offset 1", file=sys.stderr)
        return 1

    print(f"derived out-of-order range from capture: {{{first_start}:{first_end}}} "
          f"(first client data segment on the wire, at t={first_t:.6f})")

    # The gap-filling segment: the client data segment starting at 1.
    gapfill = [(t, s, e) for t, s, e in client_data if int(s) == 1]
    if not gapfill:
        print("no gap-filling client segment (starting at offset 1) found in capture", file=sys.stderr)
        return 1
    gapfill_t = gapfill[0][0]

    total_end = max(int(e) for _, _, e in client_data)

    # --- phase 1: while the gap is open (before the gap-fill arrives) ------
    pre_acks = [(t, r) for t, d, r in events if d == "s2c" and t < gapfill_t and ACK_RE.search(r)]
    sack_acks = [(t, r) for t, r in pre_acks if SACK_RE.search(r)]
    if not sack_acks:
        print("no SACK option observed in any ACK before the gap was filled", file=sys.stderr)
        return 1

    for t, r in sack_acks:
        ack_num = int(ACK_RE.search(r).group(1))
        if ack_num != 1:
            print(f"cumulative ACK incorrectly advanced to {ack_num} while the gap "
                  f"(byte 1) was still missing, at t={t:.6f}: {r}", file=sys.stderr)
            return 1
        sm = SACK_RE.search(r)
        blocks = SACK_BLOCK_RE.findall(sm.group(2))
        if len(blocks) != 1:
            print(f"expected exactly one SACK block, got {len(blocks)} at t={t:.6f}: {r}", file=sys.stderr)
            return 1
        left, right = int(blocks[0][0]), int(blocks[0][1])
        if left != first_start:
            print(f"SACK left edge {left} does not match captured out-of-order "
                  f"range start {first_start}, at t={t:.6f}: {r}", file=sys.stderr)
            return 1
        if right != first_end:
            print(f"SACK right edge {right} does not match captured out-of-order "
                  f"range end {first_end}, at t={t:.6f}: {r}", file=sys.stderr)
            return 1

    print(f"pre-gapfill ACKs verified: cumulative ack=1, SACK block={{{first_start}:{first_end}}} "
          f"({len(sack_acks)} ACK(s) checked)")

    # --- phase 2: after the gap-fill arrives ---------------------------------
    post_acks = [(t, r) for t, d, r in events if d == "s2c" and t >= gapfill_t and ACK_RE.search(r)]
    if not post_acks:
        print("no ACK observed after the gap-filling segment arrived", file=sys.stderr)
        return 1

    final_acks = [int(ACK_RE.search(r).group(1)) for _, r in post_acks]
    # >= rather than ==: the client's closing FIN consumes one more
    # sequence number after the last data byte, so a later ACK covering
    # the FIN too (total_end + 1) is a stronger, still-correct result --
    # only failing to reach total_end at all is the defect being checked.
    if max(final_acks) < total_end:
        print(f"cumulative ACK never advanced to the full request end ({total_end}); "
              f"max observed was {max(final_acks)}", file=sys.stderr)
        return 1

    stale_sack = [(t, r) for t, r in post_acks if int(ACK_RE.search(r).group(1)) >= total_end and SACK_RE.search(r)]
    if stale_sack:
        print(f"stale SACK block still advertised after cumulative ACK reached "
              f"the full request end: {stale_sack[0][1]}", file=sys.stderr)
        return 1

    print(f"post-gapfill: cumulative ACK advanced to {total_end} (full request), "
          "no stale SACK block advertised")

    # --- response delivered exactly once ------------------------------------
    response_segs = [(t, r) for t, d, r in events if d == "s2c" and t > gapfill_t
                      and "Flags [P" in r and SEQ_RE.search(r)]
    if not response_segs:
        print("no HTTP response data segment observed after the gap was filled", file=sys.stderr)
        return 1
    distinct_response_starts = {SEQ_RE.search(r).group(1) for _, r in response_segs}
    if len(distinct_response_starts) != 1:
        print(f"more than one distinct HTTP response segment observed "
              f"(starts: {sorted(distinct_response_starts)}) -- duplicate application response",
              file=sys.stderr)
        return 1

    print(f"HTTP response observed exactly once (sequence start "
          f"{next(iter(distinct_response_starts))}, {len(response_segs)} segment(s) on the wire)")

    return 0


if __name__ == "__main__":
    sys.exit(main())
