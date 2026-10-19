#!/usr/bin/env python3
"""Validate Linux SACK feedback and Wirestack selective retransmission."""

import re
import sys
from collections import Counter


LINE_RE = re.compile(r"^(\d{4}-\d\d-\d\d \d\d:\d\d:\d\d\.\d+)\s+(.*)$")
SEQ_RE = re.compile(r"\bseq (\d+):(\d+)\b")
ACK_RE = re.compile(r"\back (\d+)\b")
SACK_RE = re.compile(r"\bsack \d+ ((?:\{\d+:\d+\})+)")
BLOCK_RE = re.compile(r"\{(\d+):(\d+)\}")


def load(path, server_ip, client_ip, port):
    server = re.compile(re.escape(server_ip) + rf"\.{port} > " + re.escape(client_ip) + r"\.\d+: (.*)$")
    client = re.compile(re.escape(client_ip) + r"\.\d+ > " + re.escape(server_ip) + rf"\.{port}: (.*)$")
    events = []
    with open(path, encoding="utf-8") as trace:
        for line in trace:
            match = LINE_RE.match(line)
            if not match:
                continue
            rest = match.group(2)
            direction = None
            payload = None
            for name, pattern in (("s2c", server), ("c2s", client)):
                found = pattern.search(rest)
                if found:
                    direction, payload = name, found.group(1)
                    break
            if direction:
                events.append((match.group(1), direction, payload))
    return events


def data_ranges(events, direction="s2c"):
    return [(int(match.group(1)), int(match.group(2)))
            for _, event_direction, text in events if event_direction == direction
            for match in [SEQ_RE.search(text)] if match]


def fail(message):
    print(message, file=sys.stderr)
    return 1


def main():
    tap_path, host_path, mode, server_ip, client_ip, port = sys.argv[1:7]
    port = int(port)
    tap = load(tap_path, server_ip, client_ip, port)
    host = load(host_path, server_ip, client_ip, port)

    syn = next((text for _, direction, text in tap
                if direction == "c2s" and "Flags [S]" in text), "")
    synack = next((text for _, direction, text in tap
                   if direction == "s2c" and "Flags [S.]" in text), "")
    if "sackOK" not in syn or "sackOK" not in synack:
        return fail("SACK-Permitted was not negotiated in both SYN directions")

    tap_data = data_ranges(tap)
    host_data = data_ranges(host)
    if len(set(tap_data)) < 9:
        return fail(f"expected at least 9 distinct response segments, got {len(set(tap_data))}")

    counts = Counter(tap_data)
    retransmitted = {start for (start, _), count in counts.items() if count > 1}
    ordered_ranges = sorted(set(tap_data))
    expected_loss = {
        "single": {ordered_ranges[1][0]},
        "double": {ordered_ranges[1][0], ordered_ranges[3][0]},
    }.get(mode, set())

    if mode in ("single", "double"):
        if retransmitted != expected_loss:
            return fail(f"retransmitted starts {sorted(retransmitted)}, expected {sorted(expected_loss)}")
        sack_acks = [(text, [(int(a), int(b)) for a, b in BLOCK_RE.findall(match.group(1))])
                     for _, direction, text in tap if direction == "c2s"
                     for match in [SACK_RE.search(text)] if match]
        if not sack_acks:
            return fail("Linux emitted no SACK blocks during loss recovery")
        if not any(any(right > int(ACK_RE.search(text).group(1)) for _, right in blocks)
                   for text, blocks in sack_acks if ACK_RE.search(text)):
            return fail("SACK blocks did not describe data above the cumulative ACK")
    elif retransmitted:
        return fail(f"unexpected retransmission without loss: {sorted(retransmitted)}")

    if mode == "reorder":
        starts = [start for start, _ in host_data]
        if starts == sorted(starts):
            return fail("configured reorder case did not reorder response segments")
        if not any(direction == "c2s" and SACK_RE.search(text) for _, direction, text in tap):
            return fail("Linux emitted no SACK block for reordered response data")

    final_end = max(end for _, end in ordered_ranges)
    acknowledgments = [int(match.group(1)) for _, direction, text in tap
                       if direction == "c2s" for match in [ACK_RE.search(text)] if match]
    if not acknowledgments or max(acknowledgments) < final_end:
        return fail(f"cumulative ACK did not reach response end {final_end}")
    if not any(direction == "s2c" and "Flags [F" in text for _, direction, text in tap):
        return fail("Wirestack FIN not observed")
    if not any(direction == "c2s" and "Flags [F" in text for _, direction, text in tap):
        return fail("Linux FIN not observed")

    print(f"{mode}: {len(ordered_ranges)} data segments, retransmitted starts "
          f"{sorted(retransmitted)}, cumulative ACK {max(acknowledgments)}, clean close")
    return 0


if __name__ == "__main__":
    sys.exit(main())
