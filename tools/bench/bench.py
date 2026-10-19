#!/usr/bin/env python3
"""Small standard-library helpers for the isolated TCP benchmark."""

import argparse
import json
import os
import re
import socket
import statistics
import sys
import time
from collections import Counter, defaultdict
from datetime import datetime


BODY = b"s" * 12000
RESPONSE = (b"HTTP/1.0 200 OK\r\nContent-Type: text/plain; charset=utf-8\r\n"
            b"Content-Length: 12000\r\nConnection: close\r\n\r\n" + BODY)
REQUEST = b"GET /sack-test HTTP/1.0\r\n\r\n"


def percentile(values, percentile_value):
    ordered = sorted(values)
    index = max(0, (len(ordered) * percentile_value + 99) // 100 - 1)
    return ordered[index]


def serve(args):
    listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    listener.setsockopt(socket.IPPROTO_TCP, socket.TCP_MAXSEG, 1460)
    listener.bind((args.ip, args.port))
    listener.listen(16)
    print("READY", flush=True)
    while True:
        connection, _ = listener.accept()
        with connection:
            connection.settimeout(5.0)
            request = b""
            while b"\r\n\r\n" not in request and len(request) <= 8192:
                chunk = connection.recv(4096)
                if not chunk:
                    break
                request += chunk
            if request != REQUEST:
                continue
            connection.sendall(RESPONSE)


def client(args):
    connect_start = time.perf_counter_ns()
    connection = socket.create_connection((args.ip, args.port), timeout=5.0)
    connect_ns = time.perf_counter_ns() - connect_start
    source_port = connection.getsockname()[1]
    print(f"CONNECTED {source_port}", flush=True)
    deadline = time.monotonic() + 5.0
    while not os.path.exists(args.go_file):
        if time.monotonic() >= deadline:
            raise TimeoutError("benchmark harness did not release client")
        time.sleep(0.001)

    request_start = time.perf_counter_ns()
    connection.sendall(REQUEST)
    connection.settimeout(8.0)
    chunks = []
    while True:
        chunk = connection.recv(16384)
        if not chunk:
            break
        chunks.append(chunk)
    request_ns = time.perf_counter_ns() - request_start
    connection.close()
    received = b"".join(chunks)
    if received != RESPONSE:
        raise ValueError(f"response mismatch: received {len(received)} bytes")

    record = {
        "target": args.target,
        "scenario": args.scenario,
        "iteration": args.iteration,
        "source_port": source_port,
        "connect_ns": connect_ns,
        "request_ns": request_ns,
        "bytes": len(received),
        "success": True,
    }
    with open(args.output, "a", encoding="utf-8") as output:
        output.write(json.dumps(record, sort_keys=True) + "\n")


def snapshot(args):
    with open(f"/proc/{args.pid}/stat", encoding="utf-8") as stat_file:
        fields = stat_file.read().rsplit(")", 1)[1].split()
    ticks = int(fields[11]) + int(fields[12])
    peak_kib = 0
    with open(f"/proc/{args.pid}/status", encoding="utf-8") as status_file:
        for line in status_file:
            if line.startswith("VmHWM:"):
                peak_kib = int(line.split()[1])
                break
    print(json.dumps({"cpu_ticks": ticks, "clock_ticks": os.sysconf("SC_CLK_TCK"),
                      "peak_rss_kib": peak_kib}))


LINE_RE = re.compile(r"^(\d{4}-\d\d-\d\d \d\d:\d\d:\d\d\.\d+)\s+(.*)$")
SERVER_RE_TEMPLATE = r"{server}\.{port} > {client}\.(\d+): (.*)$"
SEQ_RE = re.compile(r"\bseq (\d+):(\d+)\b")
SACK_RE = re.compile(r"\bsack \d+ \{")


def trace_metrics(args):
    server_re = re.compile(SERVER_RE_TEMPLATE.format(
        server=re.escape(args.server_ip), port=args.port, client=re.escape(args.client_ip)))
    client_re = re.compile(re.escape(args.client_ip) + r"\.(\d+) > " +
                           re.escape(args.server_ip) + rf"\.{args.port}: (.*)$")
    data = defaultdict(list)
    sack_ports = set()
    with open(args.trace, encoding="utf-8") as trace:
        for line in trace:
            line_match = LINE_RE.match(line)
            if not line_match:
                continue
            timestamp = datetime.strptime(line_match.group(1), "%Y-%m-%d %H:%M:%S.%f").timestamp()
            rest = line_match.group(2)
            server_match = server_re.search(rest)
            if server_match:
                sequence = SEQ_RE.search(server_match.group(2))
                if sequence:
                    data[int(server_match.group(1))].append(
                        (timestamp, int(sequence.group(1)), int(sequence.group(2))))
                continue
            client_match = client_re.search(rest)
            if client_match and SACK_RE.search(client_match.group(2)):
                sack_ports.add(int(client_match.group(1)))

    retransmissions = 0
    recoveries_ms = []
    for events in data.values():
        occurrences = defaultdict(list)
        for timestamp, start, end in events:
            occurrences[(start, end)].append(timestamp)
        for times in occurrences.values():
            retransmissions += max(0, len(times) - 1)
            if len(times) > 1:
                recoveries_ms.append((times[1] - times[0]) * 1000.0)
    result = {
        "retransmissions": retransmissions,
        "connections_with_sack": len(sack_ports),
        "recovery_median_ms": statistics.median(recoveries_ms) if recoveries_ms else None,
        "recovery_p95_ms": percentile(recoveries_ms, 95) if recoveries_ms else None,
    }
    print(json.dumps(result, sort_keys=True))


def summarize(args):
    records = []
    with open(args.records, encoding="utf-8") as source:
        records = [json.loads(line) for line in source if line.strip()]
    start = json.loads(args.start_snapshot)
    end = json.loads(args.end_snapshot)
    cpu_ms = ((end["cpu_ticks"] - start["cpu_ticks"]) / end["clock_ticks"]) * 1000.0
    grouped = defaultdict(list)
    for record in records:
        grouped[record["scenario"]].append(record)
    output = {"target": args.target, "cpu_ms": cpu_ms,
              "peak_rss_kib": end["peak_rss_kib"], "scenarios": {}}
    for scenario, group in sorted(grouped.items()):
        durations = [record["request_ns"] / 1_000_000.0 for record in group]
        setup = [(record["connect_ns"] + record["request_ns"]) / 1_000_000.0
                 for record in group]
        goodput = [(record["bytes"] * 8.0) / (record["request_ns"] / 1_000_000_000.0) / 1_000_000.0
                   for record in group]
        output["scenarios"][scenario] = {
            "runs": len(group), "successes": sum(record["success"] for record in group),
            "failures": len(group) - sum(record["success"] for record in group),
            "latency_median_ms": statistics.median(durations),
            "latency_p95_ms": percentile(durations, 95),
            "goodput_median_mbps": statistics.median(goodput),
            "setup_teardown_median_ms": statistics.median(setup),
            "setup_teardown_p95_ms": percentile(setup, 95),
            "sequential_request_rate_per_s": 1000.0 / statistics.median(setup),
        }
    print(json.dumps(output, indent=2, sort_keys=True))


def main():
    parser = argparse.ArgumentParser()
    commands = parser.add_subparsers(dest="command", required=True)
    server = commands.add_parser("server")
    server.add_argument("ip")
    server.add_argument("port", type=int)
    server.set_defaults(function=serve)
    client_parser = commands.add_parser("client")
    client_parser.add_argument("ip")
    client_parser.add_argument("port", type=int)
    client_parser.add_argument("go_file")
    client_parser.add_argument("output")
    client_parser.add_argument("target")
    client_parser.add_argument("scenario")
    client_parser.add_argument("iteration", type=int)
    client_parser.set_defaults(function=client)
    snapshot_parser = commands.add_parser("snapshot")
    snapshot_parser.add_argument("pid", type=int)
    snapshot_parser.set_defaults(function=snapshot)
    trace = commands.add_parser("trace")
    trace.add_argument("trace")
    trace.add_argument("server_ip")
    trace.add_argument("client_ip")
    trace.add_argument("port", type=int)
    trace.set_defaults(function=trace_metrics)
    summary = commands.add_parser("summarize")
    summary.add_argument("records")
    summary.add_argument("target")
    summary.add_argument("start_snapshot")
    summary.add_argument("end_snapshot")
    summary.set_defaults(function=summarize)
    args = parser.parse_args()
    args.function(args)


if __name__ == "__main__":
    main()
