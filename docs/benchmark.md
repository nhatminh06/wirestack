# Reproducible TCP benchmark

This benchmark measures the existing 12,103-byte `/sack-test` HTTP/1.0
response. It is a short-transfer latency and per-transfer goodput benchmark,
not a sustained-throughput benchmark.

## Reproduce

Build the ordinary Debug configuration, then run the benchmark inside an
unprivileged user/network namespace:

```bash
cmake -S . -B build
cmake --build build -j
unshare --user --net --map-root-user -- bash tools/bench/run.sh
```

The script performs five untimed warm-up transfers per server, followed by 30
measured connections for each scenario. It prints the evidence directory;
that directory contains JSONL timings, JSON summaries, pcaps, decoded traces,
client logs, and trace-derived retransmission/recovery metrics. Repetition
counts can be reduced for harness debugging with `WS_BENCH_REPETITIONS` and
`WS_BENCH_WARMUPS`; published results below use the defaults.

## Environment for the recorded run

- Date: 2026-10-18
- CPU: Intel Core i5-11400H, 6 cores/12 threads, frequency scaling enabled
- OS/kernel: x86-64 Linux 7.2.9-2-cachyos, PREEMPT_DYNAMIC
- Compiler: GCC 16.2.1, C++20
- CMake: 4.4.4
- Build: default project Debug configuration, existing warning flags
- Source revision: `affba42` plus the uncommitted Milestones 1-6 changes
- Evidence: `/tmp/wirestack-integration.8ZZC2t`

No CPU pinning, frequency locking, or exclusive-host reservation was used.
Results therefore describe this run, not a stable hardware limit.

## Topology and workload

The harness reuses the integration suite's isolated 1500-MTU topology:

```text
Linux client namespace (10.0.0.1)
              |
         veth pair, MTU 1500
              |
        Linux bridge
          /        \
 Wirestack TAP   Linux TCP baseline
  10.0.0.2       10.0.0.3
```

Offloads and TCP timestamps are disabled inside the isolated namespaces so
both senders use 1460-byte data segments. Wirestack and the single-threaded
Python baseline server emit the same HTTP/1.0 headers and 12,000-byte body.
The client rejects any byte mismatch.

Scenarios are normal transfer, exact loss of segment 2, exact loss of
nonadjacent segments 2 and 4, and `netem delay 60ms reorder 100% gap 2`
without configured loss. Exact-loss cases use the captured server ISN and
`tc u32` sequence filters. Client egress is delayed 20 ms during those cases
so the drop qdisc can be removed before recovery packets arrive; this applies
equally to both implementations and is part of the reported latency.

## Measurement method

- Request latency starts immediately before sending the GET and ends at EOF.
- Setup/teardown time is TCP connect time plus request latency.
- Per-transfer goodput is validated application bytes divided by request
  latency. It includes HTTP headers and is not sustained TCP throughput.
- Retransmissions and loss recovery time come from upstream pcaps. A repeated
  data sequence range counts as one retransmission; recovery time spans its
  first transmission to first repeat.
- CPU time is the server process's `/proc/<pid>/stat` user+system delta across
  all 120 measured transfers. Peak RSS is `/proc/<pid>/status` `VmHWM`.
- No random loss or random workload selection is used.

## Results

All scenarios completed 30/30 transfers with exact response bytes.

| Server | Scenario | Median latency | p95 latency | Median per-transfer goodput | Retransmissions | Recovery median/p95 |
|---|---:|---:|---:|---:|---:|---:|
| Wirestack | Normal | 0.306 ms | 0.487 ms | 316.20 Mbit/s | 0 | n/a |
| Linux | Normal | 0.131 ms | 0.220 ms | 736.68 Mbit/s | 0 | n/a |
| Wirestack | One loss | 41.034 ms | 41.158 ms | 2.36 Mbit/s | 30 | 20.470/20.543 ms |
| Linux | One loss | 40.376 ms | 40.472 ms | 2.40 Mbit/s | 35 | 20.101/20.121 ms |
| Wirestack | Two losses | 61.369 ms | 61.501 ms | 1.58 Mbit/s | 60 | 30.618/40.823 ms |
| Linux | Two losses | 40.388 ms | 40.470 ms | 2.40 Mbit/s | 63 | 20.106/20.144 ms |
| Wirestack | Reorder only | 60.585 ms | 60.785 ms | 1.60 Mbit/s | 0 | n/a |
| Linux | Reorder only | 120.293 ms | 120.419 ms | 0.80 Mbit/s | 126 | 0.072/60.035 ms* |

`*` Linux retransmitted under the reorder pattern despite no configured packet
loss. Its recovery statistic mixes immediate duplicate-range transmissions
with roughly 60 ms repeats, so it is not comparable to loss recovery time.

Normal setup/teardown median and p95 were 1.483/1.615 ms for Wirestack and
1.176/1.308 ms for Linux, equivalent to about 674 and 850 sequential
connections per second at the median. This is serialized request rate, not a
concurrent-load result.

Across all 120 measured transfers, server process CPU time was 150 ms for
Wirestack and 30 ms for the Python baseline. Peak RSS was 6,252 KiB and 17,616
KiB respectively.

## Comparison limitations

- The Linux baseline's application is Python while Wirestack combines a C++
  application and userspace TCP stack. Process CPU excludes Linux networking
  work executed outside the Python process, so the CPU figures are not a full
  kernel-versus-userspace accounting. RSS also includes different runtimes.
- The Linux endpoint terminates on the bridge; Wirestack additionally crosses
  the TAP interface. Both use the same client, veth, bridge, MTU, payload,
  protocol, offload settings, and impairment rules, but topology is not
  perfectly identical.
- The 12 KB response fits Wirestack's initial congestion window and 256 KiB
  send-buffer bound. No sustained transfer, concurrency, saturation, disk I/O,
  routed network, or physical NIC is measured.
- Frequency scaling and ordinary host activity were not controlled. Repeat on
  the target hardware before using the numbers for engineering decisions.
