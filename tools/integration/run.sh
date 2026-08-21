#!/usr/bin/env bash
# Top-level entry point for the Linux TAP interoperability suite.
#
# Must be invoked already inside a sandbox with CAP_NET_ADMIN in its own
# network namespace:
#
#   unshare --user --net --map-root-user -- bash tools/integration/run.sh
#
# Builds the isolated topology (tools/integration/setup.sh), runs each
# protocol/loss/reordering scenario against the real wirestack binary and
# real Linux kernel clients, and tears everything down again
# (tools/integration/cleanup.sh) whether or not the scenarios pass. See
# docs/interoperability.md for the full procedure and evidence layout.
#
# Exit status is nonzero if any scenario fails, a dependency is missing,
# setup fails, or cleanup cannot remove harness-owned resources.

set -euo pipefail

WS_SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
export WS_INTEGRATION_SOURCED=1
# shellcheck source=./common.sh
. "${WS_SCRIPT_DIR}/common.sh"
# shellcheck source=./setup.sh
. "${WS_SCRIPT_DIR}/setup.sh"
# shellcheck source=./cleanup.sh
. "${WS_SCRIPT_DIR}/cleanup.sh"

ws_check_dependencies
ws_check_privileges
ws_make_evidence_dir

WS_CLEANED_UP=0
ws_on_exit() {
    local status=$?
    # Disarm before doing anything else: cleanup below can itself trigger
    # an EXIT (e.g. via a failing command under `set -e` in a sourced
    # function), and a still-armed trap would re-enter this handler.
    trap - EXIT
    if [ "${WS_CLEANED_UP}" != "1" ]; then
        WS_CLEANED_UP=1
        if ! ws_cleanup; then
            ws_log "cleanup could not remove all harness-owned resources"
            [ "${status}" = "0" ] && status=1
        fi
    fi
    if [ "${status}" != "0" ] || [ "${WS_TEST_FAILURES}" != "0" ]; then
        ws_log "evidence preserved at: ${WS_EVIDENCE_DIR}"
    fi
    exit "${status}"
}
trap ws_on_exit EXIT

ws_log "wirestack stdout/stderr, pcaps, and decoded traces will be kept under ${WS_EVIDENCE_DIR}"

ws_setup_topology
ws_start_wirestack

# ---------------------------------------------------------------------------
# 1. ARP
# ---------------------------------------------------------------------------
ws_test_arp() {
    ws_capture_start arp "${WS_HOST_VETH}"
    ws_in_client arping -c 1 -w 2 -I "${WS_CLIENT_VETH}" "${WS_SERVER_IP}" \
        >"${WS_EVIDENCE_DIR}/arp_client.log" 2>&1
    local client_rc=$?
    ws_capture_stop arp

    [ "${client_rc}" = "0" ] || { ws_log "arping failed, see ${WS_EVIDENCE_DIR}/arp_client.log"; return 1; }
    grep -q "Request who-has ${WS_SERVER_IP}.*tell ${WS_CLIENT_IP}" "${WS_EVIDENCE_DIR}/arp.txt" || return 1
    grep -qi "Reply ${WS_SERVER_IP} is-at ${WS_SERVER_MAC}" "${WS_EVIDENCE_DIR}/arp.txt" || return 1
    return 0
}

# ---------------------------------------------------------------------------
# 2. ICMP
# ---------------------------------------------------------------------------
ws_test_icmp() {
    ws_capture_start icmp "${WS_HOST_VETH}"
    ws_in_client ping -c 2 -W 2 -I "${WS_CLIENT_VETH}" "${WS_SERVER_IP}" \
        >"${WS_EVIDENCE_DIR}/icmp_client.log" 2>&1
    local client_rc=$?
    ws_capture_stop icmp

    [ "${client_rc}" = "0" ] || { ws_log "ping failed, see ${WS_EVIDENCE_DIR}/icmp_client.log"; return 1; }
    grep -q "0% packet loss" "${WS_EVIDENCE_DIR}/icmp_client.log" || return 1
    grep -q "ICMP echo request" "${WS_EVIDENCE_DIR}/icmp.txt" || return 1
    grep -q "ICMP echo reply" "${WS_EVIDENCE_DIR}/icmp.txt" || return 1
    grep -qi "bad cksum" "${WS_EVIDENCE_DIR}/icmp.txt" && return 1
    return 0
}

# ---------------------------------------------------------------------------
# 3. UDP
# ---------------------------------------------------------------------------
ws_test_udp() {
    ws_capture_start udp "${WS_HOST_VETH}"
    ws_in_client python3 - "${WS_SERVER_IP}" "${WS_UDP_PORT}" \
        >"${WS_EVIDENCE_DIR}/udp_client.log" 2>&1 <<'PYEOF'
import socket
import sys

server_ip = sys.argv[1]
port = int(sys.argv[2])
payload = b"wirestack-udp-probe"

s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.settimeout(2.0)
s.sendto(payload, (server_ip, port))
data, _ = s.recvfrom(4096)
if data != payload:
    print("MISMATCH sent=%r got=%r" % (payload, data))
    sys.exit(1)
print("OK payload=%r" % data)
PYEOF
    local client_rc=$?
    ws_capture_stop udp

    [ "${client_rc}" = "0" ] || { ws_log "udp probe failed, see ${WS_EVIDENCE_DIR}/udp_client.log"; return 1; }
    grep -q "OK payload=" "${WS_EVIDENCE_DIR}/udp_client.log" || return 1
    grep -q "${WS_CLIENT_IP}.*> ${WS_SERVER_IP}.*UDP" "${WS_EVIDENCE_DIR}/udp.txt" || return 1
    grep -q "${WS_SERVER_IP}.*> ${WS_CLIENT_IP}.*UDP" "${WS_EVIDENCE_DIR}/udp.txt" || return 1
    return 0
}

# ---------------------------------------------------------------------------
# 4. TCP handshake
# ---------------------------------------------------------------------------
ws_test_tcp_handshake() {
    ws_capture_start tcp_handshake "${WS_HOST_VETH}"
    ws_in_client python3 - "${WS_SERVER_IP}" "${WS_TCP_PORT}" \
        >"${WS_EVIDENCE_DIR}/tcp_handshake_client.log" 2>&1 <<'PYEOF'
import socket
import sys

server_ip = sys.argv[1]
port = int(sys.argv[2])

s = socket.create_connection((server_ip, port), timeout=3.0)
print("OK connected", s.getsockname(), s.getpeername())
s.close()
PYEOF
    local client_rc=$?
    ws_capture_stop tcp_handshake

    [ "${client_rc}" = "0" ] || { ws_log "handshake probe failed, see ${WS_EVIDENCE_DIR}/tcp_handshake_client.log"; return 1; }
    grep -q "OK connected" "${WS_EVIDENCE_DIR}/tcp_handshake_client.log" || return 1
    grep -q "Flags \[S\]" "${WS_EVIDENCE_DIR}/tcp_handshake.txt" || return 1
    grep -q "Flags \[S\.\]" "${WS_EVIDENCE_DIR}/tcp_handshake.txt" || return 1
    grep -q "mss 1460" "${WS_EVIDENCE_DIR}/tcp_handshake.txt" || return 1
    grep -qi "sackOK" "${WS_EVIDENCE_DIR}/tcp_handshake.txt" || return 1
    grep -qi "wscale" "${WS_EVIDENCE_DIR}/tcp_handshake.txt" || return 1
    grep -q "${WS_SERVER_IP}.${WS_TCP_PORT} > .*Flags \[R" "${WS_EVIDENCE_DIR}/tcp_handshake.txt" && return 1
    return 0
}

# ---------------------------------------------------------------------------
# 5. HTTP (also covers ordinary connection close)
# ---------------------------------------------------------------------------
ws_test_http() {
    ws_capture_start http "${WS_HOST_VETH}"
    ws_in_client curl --http1.0 -sS -D "${WS_EVIDENCE_DIR}/http_headers.txt" \
        -o "${WS_EVIDENCE_DIR}/http_body.txt" \
        "http://${WS_SERVER_IP}:${WS_TCP_PORT}/" >"${WS_EVIDENCE_DIR}/http_client.log" 2>&1
    local client_rc=$?
    ws_capture_stop http

    [ "${client_rc}" = "0" ] || { ws_log "curl failed, see ${WS_EVIDENCE_DIR}/http_client.log"; return 1; }

    local expected_body
    expected_body="$(printf 'Hello from Wirestack\n')"
    local actual_body
    actual_body="$(cat "${WS_EVIDENCE_DIR}/http_body.txt")"
    [ "${actual_body}" = "${expected_body}" ] || { ws_log "unexpected body: $(cat "${WS_EVIDENCE_DIR}/http_body.txt" | xxd | head -3)"; return 1; }

    grep -q "^HTTP/1.0 200 OK" "${WS_EVIDENCE_DIR}/http_headers.txt" || return 1
    grep -qi "^Content-Length: 21" "${WS_EVIDENCE_DIR}/http_headers.txt" || return 1
    grep -qi "^Connection: close" "${WS_EVIDENCE_DIR}/http_headers.txt" || return 1

    grep -q "Flags \[S\]" "${WS_EVIDENCE_DIR}/http.txt" || return 1
    grep -q "Flags \[S\.\]" "${WS_EVIDENCE_DIR}/http.txt" || return 1
    grep -q "GET / HTTP/1.0" "${WS_EVIDENCE_DIR}/http.txt" || return 1
    grep -q "Flags \[P\." "${WS_EVIDENCE_DIR}/http.txt" || return 1
    # Wirestack's own FIN, and the client's FIN in the other direction.
    grep -q "${WS_SERVER_IP}\.${WS_TCP_PORT} > .*Flags \[F" "${WS_EVIDENCE_DIR}/http.txt" || return 1
    grep -q "> ${WS_SERVER_IP}\.${WS_TCP_PORT}: Flags \[F" "${WS_EVIDENCE_DIR}/http.txt" || return 1
    return 0
}

# ---------------------------------------------------------------------------
# 6. Closed-port reset (SYN, no ACK, to an unbound port)
# ---------------------------------------------------------------------------
ws_test_closed_port_reset() {
    local closed_port=8081
    ws_capture_start closed_port "${WS_HOST_VETH}"
    ws_in_client python3 - "${WS_SERVER_IP}" "${closed_port}" \
        >"${WS_EVIDENCE_DIR}/closed_port_client.log" 2>&1 <<'PYEOF'
import socket
import sys

server_ip = sys.argv[1]
port = int(sys.argv[2])

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.settimeout(2.0)
try:
    s.connect((server_ip, port))
    print("UNEXPECTED connect succeeded")
    sys.exit(1)
except ConnectionRefusedError:
    print("OK connection refused")
except OSError as e:
    print("OTHER ERROR", e)
    sys.exit(1)
PYEOF
    local client_rc=$?
    ws_capture_stop closed_port

    [ "${client_rc}" = "0" ] || { ws_log "closed-port probe failed, see ${WS_EVIDENCE_DIR}/closed_port_client.log"; return 1; }
    grep -q "OK connection refused" "${WS_EVIDENCE_DIR}/closed_port_client.log" || return 1
    grep -q "${WS_CLIENT_IP}.*> ${WS_SERVER_IP}\.${closed_port}: Flags \[S\]" "${WS_EVIDENCE_DIR}/closed_port.txt" || return 1
    grep -q "${WS_SERVER_IP}\.${closed_port} > .*Flags \[R\.\]" "${WS_EVIDENCE_DIR}/closed_port.txt" || return 1
    return 0
}

# ---------------------------------------------------------------------------
# 7. Bare-ACK reset (raw socket, ACK with no prior SYN, to the bound
#    HTTP port but an unknown four-tuple)
# ---------------------------------------------------------------------------
ws_test_bare_ack_reset() {
    ws_capture_start bare_ack "${WS_HOST_VETH}"
    ws_in_client python3 - "${WS_CLIENT_IP}" "${WS_SERVER_IP}" "${WS_TCP_PORT}" \
        >"${WS_EVIDENCE_DIR}/bare_ack_client.log" 2>&1 <<'PYEOF'
import socket
import struct
import sys

src_ip, dst_ip, dst_port = sys.argv[1], sys.argv[2], int(sys.argv[3])
src_port = 54321
seq = 111111
ack = 222222


def checksum(data: bytes) -> int:
    if len(data) % 2:
        data += b"\x00"
    total = sum(struct.unpack("!%dH" % (len(data) // 2), data))
    total = (total >> 16) + (total & 0xFFFF)
    total += total >> 16
    return (~total) & 0xFFFF


def build_tcp(src_ip, dst_ip, src_port, dst_port, seq, ack):
    offset_reserved_flags = (5 << 12) | 0x10  # data offset 5, ACK flag
    header = struct.pack(
        "!HHLLHHHH",
        src_port,
        dst_port,
        seq,
        ack,
        offset_reserved_flags,
        65535,
        0,
        0,
    )
    pseudo = struct.pack(
        "!4s4sBBH",
        socket.inet_aton(src_ip),
        socket.inet_aton(dst_ip),
        0,
        socket.IPPROTO_TCP,
        len(header),
    )
    csum = checksum(pseudo + header)
    header = struct.pack(
        "!HHLLHHHH",
        src_port,
        dst_port,
        seq,
        ack,
        offset_reserved_flags,
        65535,
        csum,
        0,
    )
    return header


def build_ip(src_ip, dst_ip, payload):
    total_len = 20 + len(payload)
    header = struct.pack(
        "!BBHHHBBH4s4s",
        0x45,
        0,
        total_len,
        0,
        0,
        64,
        socket.IPPROTO_TCP,
        0,
        socket.inet_aton(src_ip),
        socket.inet_aton(dst_ip),
    )
    csum = checksum(header)
    header = struct.pack(
        "!BBHHHBBH4s4s",
        0x45,
        0,
        total_len,
        0,
        0,
        64,
        socket.IPPROTO_TCP,
        csum,
        socket.inet_aton(src_ip),
        socket.inet_aton(dst_ip),
    )
    return header + payload


tcp_segment = build_tcp(src_ip, dst_ip, src_port, dst_port, seq, ack)
packet = build_ip(src_ip, dst_ip, tcp_segment)

s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_RAW)
s.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
s.sendto(packet, (dst_ip, dst_port))
print("OK sent bare ACK seq=%d ack=%d" % (seq, ack))
PYEOF
    local client_rc=$?
    sleep 0.2
    ws_capture_stop bare_ack

    [ "${client_rc}" = "0" ] || { ws_log "bare-ACK probe failed, see ${WS_EVIDENCE_DIR}/bare_ack_client.log"; return 1; }
    grep -q "OK sent bare ACK" "${WS_EVIDENCE_DIR}/bare_ack_client.log" || return 1
    # Expect a lone-RST (no ACK flag) whose sequence number equals the
    # incoming ACK number we sent (222222), per docs/tcp.md "Closed-port
    # RST": ACK-set incoming -> reset carries seq=incoming.ack, RST only.
    grep -q "${WS_SERVER_IP}\.${WS_TCP_PORT} > .*Flags \[R\],.*seq 222222" "${WS_EVIDENCE_DIR}/bare_ack.abs.txt" || return 1
    return 0
}

ws_run_test() {
    local name="$1" fn="$2"
    if "${fn}"; then
        ws_pass "${name}"
    else
        ws_fail "${name}"
    fi
}

# ---------------------------------------------------------------------------
# 8. HTTP response timeout retransmission
#
# tc netem loss is applied to WS_HOST_VETH's egress (the wirestack ->
# client direction only). Captures are taken simultaneously at WS_TAP
# (upstream of that qdisc -- shows what wirestack actually transmitted,
# unaffected by whether the egress drop later discards it) and at
# WS_HOST_VETH (downstream -- shows what the client side actually saw).
# ---------------------------------------------------------------------------
ws_test_http_retransmission() {
    ws_capture_start http_retrans_tap "${WS_TAP}"
    ws_capture_start http_retrans_host "${WS_HOST_VETH}"

    local go_file="${WS_EVIDENCE_DIR}/http_retrans_go"
    rm -f "${go_file}"

    ws_in_client python3 - "${WS_SERVER_IP}" "${WS_TCP_PORT}" "${go_file}" \
        >"${WS_EVIDENCE_DIR}/http_retrans_client.log" 2>&1 <<'PYEOF' &
import os
import socket
import sys
import time

server_ip, port, go_file = sys.argv[1], int(sys.argv[2]), sys.argv[3]
expected = b"HTTP/1.0 200 OK\r\nContent-Type: text/plain; charset=utf-8\r\nContent-Length: 21\r\nConnection: close\r\n\r\nHello from Wirestack\n"

s = socket.create_connection((server_ip, port), timeout=5.0)
s.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
print("CONNECTED", flush=True)

# Waits for the harness to apply egress loss before sending the request,
# so the request/response exchange (not the handshake) is what gets lost.
deadline = time.time() + 5.0
while not os.path.exists(go_file):
    if time.time() > deadline:
        print("TIMEOUT waiting for go file")
        sys.exit(1)
    time.sleep(0.01)

s.sendall(b"GET / HTTP/1.0\r\n\r\n")

s.settimeout(6.0)
chunks = []
while True:
    chunk = s.recv(4096)
    if not chunk:
        break
    chunks.append(chunk)
data = b"".join(chunks)
s.close()

if data == expected:
    print("OK body delivered once, %d bytes" % len(data))
else:
    print("MISMATCH got=%r" % data)
    sys.exit(1)
PYEOF
    local client_pid=$!

    local waited=0
    while ! grep -q "^CONNECTED" "${WS_EVIDENCE_DIR}/http_retrans_client.log" 2>/dev/null; do
        kill -0 "${client_pid}" 2>/dev/null || break
        waited=$((waited + 1))
        [ "${waited}" -gt 250 ] && break
        sleep 0.02
    done

    tc qdisc add dev "${WS_HOST_VETH}" root netem loss 100% || return 1
    touch "${go_file}"

    # Give wirestack time to process the request and emit its original
    # (doomed) response before we lift the drop.
    sleep 0.5
    tc qdisc del dev "${WS_HOST_VETH}" root
    wait "${client_pid}"
    local client_rc=$?

    ws_capture_stop http_retrans_tap
    ws_capture_stop http_retrans_host

    [ "${client_rc}" = "0" ] || { ws_log "http retransmission probe failed, see ${WS_EVIDENCE_DIR}/http_retrans_client.log"; return 1; }
    grep -q "^OK body delivered once" "${WS_EVIDENCE_DIR}/http_retrans_client.log" || return 1

    # The TAP capture (upstream of the loss point) must show the response
    # payload sent at least twice with an identical sequence number --
    # the original transmission plus a timeout retransmission carrying
    # the same bytes, not new data.
    local occurrences
    occurrences="$(grep -c "Hello from Wirestack" "${WS_EVIDENCE_DIR}/http_retrans_tap.txt" || true)"
    [ "${occurrences}" -ge 2 ] || { ws_log "expected >=2 occurrences of the response on the wire at ${WS_TAP}, got ${occurrences}"; return 1; }

    # Extract the response segments' absolute sequence numbers directly.
    local seqs
    seqs="$(grep "${WS_SERVER_IP}\.${WS_TCP_PORT} > .*Flags \[P\." "${WS_EVIDENCE_DIR}/http_retrans_tap.abs.txt" | grep -oE 'seq [0-9]+' | awk '{print $2}')"
    local count_seqs distinct_seqs
    count_seqs="$(echo "${seqs}" | grep -c . || true)"
    distinct_seqs="$(echo "${seqs}" | sort -u | grep -c . || true)"
    [ "${count_seqs}" -ge 2 ] || { ws_log "expected >=2 PSH response segments on ${WS_TAP}, got ${count_seqs}"; return 1; }
    [ "${distinct_seqs}" = "1" ] || { ws_log "response retransmission changed sequence number: ${seqs}"; return 1; }

    # The client side must show its cumulative ACK eventually covering
    # the response after the drop is lifted.
    grep -q "${WS_CLIENT_IP}.*> ${WS_SERVER_IP}\.${WS_TCP_PORT}: Flags \[\.\]" "${WS_EVIDENCE_DIR}/http_retrans_host.txt" || return 1
    return 0
}

# ---------------------------------------------------------------------------
# 9. SYN-ACK loss and recovery
#
# Loss is applied on WS_HOST_VETH's egress before the client ever sends a
# SYN, so the first SYN-ACK wirestack emits is guaranteed lost. Capture
# is taken at WS_TAP (shows every SYN-ACK wirestack actually transmits,
# including the one dropped downstream) to distinguish a spontaneous
# timeout retransmission (same stored SYN-ACK, no new client SYN needed)
# from a client-driven retry (docs/tcp.md handshake flow point 2: a
# repeated SYN for an existing SynReceived connection replays the same
# stored SYN-ACK).
# ---------------------------------------------------------------------------
ws_test_synack_loss() {
    local port=8091 # a fresh unique client source port isn't needed; ephemeral
    ws_capture_start synack_loss_tap "${WS_TAP}"
    ws_capture_start synack_loss_host "${WS_HOST_VETH}"

    local loss_start
    loss_start="$(date +%s.%N)"
    tc qdisc add dev "${WS_HOST_VETH}" root netem loss 100% || return 1

    ws_in_client python3 - "${WS_SERVER_IP}" "${WS_TCP_PORT}" \
        >"${WS_EVIDENCE_DIR}/synack_loss_client.log" 2>&1 <<'PYEOF' &
import socket
import sys
import time

server_ip, port = sys.argv[1], int(sys.argv[2])
start = time.time()
s = socket.create_connection((server_ip, port), timeout=8.0)
print("OK connected after %.2fs" % (time.time() - start))
s.close()
PYEOF
    local client_pid=$!

    # Span at least two of wirestack's own 1-second RTO ticks (kInitialRto
    # in include/wirestack/tcp_connection.hpp) while the drop is active.
    sleep 2.5
    local loss_end
    loss_end="$(date +%s.%N)"
    tc qdisc del dev "${WS_HOST_VETH}" root
    wait "${client_pid}"
    local client_rc=$?

    ws_capture_stop synack_loss_tap
    ws_capture_stop synack_loss_host

    [ "${client_rc}" = "0" ] || { ws_log "syn-ack loss probe failed, see ${WS_EVIDENCE_DIR}/synack_loss_client.log"; return 1; }
    grep -q "^OK connected" "${WS_EVIDENCE_DIR}/synack_loss_client.log" || return 1

    # One-line-per-packet traces (no -v/-vv, which wraps a packet across
    # multiple lines and would break the per-line timestamp/flags
    # parsing analyze_synack.py relies on).
    tcpdump -r "${WS_EVIDENCE_DIR}/synack_loss_tap.pcap" -n -tttt -S \
        >"${WS_EVIDENCE_DIR}/synack_loss_tap.oneline.txt" 2>/dev/null || true
    tcpdump -r "${WS_EVIDENCE_DIR}/synack_loss_host.pcap" -n -tttt -S \
        >"${WS_EVIDENCE_DIR}/synack_loss_host.oneline.txt" 2>/dev/null || true

    local analysis
    if ! analysis="$(python3 "${WS_SCRIPT_DIR}/analyze_synack.py" \
            "${WS_EVIDENCE_DIR}/synack_loss_tap.oneline.txt" \
            "${WS_EVIDENCE_DIR}/synack_loss_host.oneline.txt" \
            "${WS_SERVER_IP}" "${WS_TCP_PORT}" "${loss_start}" "${loss_end}" 2>&1)"; then
        ws_log "synack RTO/duplicate-SYN analysis failed:"
        ws_log "${analysis}"
        return 1
    fi
    while IFS= read -r line; do ws_log "${line}"; done <<<"${analysis}"

    grep -q "${WS_CLIENT_IP}.*> ${WS_SERVER_IP}\.${WS_TCP_PORT}: Flags \[\.\]" "${WS_EVIDENCE_DIR}/synack_loss_host.txt" || return 1
    return 0
}

# ---------------------------------------------------------------------------
# 10. Reordering and receiver SACK
#
# netem on the client's own egress (ws-client0) with `gap 2` sends every
# 2nd packet immediately while delaying the others, so segment 2 of a
# 3-segment request overtakes segment 1 -- deterministic reordering, not
# a probabilistic reorder percentage. Captured at WS_TAP (server side).
# ---------------------------------------------------------------------------
ws_test_reordering() {
    ws_capture_start reorder_tap "${WS_TAP}"

    ws_in_client tc qdisc add dev "${WS_CLIENT_VETH}" root netem delay 60ms reorder 100% gap 2 \
        || { ws_capture_stop reorder_tap; return 1; }

    ws_in_client python3 - "${WS_SERVER_IP}" "${WS_TCP_PORT}" \
        >"${WS_EVIDENCE_DIR}/reorder_client.log" 2>&1 <<'PYEOF'
import socket
import sys

server_ip, port = sys.argv[1], int(sys.argv[2])
body_pad = b"a" * 3000
req = b"GET / HTTP/1.0\r\nX-Pad: " + body_pad + b"\r\n\r\n"
expected = b"HTTP/1.0 200 OK\r\nContent-Type: text/plain; charset=utf-8\r\nContent-Length: 21\r\nConnection: close\r\n\r\nHello from Wirestack\n"

s = socket.create_connection((server_ip, port), timeout=5.0)
s.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
s.sendall(req)
s.settimeout(8.0)
chunks = []
while True:
    chunk = s.recv(4096)
    if not chunk:
        break
    chunks.append(chunk)
data = b"".join(chunks)
s.close()

if data == expected:
    print("OK single response, %d bytes, request was %d bytes" % (len(data), len(req)))
else:
    print("MISMATCH got=%r" % data)
    sys.exit(1)
PYEOF
    local client_rc=$?

    ws_in_client tc qdisc del dev "${WS_CLIENT_VETH}" root
    ws_capture_stop reorder_tap

    [ "${client_rc}" = "0" ] || { ws_log "reorder probe failed, see ${WS_EVIDENCE_DIR}/reorder_client.log"; return 1; }
    grep -q "^OK single response" "${WS_EVIDENCE_DIR}/reorder_client.log" || return 1

    # One-line-per-packet, relative-sequence trace (no -v/-vv, no -S):
    # byte offsets read directly from ISN, and each packet's fields stay
    # on a single line for straightforward parsing.
    tcpdump -r "${WS_EVIDENCE_DIR}/reorder_tap.pcap" -n -tttt \
        >"${WS_EVIDENCE_DIR}/reorder_tap.oneline.txt" 2>/dev/null || true

    local analysis
    if ! analysis="$(python3 "${WS_SCRIPT_DIR}/analyze_reorder.py" \
            "${WS_EVIDENCE_DIR}/reorder_tap.oneline.txt" \
            "${WS_CLIENT_IP}" "${WS_SERVER_IP}" "${WS_TCP_PORT}" 2>&1)"; then
        ws_log "reorder/SACK analysis failed:"
        ws_log "${analysis}"
        return 1
    fi
    while IFS= read -r line; do ws_log "${line}"; done <<<"${analysis}"

    return 0
}

ws_run_test "arp"               ws_test_arp
ws_run_test "icmp"              ws_test_icmp
ws_run_test "udp"               ws_test_udp
ws_run_test "tcp_handshake"     ws_test_tcp_handshake
ws_run_test "http"              ws_test_http
ws_run_test "closed_port_reset" ws_test_closed_port_reset
ws_run_test "bare_ack_reset"    ws_test_bare_ack_reset
ws_run_test "http_retransmission" ws_test_http_retransmission
ws_run_test "synack_loss"       ws_test_synack_loss
ws_run_test "reordering"        ws_test_reordering

ws_log "test failures: ${WS_TEST_FAILURES}"
[ "${WS_TEST_FAILURES}" = "0" ]
