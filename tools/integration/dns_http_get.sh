#!/usr/bin/env bash
# DNS A-record resolution interoperability scenarios (Milestone 18):
# Wirestack resolving a hostname (--http-get/--dns-server/--source-port/
# --target) through a real Python UDP DNS server in the client namespace,
# then completing an outbound HTTP/1.0 GET against a real Python HTTP/1.0
# server at the resolved address -- same one-shot-connection restart
# pattern as http_get.sh (--http-get configures a single attempt at
# process startup).
#
# Must run inside the same sandbox as run.sh/active_open.sh/http_get.sh:
#
#   unshare --user --net --map-root-user -- bash tools/integration/dns_http_get.sh
#
# Reuses the same topology (tools/integration/setup.sh) and the same
# process-identity-verified cleanup (tools/integration/cleanup.sh) as the
# other scenario scripts -- no new harness machinery.

set -euo pipefail

WS_SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
export WS_INTEGRATION_SOURCED=1
# shellcheck source=./common.sh
. "${WS_SCRIPT_DIR}/common.sh"
# shellcheck source=./setup.sh
. "${WS_SCRIPT_DIR}/setup.sh"
# shellcheck source=./cleanup.sh
. "${WS_SCRIPT_DIR}/cleanup.sh"

WS_DNS_PORT=5353
WS_HOSTNAME="wirestack.test"
# Distinct HTTP/TCP-source ports per scenario that opens a real TCP
# connection (success, retry) -- reusing one four-tuple back-to-back
# across restarted wirestack processes leaves stale kernel socket state
# in the client namespace from the previous scenario, exactly like
# http_get.sh's WS_CL_PORT/WS_CL_CLOSE_PORT split.
WS_SUCCESS_HTTP_PORT=9094
WS_SUCCESS_SRC_PORT=49300
WS_RETRY_HTTP_PORT=9095
WS_RETRY_SRC_PORT=49301
WS_NXDOMAIN_HTTP_PORT=9096
WS_NXDOMAIN_SRC_PORT=49302

ws_check_dependencies
ws_check_privileges
ws_make_evidence_dir

WS_CLEANED_UP=0
ws_on_exit() {
    local status=$?
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

ws_log "evidence directory: ${WS_EVIDENCE_DIR}"

ws_setup_topology

ws_restart_wirestack_dns() {
    local http_port="$1" src_port="$2"
    if [ -f "${WS_EVIDENCE_DIR}/${WS_WIRESTACK_PIDFILE_NAME}" ]; then
        ws_cleanup_kill_recorded "${WS_EVIDENCE_DIR}/${WS_WIRESTACK_PIDFILE_NAME}" "wirestack"
        ws_cleanup_delete_link "${WS_TAP}" tap
    fi
    ws_start_wirestack --http-get "${WS_HOSTNAME}:${http_port}" \
        --dns-server "${WS_CLIENT_IP}:${WS_DNS_PORT}" --source-port "${src_port}" --target "/"
}

ws_prime_arp() {
    ws_in_client ping -c 1 -W 2 -I "${WS_CLIENT_VETH}" "${WS_SERVER_IP}" \
        >"${WS_EVIDENCE_DIR}/dns_http_get_arp_prime.log" 2>&1 || true
}

# `mode`: "success" answers the first query; "drop_then_answer" drops the
# first query and answers the second (byte-identical retry); "nxdomain"
# answers the first query with RCODE=3. The response's transaction ID and
# question section are copied byte-for-byte from the received query
# rather than reconstructed, so this server's own correctness never
# depends on independently re-encoding DNS names -- only Wirestack's own
# query encoding and response parsing are under test.
WS_DNS_SERVER_PY='
import socket
import struct
import sys

ip, port, mode = sys.argv[1], int(sys.argv[2]), sys.argv[3]

s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
s.bind((ip, port))
print("LISTENING", flush=True)


def build_response(query, rcode, with_answer):
    txid = query[0:2]
    flags_hi = 0x80  # QR=1, Opcode=0, AA=0, TC=0, RD=0
    flags_lo = rcode & 0x0F
    ancount = 1 if with_answer else 0
    header = txid + bytes([flags_hi, flags_lo]) + struct.pack(">HHHH", 1, ancount, 0, 0)
    question = query[12:]  # QNAME + QTYPE + QCLASS, copied verbatim
    body = header + question
    if with_answer:
        rdata = socket.inet_aton("10.0.0.1")
        body += b"\xc0\x0c" + struct.pack(">HH", 1, 1) + struct.pack(">I", 60) + \
            struct.pack(">H", 4) + rdata
    return body


seen = 0
s.settimeout(20.0)
while True:
    data, addr = s.recvfrom(512)
    seen += 1
    print(f"QUERY {seen} txid={data[0:2].hex()} bytes={data.hex()}", flush=True)
    if mode == "success":
        s.sendto(build_response(data, 0, True), addr)
        print("ANSWERED", flush=True)
        break
    elif mode == "drop_then_answer":
        if seen == 1:
            print("DROPPED", flush=True)
            continue
        s.sendto(build_response(data, 0, True), addr)
        print("ANSWERED", flush=True)
        break
    elif mode == "nxdomain":
        s.sendto(build_response(data, 3, False), addr)
        print("ANSWERED_NXDOMAIN", flush=True)
        break
print("DONE", flush=True)
'

WS_HTTP_SERVER_PY='
import socket
import sys

ip, port, host_header = sys.argv[1], int(sys.argv[2]), sys.argv[3]
body = b"Hello from Linux HTTP server\n"
expected = (
    b"GET / HTTP/1.0\r\nHost: " + host_header.encode() + b"\r\nConnection: close\r\n\r\n"
)

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
s.bind((ip, port))
s.listen(1)
print("LISTENING", flush=True)
s.settimeout(15.0)
conn, addr = s.accept()
print("ACCEPTED", addr, flush=True)
conn.settimeout(15.0)
request = b""
while b"\r\n\r\n" not in request:
    chunk = conn.recv(4096)
    if not chunk:
        break
    request += chunk
print("REQUEST_BYTES", len(request), flush=True)
if request == expected:
    print("REQUEST_EXACT_MATCH", flush=True)
response = b"HTTP/1.0 200 OK\r\nContent-Length: " + str(len(body)).encode() + b"\r\n\r\n" + body
conn.sendall(response)
conn.close()
s.close()
print("CLOSED", flush=True)
'

ws_start_dns_server() {
    local mode="$1" log="$2" pidfile="$3"
    ws_in_client python3 - "${WS_CLIENT_IP}" "${WS_DNS_PORT}" "${mode}" \
        >"${log}" 2>&1 <<<"${WS_DNS_SERVER_PY}" &
    local pid=$!
    echo "${pid}" >"${pidfile}"
    ws_record_identity "${pid}" "${pidfile}" python3
    local waited=0
    while ! grep -q "^LISTENING" "${log}" 2>/dev/null; do
        kill -0 "${pid}" 2>/dev/null || { ws_log "DNS server exited before LISTENING, see ${log}"; return 1; }
        waited=$((waited + 1))
        [ "${waited}" -gt 250 ] && { ws_log "timed out waiting for DNS server to report LISTENING"; return 1; }
        sleep 0.02
    done
    echo "${pid}"
}

ws_start_http_server() {
    local port="$1" host_header="$2" log="$3" pidfile="$4"
    ws_in_client python3 - "${WS_CLIENT_IP}" "${port}" "${host_header}" \
        >"${log}" 2>&1 <<<"${WS_HTTP_SERVER_PY}" &
    local pid=$!
    echo "${pid}" >"${pidfile}"
    ws_record_identity "${pid}" "${pidfile}" python3
    local waited=0
    while ! grep -q "^LISTENING" "${log}" 2>/dev/null; do
        kill -0 "${pid}" 2>/dev/null || { ws_log "HTTP server exited before LISTENING, see ${log}"; return 1; }
        waited=$((waited + 1))
        [ "${waited}" -gt 250 ] && { ws_log "timed out waiting for HTTP server to report LISTENING"; return 1; }
        sleep 0.02
    done
}

# ---------------------------------------------------------------------------
# 1. Success: DNS answers the first query; Wirestack resolves, connects,
#    and completes exactly one HTTP GET.
# ---------------------------------------------------------------------------
ws_test_dns_success() {
    ws_restart_wirestack_dns "${WS_SUCCESS_HTTP_PORT}" "${WS_SUCCESS_SRC_PORT}"

    local dns_log="${WS_EVIDENCE_DIR}/dns_success_server.log"
    local dns_pidfile="${WS_EVIDENCE_DIR}/dns_success_server.pid"
    ws_start_dns_server success "${dns_log}" "${dns_pidfile}" >/dev/null || return 1

    local http_log="${WS_EVIDENCE_DIR}/dns_success_http.log"
    local http_pidfile="${WS_EVIDENCE_DIR}/dns_success_http.pid"
    ws_start_http_server "${WS_SUCCESS_HTTP_PORT}" "${WS_HOSTNAME}:${WS_SUCCESS_HTTP_PORT}" \
        "${http_log}" "${http_pidfile}" || return 1

    ws_capture_start dns_success "${WS_HOST_VETH}"
    ws_prime_arp

    local waited=0
    while ! grep -q "^CLOSED" "${http_log}" 2>/dev/null; do
        kill -0 "$(cat "${dns_pidfile}")" 2>/dev/null || true
        waited=$((waited + 1))
        [ "${waited}" -gt 1000 ] && { ws_log "timed out waiting for HTTP server to close"; ws_capture_stop dns_success; return 1; }
        sleep 0.02
    done
    sleep 0.5
    ws_capture_stop dns_success

    grep -q "^ANSWERED$" "${dns_log}" || { ws_log "DNS server never answered"; return 1; }
    local query_count
    query_count="$(grep -c "^QUERY " "${dns_log}" || true)"
    [ "${query_count}" = "1" ] || { ws_log "expected exactly 1 DNS query, got ${query_count}"; return 1; }

    grep -q "^ACCEPTED" "${http_log}" || { ws_log "HTTP server never accepted a connection"; return 1; }
    grep -q "^REQUEST_EXACT_MATCH" "${http_log}" || { ws_log "HTTP server did not receive the exact expected GET (Host: ${WS_HOSTNAME}:${WS_SUCCESS_HTTP_PORT})"; return 1; }

    local wirestack_log="${WS_EVIDENCE_DIR}/wirestack.out"
    grep -q "^dns-client: resolved ${WS_HOSTNAME} -> ${WS_CLIENT_IP}$" "${wirestack_log}" || {
        ws_log "wirestack did not log a successful DNS resolution"; return 1
    }
    local completion_count
    completion_count="$(grep -c "^http-client: response complete status=200 body_len=29$" "${wirestack_log}" || true)"
    [ "${completion_count}" = "1" ] || { ws_log "expected exactly 1 HTTP completion, got ${completion_count}"; return 1; }
    grep -q "^http-client: response rejected" "${wirestack_log}" && { ws_log "wirestack rejected the response"; return 1; }

    # TCP SYN must not appear before the DNS answer on the wire.
    local dns_line_no syn_line_no
    dns_line_no="$(grep -n "${WS_CLIENT_IP}\.${WS_DNS_PORT} > ${WS_SERVER_IP}\." "${WS_EVIDENCE_DIR}/dns_success.abs.txt" | head -1 | cut -d: -f1)"
    syn_line_no="$(grep -n "${WS_SERVER_IP}\.${WS_SUCCESS_SRC_PORT} > ${WS_CLIENT_IP}\.${WS_SUCCESS_HTTP_PORT}: Flags \[S\]" "${WS_EVIDENCE_DIR}/dns_success.abs.txt" | head -1 | cut -d: -f1)"
    [ -n "${dns_line_no}" ] || { ws_log "no DNS response observed on the wire"; return 1; }
    [ -n "${syn_line_no}" ] || { ws_log "no TCP SYN observed on the wire"; return 1; }
    [ "${dns_line_no}" -lt "${syn_line_no}" ] || { ws_log "TCP SYN appeared before the DNS response"; return 1; }

    grep -qi "bad cksum" "${WS_EVIDENCE_DIR}/dns_success.abs.txt" && { ws_log "bad checksum observed"; return 1; }
    grep -q "${WS_CLIENT_IP}\.${WS_SUCCESS_HTTP_PORT} > .*Flags \[R" "${WS_EVIDENCE_DIR}/dns_success.abs.txt" && { ws_log "unexpected RST observed"; return 1; }

    return 0
}

# ---------------------------------------------------------------------------
# 2. Dropped first query: DNS drops query 1, answers query 2 -- proves
#    byte-identical retry, no SYN before the reply, exactly one connection.
# ---------------------------------------------------------------------------
ws_test_dns_retry() {
    ws_restart_wirestack_dns "${WS_RETRY_HTTP_PORT}" "${WS_RETRY_SRC_PORT}"

    local dns_log="${WS_EVIDENCE_DIR}/dns_retry_server.log"
    local dns_pidfile="${WS_EVIDENCE_DIR}/dns_retry_server.pid"
    ws_start_dns_server drop_then_answer "${dns_log}" "${dns_pidfile}" >/dev/null || return 1

    local http_log="${WS_EVIDENCE_DIR}/dns_retry_http.log"
    local http_pidfile="${WS_EVIDENCE_DIR}/dns_retry_http.pid"
    ws_start_http_server "${WS_RETRY_HTTP_PORT}" "${WS_HOSTNAME}:${WS_RETRY_HTTP_PORT}" \
        "${http_log}" "${http_pidfile}" || return 1

    ws_capture_start dns_retry "${WS_HOST_VETH}"
    ws_prime_arp

    # The retry fires at t=1s (kDnsInitialInterval, docs/dns.md); allow
    # generous wall-clock slack for a loaded scheduler.
    local waited=0
    while ! grep -q "^CLOSED" "${http_log}" 2>/dev/null; do
        waited=$((waited + 1))
        [ "${waited}" -gt 1500 ] && { ws_log "timed out waiting for HTTP server to close"; ws_capture_stop dns_retry; return 1; }
        sleep 0.02
    done
    sleep 0.5
    ws_capture_stop dns_retry

    local query_count
    query_count="$(grep -c "^QUERY " "${dns_log}" || true)"
    [ "${query_count}" = "2" ] || { ws_log "expected exactly 2 DNS queries, got ${query_count}"; return 1; }

    local txid1 txid2
    txid1="$(grep "^QUERY 1 " "${dns_log}" | grep -oP '(?<=txid=)[0-9a-f]+')"
    txid2="$(grep "^QUERY 2 " "${dns_log}" | grep -oP '(?<=txid=)[0-9a-f]+')"
    [ -n "${txid1}" ] && [ "${txid1}" = "${txid2}" ] || { ws_log "transaction ID differs between the two queries (${txid1} vs ${txid2})"; return 1; }

    local bytes1 bytes2
    bytes1="$(grep "^QUERY 1 " "${dns_log}" | grep -oP '(?<=bytes=)[0-9a-f]+')"
    bytes2="$(grep "^QUERY 2 " "${dns_log}" | grep -oP '(?<=bytes=)[0-9a-f]+')"
    [ -n "${bytes1}" ] && [ "${bytes1}" = "${bytes2}" ] || { ws_log "query payload not byte-identical on retry"; return 1; }

    grep -q "^ACCEPTED" "${http_log}" || { ws_log "HTTP server never accepted a connection"; return 1; }
    local completion_count
    completion_count="$(grep -c "^http-client: response complete status=200 body_len=29$" "${WS_EVIDENCE_DIR}/wirestack.out" || true)"
    [ "${completion_count}" = "1" ] || { ws_log "expected exactly 1 HTTP completion, got ${completion_count}"; return 1; }

    local syn_count
    syn_count="$(grep -c "${WS_SERVER_IP}\.${WS_RETRY_SRC_PORT} > ${WS_CLIENT_IP}\.${WS_RETRY_HTTP_PORT}: Flags \[S\]" "${WS_EVIDENCE_DIR}/dns_retry.abs.txt" || true)"
    [ "${syn_count}" = "1" ] || { ws_log "expected exactly 1 TCP SYN, got ${syn_count}"; return 1; }

    return 0
}

# ---------------------------------------------------------------------------
# 3. NXDOMAIN: DNS answers with RCODE=3 -- exactly one failure log, no
#    retries, no TCP SYN, no HTTP request.
# ---------------------------------------------------------------------------
ws_test_dns_nxdomain() {
    ws_restart_wirestack_dns "${WS_NXDOMAIN_HTTP_PORT}" "${WS_NXDOMAIN_SRC_PORT}"

    local dns_log="${WS_EVIDENCE_DIR}/dns_nxdomain_server.log"
    local dns_pidfile="${WS_EVIDENCE_DIR}/dns_nxdomain_server.pid"
    ws_start_dns_server nxdomain "${dns_log}" "${dns_pidfile}" >/dev/null || return 1

    ws_capture_start dns_nxdomain "${WS_HOST_VETH}"
    ws_prime_arp

    local wirestack_log="${WS_EVIDENCE_DIR}/wirestack.out"
    local waited=0
    while ! grep -q "^dns-client: resolution failed host=${WS_HOSTNAME} reason=NXDOMAIN$" "${wirestack_log}" 2>/dev/null; do
        waited=$((waited + 1))
        [ "${waited}" -gt 500 ] && { ws_log "timed out waiting for wirestack's NXDOMAIN failure log"; ws_capture_stop dns_nxdomain; return 1; }
        sleep 0.02
    done
    # No further activity is expected; wait a little longer to prove no
    # retry, no SYN, and no HTTP request ever follow.
    sleep 2
    ws_capture_stop dns_nxdomain

    local query_count
    query_count="$(grep -c "^QUERY " "${dns_log}" || true)"
    [ "${query_count}" = "1" ] || { ws_log "expected exactly 1 DNS query (no retries after NXDOMAIN), got ${query_count}"; return 1; }

    local failure_count
    failure_count="$(grep -c "^dns-client: resolution failed host=${WS_HOSTNAME} reason=NXDOMAIN$" "${wirestack_log}" || true)"
    [ "${failure_count}" = "1" ] || { ws_log "expected exactly 1 NXDOMAIN failure log, got ${failure_count}"; return 1; }

    grep -q "^tcp: active open started" "${wirestack_log}" && { ws_log "wirestack started a TCP connection after NXDOMAIN"; return 1; }
    grep -q "Flags \[S\]" "${WS_EVIDENCE_DIR}/dns_nxdomain.abs.txt" && { ws_log "a TCP SYN appeared on the wire after NXDOMAIN"; return 1; }
    grep -q "^http-client:" "${wirestack_log}" && { ws_log "wirestack attempted an HTTP request after NXDOMAIN"; return 1; }

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

ws_run_test "dns_success" ws_test_dns_success
ws_run_test "dns_retry" ws_test_dns_retry
ws_run_test "dns_nxdomain" ws_test_dns_nxdomain

ws_log "test failures: ${WS_TEST_FAILURES}"
[ "${WS_TEST_FAILURES}" = "0" ]
