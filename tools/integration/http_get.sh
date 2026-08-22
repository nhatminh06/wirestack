#!/usr/bin/env bash
# Outbound HTTP/1.0 client interoperability scenarios: Wirestack actively
# opening a connection (--http-get/--source-port/--target) and sending one
# GET request against a real Python HTTP/1.0 server running in the client
# namespace. Kept separate from run.sh/active_open.sh for the same reason
# active_open.sh is separate: --http-get configures a single one-shot
# connection attempt at process startup, so each scenario restarts the
# wirestack process.
#
# Must run inside the same sandbox as run.sh/active_open.sh:
#
#   unshare --user --net --map-root-user -- bash tools/integration/http_get.sh
#
# Reuses the same topology (tools/integration/setup.sh) and the same
# process-identity-verified cleanup (tools/integration/cleanup.sh) as
# run.sh/active_open.sh.

set -euo pipefail

WS_SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
export WS_INTEGRATION_SOURCED=1
# shellcheck source=./common.sh
. "${WS_SCRIPT_DIR}/common.sh"
# shellcheck source=./setup.sh
. "${WS_SCRIPT_DIR}/setup.sh"
# shellcheck source=./cleanup.sh
. "${WS_SCRIPT_DIR}/cleanup.sh"

WS_CL_PORT=9092
WS_CL_SRC_PORT=49300
WS_CL_CLOSE_PORT=9093
WS_CL_CLOSE_SRC_PORT=49301

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

ws_restart_wirestack_http_get() {
    local remote_ip="$1" remote_port="$2" source_port="$3" target="$4"
    if [ -f "${WS_EVIDENCE_DIR}/${WS_WIRESTACK_PIDFILE_NAME}" ]; then
        ws_cleanup_kill_recorded "${WS_EVIDENCE_DIR}/${WS_WIRESTACK_PIDFILE_NAME}" "wirestack"
        ws_cleanup_delete_link "${WS_TAP}" tap
    fi
    ws_start_wirestack --http-get "${remote_ip}:${remote_port}" --source-port "${source_port}" \
        --target "${target}"
}

ws_prime_arp() {
    ws_in_client ping -c 1 -W 2 -I "${WS_CLIENT_VETH}" "${WS_SERVER_IP}" \
        >"${WS_EVIDENCE_DIR}/http_get_arp_prime.log" 2>&1 || true
}

ws_extract_field() {
    local line="$1" field="$2"
    printf '%s\n' "${line}" | grep -oP "(?<=${field} )[0-9]+" | head -1
}

# ---------------------------------------------------------------------------
# 1. GET against a real Linux HTTP/1.0 server, Content-Length-delimited
#    response.
# ---------------------------------------------------------------------------
ws_test_http_get_content_length() {
    ws_restart_wirestack_http_get "${WS_CLIENT_IP}" "${WS_CL_PORT}" "${WS_CL_SRC_PORT}" "/"

    local pidfile="${WS_EVIDENCE_DIR}/http_get_cl_server.pid"
    local log="${WS_EVIDENCE_DIR}/http_get_cl_server.log"
    ws_in_client python3 - "${WS_CLIENT_IP}" "${WS_CL_PORT}" \
        >"${log}" 2>&1 <<'PYEOF_SERVER' &
import socket
import sys

ip = sys.argv[1]
port = int(sys.argv[2])
body = b"Hello from Linux HTTP server\n"

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
s.bind((ip, port))
s.listen(1)
print("LISTENING", flush=True)
s.settimeout(10.0)
conn, addr = s.accept()
print("ACCEPTED", addr, flush=True)
conn.settimeout(10.0)
request = b""
while b"\r\n\r\n" not in request:
    chunk = conn.recv(4096)
    if not chunk:
        break
    request += chunk
print("REQUEST_BYTES", len(request), flush=True)
if request == b"GET / HTTP/1.0\r\nHost: 10.0.0.1:9092\r\nConnection: close\r\n\r\n":
    print("REQUEST_EXACT_MATCH", flush=True)
response = (
    b"HTTP/1.0 200 OK\r\n"
    b"Content-Length: " + str(len(body)).encode() + b"\r\n"
    b"\r\n" + body
)
conn.sendall(response)
conn.close()
s.close()
print("CLOSED", flush=True)
PYEOF_SERVER
    local server_pid=$!
    echo "${server_pid}" >"${pidfile}"
    ws_record_identity "${server_pid}" "${pidfile}" python3

    local waited=0
    while ! grep -q "^LISTENING" "${log}" 2>/dev/null; do
        kill -0 "${server_pid}" 2>/dev/null || { ws_log "server exited before LISTENING, see ${log}"; return 1; }
        waited=$((waited + 1))
        [ "${waited}" -gt 250 ] && { ws_log "timed out waiting for server to report LISTENING"; return 1; }
        sleep 0.02
    done

    ws_capture_start http_get_cl "${WS_HOST_VETH}"
    ws_prime_arp

    waited=0
    while ! grep -q "^CLOSED" "${log}" 2>/dev/null; do
        kill -0 "${server_pid}" 2>/dev/null || { ws_log "server exited before CLOSED, see ${log}"; ws_capture_stop http_get_cl; return 1; }
        waited=$((waited + 1))
        [ "${waited}" -gt 500 ] && { ws_log "timed out waiting for server to close"; ws_capture_stop http_get_cl; return 1; }
        sleep 0.02
    done
    sleep 0.5
    ws_capture_stop http_get_cl

    grep -q "^ACCEPTED" "${log}" || { ws_log "server never accepted a connection"; return 1; }
    # The exact request bytes are verified application-side by the real
    # Python server (REQUEST_EXACT_MATCH above) -- authoritative, since
    # tcpdump's own HTTP dissector only recognizes a handful of built-in
    # "well-known" ports and silently prints no decoded text for this
    # scenario's port (9092), unlike run.sh's port-8080 HTTP scenarios.
    # The wire capture instead proves exactly one PSH-carrying segment
    # left Wirestack for the server (one logical request, not zero, not
    # duplicated by retransmission-as-new-data) and exactly one PSH
    # segment came back (one response, not a second/pipelined one).
    grep -q "^REQUEST_EXACT_MATCH" "${log}" || { ws_log "server did not receive the exact expected GET request"; return 1; }

    local get_psh_count response_psh_count
    get_psh_count="$(grep -c "${WS_SERVER_IP}\.${WS_CL_SRC_PORT} > ${WS_CLIENT_IP}\.${WS_CL_PORT}: Flags \[P" "${WS_EVIDENCE_DIR}/http_get_cl.abs.txt" || true)"
    [ "${get_psh_count}" = "1" ] || { ws_log "expected exactly 1 GET request segment on the wire, got ${get_psh_count}"; return 1; }
    response_psh_count="$(grep -c "${WS_CLIENT_IP}\.${WS_CL_PORT} > ${WS_SERVER_IP}\.${WS_CL_SRC_PORT}: Flags \[P" "${WS_EVIDENCE_DIR}/http_get_cl.abs.txt" || true)"
    [ "${response_psh_count}" = "1" ] || { ws_log "expected exactly 1 response segment on the wire, got ${response_psh_count}"; return 1; }

    grep -qi "bad cksum" "${WS_EVIDENCE_DIR}/http_get_cl.abs.txt" && { ws_log "bad checksum observed"; return 1; }
    grep -q "${WS_CLIENT_IP}\.${WS_CL_PORT} > .*Flags \[R" "${WS_EVIDENCE_DIR}/http_get_cl.abs.txt" && { ws_log "unexpected RST from server"; return 1; }

    local syn_line synack_line
    syn_line="$(grep "${WS_SERVER_IP}\.${WS_CL_SRC_PORT} > ${WS_CLIENT_IP}\.${WS_CL_PORT}: Flags \[S\]" "${WS_EVIDENCE_DIR}/http_get_cl.abs.txt" | head -1)"
    synack_line="$(grep "${WS_CLIENT_IP}\.${WS_CL_PORT} > ${WS_SERVER_IP}\.${WS_CL_SRC_PORT}: Flags \[S\.\]" "${WS_EVIDENCE_DIR}/http_get_cl.abs.txt" | head -1)"
    [ -n "${syn_line}" ] || { ws_log "no outbound SYN found"; return 1; }
    [ -n "${synack_line}" ] || { ws_log "no SYN-ACK from server found"; return 1; }

    ws_log "SYN:     ${syn_line}"
    ws_log "SYN-ACK: ${synack_line}"

    return 0
}

# ---------------------------------------------------------------------------
# 2. GET against a real Linux HTTP/1.0 server, close-delimited response
#    (no Content-Length -- the server closes the connection to signal the
#    end of the body).
# ---------------------------------------------------------------------------
ws_test_http_get_close_delimited() {
    ws_restart_wirestack_http_get "${WS_CLIENT_IP}" "${WS_CL_CLOSE_PORT}" "${WS_CL_CLOSE_SRC_PORT}" "/health"

    local pidfile="${WS_EVIDENCE_DIR}/http_get_close_server.pid"
    local log="${WS_EVIDENCE_DIR}/http_get_close_server.log"
    ws_in_client python3 - "${WS_CLIENT_IP}" "${WS_CL_CLOSE_PORT}" \
        >"${log}" 2>&1 <<'PYEOF_SERVER' &
import socket
import sys

ip = sys.argv[1]
port = int(sys.argv[2])
body = b"close-delimited body\n"

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
s.bind((ip, port))
s.listen(1)
print("LISTENING", flush=True)
s.settimeout(10.0)
conn, addr = s.accept()
print("ACCEPTED", addr, flush=True)
conn.settimeout(10.0)
request = b""
while b"\r\n\r\n" not in request:
    chunk = conn.recv(4096)
    if not chunk:
        break
    request += chunk
print("REQUEST_BYTES", len(request), flush=True)
if request == b"GET /health HTTP/1.0\r\nHost: 10.0.0.1:9093\r\nConnection: close\r\n\r\n":
    print("REQUEST_EXACT_MATCH", flush=True)
response = b"HTTP/1.0 200 OK\r\n\r\n" + body
conn.sendall(response)
conn.shutdown(socket.SHUT_WR)
conn.close()
s.close()
print("CLOSED", flush=True)
PYEOF_SERVER
    local server_pid=$!
    echo "${server_pid}" >"${pidfile}"
    ws_record_identity "${server_pid}" "${pidfile}" python3

    local waited=0
    while ! grep -q "^LISTENING" "${log}" 2>/dev/null; do
        kill -0 "${server_pid}" 2>/dev/null || { ws_log "server exited before LISTENING, see ${log}"; return 1; }
        waited=$((waited + 1))
        [ "${waited}" -gt 250 ] && { ws_log "timed out waiting for server to report LISTENING"; return 1; }
        sleep 0.02
    done

    ws_capture_start http_get_close "${WS_HOST_VETH}"
    ws_prime_arp

    waited=0
    while ! grep -q "^CLOSED" "${log}" 2>/dev/null; do
        kill -0 "${server_pid}" 2>/dev/null || { ws_log "server exited before CLOSED, see ${log}"; ws_capture_stop http_get_close; return 1; }
        waited=$((waited + 1))
        [ "${waited}" -gt 500 ] && { ws_log "timed out waiting for server to close"; ws_capture_stop http_get_close; return 1; }
        sleep 0.02
    done
    sleep 0.5
    ws_capture_stop http_get_close

    grep -q "^ACCEPTED" "${log}" || { ws_log "server never accepted a connection"; return 1; }
    # See the matching comment in ws_test_http_get_content_length: exact
    # bytes are verified application-side (REQUEST_EXACT_MATCH); tcpdump's
    # HTTP dissector does not recognize this non-well-known port, so the
    # wire capture instead proves exactly one PSH segment in each
    # direction.
    grep -q "^REQUEST_EXACT_MATCH" "${log}" || { ws_log "server did not receive the exact expected GET request"; return 1; }

    local get_psh_count response_psh_count
    get_psh_count="$(grep -c "${WS_SERVER_IP}\.${WS_CL_CLOSE_SRC_PORT} > ${WS_CLIENT_IP}\.${WS_CL_CLOSE_PORT}: Flags \[P" "${WS_EVIDENCE_DIR}/http_get_close.abs.txt" || true)"
    [ "${get_psh_count}" = "1" ] || { ws_log "expected exactly 1 GET request segment on the wire, got ${get_psh_count}"; return 1; }
    response_psh_count="$(grep -c "${WS_CLIENT_IP}\.${WS_CL_CLOSE_PORT} > ${WS_SERVER_IP}\.${WS_CL_CLOSE_SRC_PORT}: Flags \[P" "${WS_EVIDENCE_DIR}/http_get_close.abs.txt" || true)"
    [ "${response_psh_count}" = "1" ] || { ws_log "expected exactly 1 response segment on the wire, got ${response_psh_count}"; return 1; }

    local fin_from_server
    fin_from_server="$(grep -c "${WS_CLIENT_IP}\.${WS_CL_CLOSE_PORT} > .*Flags \[F" "${WS_EVIDENCE_DIR}/http_get_close.abs.txt" || true)"
    [ "${fin_from_server}" -ge "1" ] || { ws_log "no FIN observed from the close-delimited server"; return 1; }

    local fin_from_wirestack
    fin_from_wirestack="$(grep -c "${WS_SERVER_IP}\.${WS_CL_CLOSE_SRC_PORT} > .*Flags \[F" "${WS_EVIDENCE_DIR}/http_get_close.abs.txt" || true)"
    [ "${fin_from_wirestack}" -ge "1" ] || { ws_log "wirestack never sent its own FIN to close cleanly"; return 1; }

    grep -qi "bad cksum" "${WS_EVIDENCE_DIR}/http_get_close.abs.txt" && { ws_log "bad checksum observed"; return 1; }

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

ws_run_test "http_get_content_length" ws_test_http_get_content_length
ws_run_test "http_get_close_delimited" ws_test_http_get_close_delimited

ws_log "test failures: ${WS_TEST_FAILURES}"
[ "${WS_TEST_FAILURES}" = "0" ]
