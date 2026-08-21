#!/usr/bin/env bash
# TCP active-open interoperability scenarios: Wirestack initiating a
# connection (the --active-open/--source-port flags) against a real
# Linux TCP listener, and against a closed port. Kept separate from
# run.sh because --active-open configures a single one-shot connection
# attempt at process startup -- exercising it means restarting the
# wirestack process with different flags per scenario, which would
# complicate the single long-lived passive-open server instance run.sh's
# ten scenarios already rely on.
#
# Must run inside the same sandbox as run.sh:
#
#   unshare --user --net --map-root-user -- bash tools/integration/active_open.sh
#
# Reuses the same topology (tools/integration/setup.sh) and the same
# process-identity-verified cleanup (tools/integration/cleanup.sh) as
# run.sh. Wirestack never sends an ARP request of its own (see
# docs/tcp.md); each scenario primes Wirestack's ARP cache first with a
# single ping from the client to Wirestack, which Wirestack learns the
# sender's MAC from opportunistically (any inbound IPv4 packet, not just
# ARP -- see arp_cache.insert in handleIpv4, src/main.cpp).

set -euo pipefail

WS_SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
export WS_INTEGRATION_SOURCED=1
# shellcheck source=./common.sh
. "${WS_SCRIPT_DIR}/common.sh"
# shellcheck source=./setup.sh
. "${WS_SCRIPT_DIR}/setup.sh"
# shellcheck source=./cleanup.sh
. "${WS_SCRIPT_DIR}/cleanup.sh"

WS_LISTEN_PORT=9090
WS_REFUSED_PORT=9091
WS_ACTIVE_SRC_PORT=49200
WS_REFUSED_SRC_PORT=49201

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

# Kills any wirestack instance this run already started and removes the
# TAP device, then starts a fresh instance with --active-open pointed at
# remote_ip:remote_port. Needed because --active-open only attempts its
# one connection once, at a fixed target chosen at startup.
ws_restart_wirestack_active_open() {
    local remote_ip="$1" remote_port="$2" source_port="$3"
    if [ -f "${WS_EVIDENCE_DIR}/${WS_WIRESTACK_PIDFILE_NAME}" ]; then
        ws_cleanup_kill_recorded "${WS_EVIDENCE_DIR}/${WS_WIRESTACK_PIDFILE_NAME}" "wirestack"
        ws_cleanup_delete_link "${WS_TAP}" tap
    fi
    ws_start_wirestack --active-open "${remote_ip}:${remote_port}" --source-port "${source_port}"
}

ws_prime_arp() {
    ws_in_client ping -c 1 -W 2 -I "${WS_CLIENT_VETH}" "${WS_SERVER_IP}" \
        >"${WS_EVIDENCE_DIR}/active_open_arp_prime.log" 2>&1 || true
}

# Extracts an unsigned decimal field (seq/ack) that immediately follows
# `field` in a tcpdump -vv -S line, e.g. "seq 12345," -> 12345.
ws_extract_field() {
    local line="$1" field="$2"
    printf '%s\n' "${line}" | grep -oP "(?<=${field} )[0-9]+" | head -1
}

# ---------------------------------------------------------------------------
# 1. Active open against a real Linux listener: full three-way handshake
#    initiated by Wirestack, accepted by a real accept() call.
# ---------------------------------------------------------------------------
ws_test_active_open_established() {
    ws_restart_wirestack_active_open "${WS_CLIENT_IP}" "${WS_LISTEN_PORT}" "${WS_ACTIVE_SRC_PORT}"

    local pidfile="${WS_EVIDENCE_DIR}/active_open_listener.pid"
    local log="${WS_EVIDENCE_DIR}/active_open_listener.log"
    # Closes the accepted connection immediately, with no bytes exchanged:
    # this is the exact scenario that once caused Wirestack to route an
    # active-open connection's peer_closed/accepted_payload into the
    # passive HTTP server layer (src/main.cpp handleTcp) and answer with
    # an unsolicited HTTP 400 -- fixed by gating that routing on
    # active_open_key. Regression evidence for the fix, not just a
    # handshake demonstration.
    ws_in_client python3 - "${WS_CLIENT_IP}" "${WS_LISTEN_PORT}" \
        >"${log}" 2>&1 <<'PYEOF' &
import socket
import sys

ip = sys.argv[1]
port = int(sys.argv[2])

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
s.bind((ip, port))
s.listen(1)
print("LISTENING", flush=True)
s.settimeout(10.0)
conn, addr = s.accept()
print("ACCEPTED", addr, flush=True)
conn.close()
s.close()
print("CLOSED", flush=True)
PYEOF
    local listener_pid=$!
    echo "${listener_pid}" >"${pidfile}"
    ws_record_identity "${listener_pid}" "${pidfile}" python3

    local waited=0
    while ! grep -q "^LISTENING" "${log}" 2>/dev/null; do
        kill -0 "${listener_pid}" 2>/dev/null || { ws_log "listener exited before LISTENING, see ${log}"; return 1; }
        waited=$((waited + 1))
        [ "${waited}" -gt 250 ] && { ws_log "timed out waiting for listener to report LISTENING"; return 1; }
        sleep 0.02
    done

    ws_capture_start active_open "${WS_HOST_VETH}"
    ws_prime_arp

    local wirestack_pid
    wirestack_pid="$(cat "${WS_EVIDENCE_DIR}/${WS_WIRESTACK_PIDFILE_NAME}")"

    # wirestack's own stdout is fully buffered once redirected to a file
    # (not a tty), so a real "established"/"refused" status line can sit
    # unflushed for an arbitrary time -- not usable as a wait gate here.
    # A real accept() returning is itself proof the three-way handshake
    # completed (the kernel would not otherwise hand back a connected
    # socket), so wait on that instead.
    waited=0
    while ! grep -q "^ACCEPTED" "${log}" 2>/dev/null; do
        kill -0 "${listener_pid}" 2>/dev/null || { ws_log "listener exited before ACCEPTED, see ${log}"; ws_capture_stop active_open; return 1; }
        waited=$((waited + 1))
        [ "${waited}" -gt 250 ] && { ws_log "timed out waiting for listener to accept"; ws_capture_stop active_open; return 1; }
        sleep 0.02
    done
    # Then wait for the listener's own immediate close -- the regression
    # case for the cross-layer HTTP-routing fix.
    waited=0
    while ! grep -q "^CLOSED" "${log}" 2>/dev/null; do
        waited=$((waited + 1))
        [ "${waited}" -gt 250 ] && { ws_log "timed out waiting for listener to close"; ws_capture_stop active_open; return 1; }
        sleep 0.02
    done
    # Give Wirestack a moment to react to the FIN (and, if the HTTP-routing
    # bug regressed, to emit an unsolicited response) before stopping.
    sleep 0.3
    ws_capture_stop active_open

    grep -q "^ACCEPTED" "${log}" || return 1
    grep -q "^CLOSED" "${log}" || return 1

    # Regression: the peer's FIN on this active-open connection must never
    # produce an HTTP response (a data-carrying PSH segment) or a
    # listener-side RST (which is what a confused already-closing Linux
    # socket sends back if it receives unexpected bytes on a connection
    # it just closed).
    if grep -qE "${WS_CLIENT_IP}\.${WS_LISTEN_PORT} > .*Flags \[R" \
        "${WS_EVIDENCE_DIR}/active_open.abs.txt"; then
        ws_log "listener sent RST after its own close -- HTTP-routing regression"
        return 1
    fi
    if grep -qE "${WS_SERVER_IP}\.${WS_ACTIVE_SRC_PORT} > .*Flags \[P" \
        "${WS_EVIDENCE_DIR}/active_open.abs.txt"; then
        ws_log "unsolicited data segment on active-open connection -- HTTP-routing regression"
        return 1
    fi

    local syn_line synack_line ack_line
    syn_line="$(grep "${WS_SERVER_IP}\.${WS_ACTIVE_SRC_PORT} > ${WS_CLIENT_IP}\.${WS_LISTEN_PORT}: Flags \[S\]" "${WS_EVIDENCE_DIR}/active_open.abs.txt" | head -1)"
    synack_line="$(grep "${WS_CLIENT_IP}\.${WS_LISTEN_PORT} > ${WS_SERVER_IP}\.${WS_ACTIVE_SRC_PORT}: Flags \[S\.\]" "${WS_EVIDENCE_DIR}/active_open.abs.txt" | head -1)"
    ack_line="$(grep "${WS_SERVER_IP}\.${WS_ACTIVE_SRC_PORT} > ${WS_CLIENT_IP}\.${WS_LISTEN_PORT}: Flags \[\.\]" "${WS_EVIDENCE_DIR}/active_open.abs.txt" | head -1)"
    [ -n "${syn_line}" ] || { ws_log "no outbound SYN found"; return 1; }
    [ -n "${synack_line}" ] || { ws_log "no SYN-ACK from listener found"; return 1; }
    [ -n "${ack_line}" ] || { ws_log "no final ACK from wirestack found"; return 1; }

    grep -qi "bad cksum" "${WS_EVIDENCE_DIR}/active_open.abs.txt" && { ws_log "bad checksum observed"; return 1; }
    grep -q "${WS_CLIENT_IP}\.${WS_LISTEN_PORT} > .*Flags \[R" "${WS_EVIDENCE_DIR}/active_open.abs.txt" && { ws_log "unexpected RST from listener"; return 1; }

    local syn_seq synack_seq synack_ack final_seq final_ack
    syn_seq="$(ws_extract_field "${syn_line}" seq)"
    synack_seq="$(ws_extract_field "${synack_line}" seq)"
    synack_ack="$(ws_extract_field "${synack_line}" ack)"
    final_seq="$(ws_extract_field "${ack_line}" seq)"
    final_ack="$(ws_extract_field "${ack_line}" ack)"

    ws_log "SYN:      ${syn_line}"
    ws_log "SYN-ACK:  ${synack_line}"
    ws_log "ACK:      ${ack_line}"

    [ -n "${syn_seq}" ] && [ -n "${synack_ack}" ] && [ "${synack_ack}" = "$((syn_seq + 1))" ] \
        || { ws_log "SYN-ACK ack (${synack_ack}) != SYN seq+1 ($((syn_seq + 1)))"; return 1; }
    [ -n "${synack_seq}" ] && [ -n "${final_ack}" ] && [ "${final_ack}" = "$((synack_seq + 1))" ] \
        || { ws_log "final ACK ack (${final_ack}) != SYN-ACK seq+1 ($((synack_seq + 1)))"; return 1; }
    [ "${final_seq}" = "$((syn_seq + 1))" ] \
        || { ws_log "final ACK seq (${final_seq}) != SYN seq+1 ($((syn_seq + 1)))"; return 1; }

    return 0
}

# ---------------------------------------------------------------------------
# 2. Active open against a closed port: the client namespace's own kernel
#    generates RST|ACK, no listener process involved.
# ---------------------------------------------------------------------------
ws_test_active_open_refused() {
    ws_restart_wirestack_active_open "${WS_CLIENT_IP}" "${WS_REFUSED_PORT}" "${WS_REFUSED_SRC_PORT}"

    ws_capture_start active_open_refused "${WS_HOST_VETH}"
    ws_prime_arp

    local wirestack_pid
    wirestack_pid="$(cat "${WS_EVIDENCE_DIR}/${WS_WIRESTACK_PIDFILE_NAME}")"

    # See the matching comment in ws_test_active_open_established: wirestack's
    # stdout is not usable as a wait gate here. No listener/accept() exists
    # in this scenario to wait on instead, so poll the capture's own pcap
    # file (ws_capture_start's tcpdump runs with -U, flushing each packet as
    # captured) directly for the RST landing on the wire.
    local pcap="${WS_EVIDENCE_DIR}/active_open_refused.pcap"
    local waited=0
    while ! tcpdump -r "${pcap}" -n 2>/dev/null | grep -q "Flags \[R"; do
        kill -0 "${wirestack_pid}" 2>/dev/null || { ws_log "wirestack exited before refusal"; ws_capture_stop active_open_refused; return 1; }
        waited=$((waited + 1))
        [ "${waited}" -gt 250 ] && { ws_log "timed out waiting for the client kernel's RST"; ws_capture_stop active_open_refused; return 1; }
        sleep 0.02
    done

    # Wirestack's RTO is 1s (kInitialRto, include/wirestack/tcp_connection.hpp)
    # -- wait past one tick to prove no retransmission follows a refusal.
    sleep 1.5
    ws_capture_stop active_open_refused

    local syn_line rst_line
    syn_line="$(grep "${WS_SERVER_IP}\.${WS_REFUSED_SRC_PORT} > ${WS_CLIENT_IP}\.${WS_REFUSED_PORT}: Flags \[S\]" "${WS_EVIDENCE_DIR}/active_open_refused.abs.txt" | head -1)"
    rst_line="$(grep "${WS_CLIENT_IP}\.${WS_REFUSED_PORT} > ${WS_SERVER_IP}\.${WS_REFUSED_SRC_PORT}: Flags \[R\.\]" "${WS_EVIDENCE_DIR}/active_open_refused.abs.txt" | head -1)"
    [ -n "${syn_line}" ] || { ws_log "no outbound SYN found"; return 1; }
    [ -n "${rst_line}" ] || { ws_log "no RST from client kernel found"; return 1; }

    ws_log "SYN: ${syn_line}"
    ws_log "RST: ${rst_line}"

    local syn_seq rst_ack
    syn_seq="$(ws_extract_field "${syn_line}" seq)"
    rst_ack="$(ws_extract_field "${rst_line}" ack)"
    [ -n "${syn_seq}" ] && [ -n "${rst_ack}" ] && [ "${rst_ack}" = "$((syn_seq + 1))" ] \
        || { ws_log "RST ack (${rst_ack}) != SYN seq+1 ($((syn_seq + 1)))"; return 1; }

    local syn_count
    syn_count="$(grep -c "${WS_SERVER_IP}\.${WS_REFUSED_SRC_PORT} > ${WS_CLIENT_IP}\.${WS_REFUSED_PORT}: Flags \[S\]" "${WS_EVIDENCE_DIR}/active_open_refused.abs.txt" || true)"
    [ "${syn_count}" = "1" ] || { ws_log "expected exactly 1 SYN on the wire, got ${syn_count} (unexpected retransmission after refusal)"; return 1; }

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

ws_run_test "active_open_established" ws_test_active_open_established
ws_run_test "active_open_refused"     ws_test_active_open_refused

ws_log "test failures: ${WS_TEST_FAILURES}"
[ "${WS_TEST_FAILURES}" = "0" ]
