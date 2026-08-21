#!/usr/bin/env bash
# Shared configuration and helpers for the Linux TAP interoperability
# harness. Sourced by setup.sh, run.sh, and cleanup.sh -- never executed
# directly.
#
# Everything here must run inside a sandbox that already has CAP_NET_ADMIN
# in its own network namespace, e.g.:
#
#   unshare --user --net --map-root-user -- bash tools/integration/run.sh
#
# `ip netns add` cannot be used in that sandbox (it tries to bind-mount
# into the host's shared /var/run/netns, which this environment does not
# allow). The "client namespace" is instead a plain network namespace
# created by backgrounding `unshare --net -- sleep infinity` and reaching
# it with `nsenter --net=/proc/<pid>/ns/net`.

if [ -n "${WIRESTACK_INTEGRATION_COMMON_SH:-}" ]; then
    return 0
fi
WIRESTACK_INTEGRATION_COMMON_SH=1

# --- resource names -------------------------------------------------------

WS_BRIDGE="ws-int-br"
WS_TAP="ws-int-tap"
WS_HOST_VETH="ws-host0"
WS_CLIENT_VETH="ws-client0"

WS_SERVER_IP="10.0.0.2"
WS_CLIENT_IP="10.0.0.1"
WS_PREFIX="24"
WS_MTU="1500"

WS_SERVER_MAC="02:00:00:00:00:02"
WS_TCP_PORT="8080"
WS_UDP_PORT="9000"

WS_CLIENT_PIDFILE_NAME="ws-client-netns.pid"
WS_WIRESTACK_PIDFILE_NAME="wirestack.pid"

# --- repo layout -----------------------------------------------------------

WS_SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
WS_REPO_ROOT="$(cd "${WS_SCRIPT_DIR}/../.." && pwd)"
# Overridable so the same suite can be pointed at the ASan+UBSan build,
# e.g. WS_BINARY=build-asan/wirestack bash tools/integration/run.sh
WS_BINARY="${WS_BINARY:-${WS_REPO_ROOT}/build/wirestack}"

# --- logging -----------------------------------------------------------

ws_log() {
    printf '[integration] %s\n' "$*" >&2
}

ws_die() {
    printf '[integration] error: %s\n' "$*" >&2
    exit 1
}

# --- dependency checks ---------------------------------------------------

ws_require_cmd() {
    local cmd="$1"
    command -v "${cmd}" >/dev/null 2>&1 || ws_die "required command not found: ${cmd}"
}

ws_check_dependencies() {
    ws_require_cmd ip
    ws_require_cmd tc
    ws_require_cmd tcpdump
    ws_require_cmd curl
    ws_require_cmd ethtool
    ws_require_cmd unshare
    ws_require_cmd nsenter
    ws_require_cmd python3
    ws_require_cmd arping
}

ws_check_privileges() {
    if [ "$(id -u)" != "0" ]; then
        ws_die "must run as uid 0 inside a sandbox with its own net namespace, e.g.:
  unshare --user --net --map-root-user -- bash tools/integration/run.sh"
    fi
}

# --- evidence directory ----------------------------------------------------

# Set by run.sh via ws_make_evidence_dir; exported here so cleanup.sh can
# print the path on failure even when sourced independently.
WS_EVIDENCE_DIR="${WS_EVIDENCE_DIR:-}"

ws_make_evidence_dir() {
    WS_EVIDENCE_DIR="$(mktemp -d /tmp/wirestack-integration.XXXXXX)"
    ws_log "evidence directory: ${WS_EVIDENCE_DIR}"
}

# --- client namespace helpers ----------------------------------------------

# Path to the file holding the client namespace's placeholder-process pid,
# once ws_client_netns_pid has been called at least once in this shell.
ws_client_pidfile() {
    printf '%s/%s' "${WS_EVIDENCE_DIR}" "${WS_CLIENT_PIDFILE_NAME}"
}

ws_client_netns_pid() {
    local pidfile
    pidfile="$(ws_client_pidfile)"
    [ -f "${pidfile}" ] || ws_die "client namespace not set up (missing ${pidfile})"
    cat "${pidfile}"
}

# Runs "$@" inside the client network namespace.
ws_in_client() {
    local pid
    pid="$(ws_client_netns_pid)"
    nsenter --net="/proc/${pid}/ns/net" -- "$@"
}

# --- packet capture ---------------------------------------------------

# Starts a full-length tcpdump on `iface`, writing both a pcap and (once
# stopped) a decoded text trace under WS_EVIDENCE_DIR, named `name`.
# -U makes tcpdump flush each packet to the pcap file as it is captured.
ws_capture_start() {
    local name="$1" iface="$2"
    local pcap="${WS_EVIDENCE_DIR}/${name}.pcap"
    tcpdump -i "${iface}" -w "${pcap}" -U -l -s 0 -n >"${WS_EVIDENCE_DIR}/${name}.tcpdump.log" 2>&1 &
    local pid=$!
    echo "${pid}" >"${WS_EVIDENCE_DIR}/${name}.tcpdump.pid"
    ws_record_identity "${pid}" "${WS_EVIDENCE_DIR}/${name}.tcpdump.pid" tcpdump
    # The pcap file gets its 24-byte global header as soon as tcpdump
    # opens the output, well before its capture socket is actually bound
    # -- wait for tcpdump's own "listening on" message instead, or the
    # very first ARP/ping of a run can race past an unready capture.
    local waited=0
    while ! grep -q "listening on" "${WS_EVIDENCE_DIR}/${name}.tcpdump.log" 2>/dev/null; do
        kill -0 "${pid}" 2>/dev/null || ws_die "tcpdump for ${name} exited immediately -- see ${WS_EVIDENCE_DIR}/${name}.tcpdump.log"
        waited=$((waited + 1))
        [ "${waited}" -gt 200 ] && ws_die "timed out waiting for tcpdump capture ${name} to start"
        sleep 0.02
    done
}

# Stops the capture started by ws_capture_start and produces a decoded
# text trace at WS_EVIDENCE_DIR/<name>.txt.
ws_capture_stop() {
    local name="$1"
    local pidfile="${WS_EVIDENCE_DIR}/${name}.tcpdump.pid"
    [ -f "${pidfile}" ] || ws_die "no capture pidfile for ${name}"
    local pid
    pid="$(cat "${pidfile}")"
    # A signal delivered while tcpdump is blocked in its receive call can
    # abort pcap_loop via EINTR before it drains packets the kernel has
    # already queued for the socket -- give it one scheduler tick to
    # finish reading and writing what has already arrived.
    sleep 1.0
    kill -INT "${pid}" 2>/dev/null || true
    for _ in $(seq 1 50); do
        kill -0 "${pid}" 2>/dev/null || break
        sleep 0.05
    done
    kill -9 "${pid}" 2>/dev/null || true
    # Relative sequence numbers (tcpdump default) read naturally as byte
    # offsets from each stream's ISN -- easiest for spotting reordering.
    tcpdump -r "${WS_EVIDENCE_DIR}/${name}.pcap" -n -tttt -vv \
        >"${WS_EVIDENCE_DIR}/${name}.txt" 2>/dev/null || true
    # Absolute sequence numbers (-S) -- needed for exact wraparound
    # arithmetic (closed-port reset fields, retransmission identity).
    tcpdump -r "${WS_EVIDENCE_DIR}/${name}.pcap" -n -tttt -vv -S \
        >"${WS_EVIDENCE_DIR}/${name}.abs.txt" 2>/dev/null || true
}

# --- resource ownership -----------------------------------------------
#
# cleanup.sh must only delete a fixed-name interface (ws-int-tap,
# ws-host0, ws-int-br) when the current run's own evidence proves it
# created that exact resource -- a standalone cleanup.sh invocation with
# no run behind it must refuse, even if a same-named interface exists
# (it could belong to a different, possibly still-running, invocation).

ws_mark_owned() {
    [ -n "${WS_EVIDENCE_DIR}" ] || ws_die "cannot record ownership without WS_EVIDENCE_DIR"
    : >"${WS_EVIDENCE_DIR}/owned.$1"
}

ws_is_owned() {
    [ -n "${WS_EVIDENCE_DIR}" ] && [ -f "${WS_EVIDENCE_DIR}/owned.$1" ]
}

# --- process identity ---------------------------------------------------
#
# A pid recorded early in a run can be reused by an unrelated process by
# the time cleanup runs. Before signaling a recorded pid, cross-check its
# /proc start time (which cannot be forged by a later process reusing the
# same pid within the same boot) and its command name.

ws_proc_start_ticks() {
    local pid="$1"
    [ -r "/proc/${pid}/stat" ] || return 1
    # After the last ')', /proc/pid/stat fields are (1-indexed): state(1)
    # ppid(2) pgrp(3) session(4) tty_nr(5) tpgid(6) flags(7) minflt(8)
    # cminflt(9) majflt(10) cmajflt(11) utime(12) stime(13) cutime(14)
    # cstime(15) priority(16) nice(17) num_threads(18) itrealvalue(19)
    # starttime(20).
    awk '{ n = split($0, a, ")"); split(a[n], b, " "); print b[20] }' "/proc/${pid}/stat"
}

ws_proc_comm() {
    local pid="$1"
    [ -r "/proc/${pid}/comm" ] || return 1
    cat "/proc/${pid}/comm"
}

# Records the identity of `pid` (already known to be the process this run
# just started) next to `pidfile`, as `<pidfile>.identity`. `expected_comm`
# is the command name the process is expected to exec into; right after
# fork the pid still carries its launching shell's comm until execve()
# completes, so this polls briefly rather than recording a comm that is
# about to change out from under it.
ws_record_identity() {
    local pid="$1" pidfile="$2" expected_comm="$3"
    local comm="" waited=0
    while :; do
        comm="$(ws_proc_comm "${pid}" 2>/dev/null)" || ws_die "process ${pid} exited before becoming '${expected_comm}'"
        [ "${comm}" = "${expected_comm}" ] && break
        waited=$((waited + 1))
        [ "${waited}" -gt 150 ] && ws_die "process ${pid} never became '${expected_comm}' (still '${comm}')"
        sleep 0.02
    done
    local start
    start="$(ws_proc_start_ticks "${pid}")" || ws_die "cannot read /proc/${pid}/stat to record identity"
    printf '%s %s\n' "${start}" "${comm}" >"${pidfile}.identity"
}

# Returns success only if `pid` is still running and its start time and
# command name match what was recorded for it. Used to refuse killing a
# pid that has since been reused by an unrelated process.
ws_verify_identity() {
    local pid="$1" pidfile="$2"
    local identity="${pidfile}.identity"
    [ -f "${identity}" ] || return 1
    local recorded_start recorded_comm
    read -r recorded_start recorded_comm <"${identity}"
    local cur_start cur_comm
    cur_start="$(ws_proc_start_ticks "${pid}" 2>/dev/null)" || return 1
    cur_comm="$(ws_proc_comm "${pid}" 2>/dev/null)" || return 1
    [ "${cur_start}" = "${recorded_start}" ] && [ "${cur_comm}" = "${recorded_comm}" ]
}

# --- offload verification -----------------------------------------------
#
# GRO/TSO/GSO/checksum offload/scatter-gather on an interface in the
# capture path can aggregate or split segments in ways that hide real
# segment boundaries -- ws_setup_topology asks the kernel to disable them
# with `ethtool -K`, but that request can be silently ignored by a driver.
# Verify the *effective* state afterward instead of trusting the request.

WS_OFFLOAD_FEATURES="tcp-segmentation-offload generic-segmentation-offload generic-receive-offload tx-checksumming rx-checksumming scatter-gather"

# Runs `ethtool -k <iface>` via "$@" (so callers can prefix with
# ws_in_client to check an interface inside the client namespace) and
# dies if any offload relevant to packet-boundary correctness is still
# effectively on.
ws_verify_offloads_off() {
    local iface="$1"
    shift
    local out
    out="$("$@" ethtool -k "${iface}" 2>/dev/null)" || ws_die "ethtool -k ${iface} failed"
    local feature line
    for feature in ${WS_OFFLOAD_FEATURES}; do
        line="$(printf '%s\n' "${out}" | grep -E "^[[:space:]]*${feature}:" | head -1)"
        [ -n "${line}" ] || continue
        printf '%s\n' "${line}" | grep -qE ': off' \
            || ws_die "offload ${feature} remains enabled on ${iface} (needed off for packet-boundary correctness): ${line}"
    done
}

# --- test result tracking ---------------------------------------------

WS_TEST_FAILURES=0

ws_pass() {
    ws_log "PASS: $1"
}

ws_fail() {
    WS_TEST_FAILURES=$((WS_TEST_FAILURES + 1))
    ws_log "FAIL: $1"
}
