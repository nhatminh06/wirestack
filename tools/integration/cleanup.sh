#!/usr/bin/env bash
# Idempotent teardown of every resource setup.sh may have created. Safe to
# run multiple times, and safe to run when only some resources exist (a
# partial or already-clean state). Removes only resources this run's own
# evidence directory recorded as owned (see ws_mark_owned in common.sh) --
# never a same-named resource left by something else. A standalone
# invocation with no evidence directory, or one with no ownership
# records, deletes nothing and reports so.

set -uo pipefail

WS_SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=./common.sh
. "${WS_SCRIPT_DIR}/common.sh"

WS_CLEANUP_FAILED=0

# Kills the process recorded in `pidfile` only if it is still running and
# still identifiably the process this run started (see ws_verify_identity).
ws_cleanup_kill_recorded() {
    local pidfile="$1" label="$2"
    [ -f "${pidfile}" ] || return 0
    local pid
    pid="$(cat "${pidfile}" 2>/dev/null || true)"
    [ -n "${pid}" ] || return 0
    kill -0 "${pid}" 2>/dev/null || return 0

    if ! ws_verify_identity "${pid}" "${pidfile}"; then
        ws_log "refusing to signal pid ${pid} for ${label}: identity no longer matches (stale pid reuse?)"
        WS_CLEANUP_FAILED=1
        return 1
    fi

    ws_log "stopping ${label} (pid ${pid})"
    kill "${pid}" 2>/dev/null || true
    for _ in $(seq 1 50); do
        kill -0 "${pid}" 2>/dev/null || break
        sleep 0.05
    done
    kill -9 "${pid}" 2>/dev/null || true
    if kill -0 "${pid}" 2>/dev/null; then
        ws_log "failed to stop ${label} (pid ${pid})"
        WS_CLEANUP_FAILED=1
        return 1
    fi
    return 0
}

# Deletes an owned link resource and verifies it is actually gone.
ws_cleanup_delete_link() {
    local iface="$1" owner_key="$2"
    if ! ws_is_owned "${owner_key}"; then
        if ip link show "${iface}" >/dev/null 2>&1; then
            ws_log "refusing to remove ${iface}: no ownership record for this run"
        fi
        return 0
    fi
    if ip link show "${iface}" >/dev/null 2>&1; then
        ws_log "removing ${iface}"
        if ! ip link delete "${iface}" >/dev/null 2>&1; then
            ws_log "failed to issue delete for ${iface}"
            WS_CLEANUP_FAILED=1
            return 1
        fi
    fi
    if ip link show "${iface}" >/dev/null 2>&1; then
        ws_log "verification failed: ${iface} still present after deletion"
        WS_CLEANUP_FAILED=1
        return 1
    fi
    return 0
}

ws_cleanup() {
    WS_CLEANUP_FAILED=0
    ws_log "cleanup: starting"

    if [ -n "${WS_EVIDENCE_DIR}" ]; then
        ws_cleanup_kill_recorded "${WS_EVIDENCE_DIR}/${WS_WIRESTACK_PIDFILE_NAME}" "wirestack"
        ws_cleanup_kill_recorded "$(ws_client_pidfile)" "client namespace placeholder"

        # Any tcpdump capture or background Python test client this run
        # started records its own pid file under WS_EVIDENCE_DIR (see
        # ws_capture_start, and the http_retrans/synack_loss client pid
        # files in run.sh); sweep them so a scenario that returns early
        # does not leave a capture or client process running.
        local f base
        for f in "${WS_EVIDENCE_DIR}"/*.pid; do
            [ -e "${f}" ] || continue
            base="$(basename "${f}")"
            [ "${base}" = "${WS_WIRESTACK_PIDFILE_NAME}" ] && continue
            [ "${base}" = "${WS_CLIENT_PIDFILE_NAME}" ] && continue
            ws_cleanup_kill_recorded "${f}" "background process (${base})"
        done
    else
        ws_log "no WS_EVIDENCE_DIR set; no recorded processes to stop"
    fi

    ws_cleanup_delete_link "${WS_TAP}" tap
    ws_cleanup_delete_link "${WS_HOST_VETH}" host_veth
    ws_cleanup_delete_link "${WS_BRIDGE}" bridge

    # The client-side veth half and any qdisc on it live inside the
    # client network namespace; both disappear when that namespace's last
    # process (the placeholder) exits, which ws_cleanup_kill_recorded
    # above already ensured (or refused, and flagged failure).

    # A qdisc a scenario added to WS_HOST_VETH is removed along with the
    # link above; this only catches a stray qdisc surviving on an
    # interface we otherwise did not delete (not owned, or already gone).
    if ws_is_owned host_veth && ip link show "${WS_HOST_VETH}" >/dev/null 2>&1; then
        if tc qdisc show dev "${WS_HOST_VETH}" 2>/dev/null | grep -qv "qdisc noqueue\|qdisc pfifo_fast\|qdisc mq\|qdisc noop"; then
            ws_log "verification failed: stray qdisc remains on ${WS_HOST_VETH}"
            WS_CLEANUP_FAILED=1
        fi
    fi

    if [ "${WS_CLEANUP_FAILED}" != "0" ]; then
        ws_log "cleanup: FAILED to remove all owned resources"
        return 1
    fi
    ws_log "cleanup: done"
    return 0
}

if [ "${WS_INTEGRATION_SOURCED:-0}" != "1" ]; then
    ws_check_privileges
    if [ -z "${WS_EVIDENCE_DIR}" ]; then
        ws_log "no WS_EVIDENCE_DIR set; standalone run, nothing recorded as owned"
    fi
    ws_cleanup
    exit $?
fi
