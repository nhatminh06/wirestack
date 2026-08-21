#!/usr/bin/env bash
# Idempotent teardown of every resource setup.sh may have created. Safe to
# run multiple times, and safe to run when only some resources exist (a
# partial or already-clean state). Removes only harness-owned resources by
# their exact fixed names -- never a wildcard match.

set -uo pipefail

WS_SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=./common.sh
. "${WS_SCRIPT_DIR}/common.sh"

ws_cleanup() {
    ws_log "cleanup: starting"

    if [ -n "${WS_EVIDENCE_DIR}" ] && [ -f "${WS_EVIDENCE_DIR}/${WS_WIRESTACK_PIDFILE_NAME}" ]; then
        local ws_pid
        ws_pid="$(cat "${WS_EVIDENCE_DIR}/${WS_WIRESTACK_PIDFILE_NAME}" 2>/dev/null || true)"
        if [ -n "${ws_pid}" ] && kill -0 "${ws_pid}" 2>/dev/null; then
            ws_log "stopping wirestack (pid ${ws_pid})"
            kill "${ws_pid}" 2>/dev/null || true
            for _ in $(seq 1 50); do
                kill -0 "${ws_pid}" 2>/dev/null || break
                sleep 0.05
            done
            kill -9 "${ws_pid}" 2>/dev/null || true
        fi
    fi

    if [ -n "${WS_EVIDENCE_DIR}" ] && [ -f "$(ws_client_pidfile)" ]; then
        local client_pid
        client_pid="$(cat "$(ws_client_pidfile)" 2>/dev/null || true)"
        if [ -n "${client_pid}" ] && kill -0 "${client_pid}" 2>/dev/null; then
            ws_log "removing client namespace (placeholder pid ${client_pid})"
            kill "${client_pid}" 2>/dev/null || true
        fi
    fi

    # Any tcpdump/tc processes this run started record their own pid files
    # under WS_EVIDENCE_DIR; sweep them so a failed run does not leave a
    # capture process running.
    if [ -n "${WS_EVIDENCE_DIR}" ] && [ -d "${WS_EVIDENCE_DIR}" ]; then
        local f base pid
        for f in "${WS_EVIDENCE_DIR}"/*.pid; do
            [ -e "${f}" ] || continue
            base="$(basename "${f}")"
            [ "${base}" = "${WS_WIRESTACK_PIDFILE_NAME}" ] && continue
            [ "${base}" = "${WS_CLIENT_PIDFILE_NAME}" ] && continue
            pid="$(cat "${f}" 2>/dev/null || true)"
            if [ -n "${pid}" ] && kill -0 "${pid}" 2>/dev/null; then
                kill "${pid}" 2>/dev/null || true
            fi
        done
    fi

    if ip link show "${WS_TAP}" >/dev/null 2>&1; then
        ws_log "removing ${WS_TAP}"
        ip link delete "${WS_TAP}" >/dev/null 2>&1 || true
    fi
    if ip link show "${WS_HOST_VETH}" >/dev/null 2>&1; then
        ws_log "removing ${WS_HOST_VETH}"
        ip link delete "${WS_HOST_VETH}" >/dev/null 2>&1 || true
    fi
    if ip link show "${WS_BRIDGE}" >/dev/null 2>&1; then
        ws_log "removing ${WS_BRIDGE}"
        ip link delete "${WS_BRIDGE}" >/dev/null 2>&1 || true
    fi

    ws_log "cleanup: done"
}

if [ "${WS_INTEGRATION_SOURCED:-0}" != "1" ]; then
    ws_check_privileges
    if [ -z "${WS_EVIDENCE_DIR}" ]; then
        # Standalone invocation with no known evidence directory: still
        # remove the fixed-name link resources, best-effort.
        ws_log "no WS_EVIDENCE_DIR set; removing link resources only"
    fi
    ws_cleanup
fi
