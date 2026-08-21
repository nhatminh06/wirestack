#!/usr/bin/env bash
# Builds the isolated topology described in docs/interoperability.md and
# starts the Wirestack process. Meant to be sourced by run.sh (which owns
# the cleanup trap); running it standalone is only useful for manual
# debugging and leaves resources behind for cleanup.sh to remove.

set -euo pipefail

WS_SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=./common.sh
. "${WS_SCRIPT_DIR}/common.sh"

# Fails loudly rather than silently reusing a leftover resource from a
# previous, incompletely-cleaned-up run.
ws_fail_if_exists() {
    if ip link show "$1" >/dev/null 2>&1; then
        ws_die "conflicting pre-existing interface: $1 (run tools/integration/cleanup.sh first)"
    fi
}

ws_setup_topology() {
    ws_fail_if_exists "${WS_BRIDGE}"
    ws_fail_if_exists "${WS_HOST_VETH}"
    ws_fail_if_exists "${WS_CLIENT_VETH}"

    ws_log "creating client network namespace"
    unshare --net -- sleep infinity &
    local client_pid=$!
    echo "${client_pid}" >"$(ws_client_pidfile)"
    # Give the placeholder process a moment to finish unshare(CLONE_NEWNET)
    # before anything tries to enter its namespace.
    for _ in $(seq 1 50); do
        [ -e "/proc/${client_pid}/ns/net" ] && break
        sleep 0.05
    done
    [ -e "/proc/${client_pid}/ns/net" ] || ws_die "client namespace did not appear (pid ${client_pid})"
    ws_record_identity "${client_pid}" "$(ws_client_pidfile)" sleep
    ws_log "created client namespace (placeholder pid ${client_pid})"

    ws_log "creating bridge ${WS_BRIDGE}"
    ip link add "${WS_BRIDGE}" type bridge
    ws_mark_owned bridge
    ip link set "${WS_BRIDGE}" up

    ws_log "creating veth pair ${WS_HOST_VETH} <-> ${WS_CLIENT_VETH}"
    ip link add "${WS_HOST_VETH}" type veth peer name "${WS_CLIENT_VETH}"
    ws_mark_owned host_veth
    ip link set "${WS_HOST_VETH}" master "${WS_BRIDGE}"
    ip link set "${WS_HOST_VETH}" up

    ws_log "moving ${WS_CLIENT_VETH} into client namespace"
    ip link set "${WS_CLIENT_VETH}" netns "${client_pid}"
    ws_in_client ip addr add "${WS_CLIENT_IP}/${WS_PREFIX}" dev "${WS_CLIENT_VETH}"
    ws_in_client ip link set "${WS_CLIENT_VETH}" up
    ws_in_client ip link set lo up

    # GRO/TSO/GSO on the veth pair can aggregate or split segments in ways
    # that hide real segment boundaries in the capture, or feed Wirestack
    # payloads larger than any single Ethernet frame it will accept.
    ethtool -K "${WS_HOST_VETH}" tso off gso off gro off tx off rx off sg off >/dev/null 2>&1 || true
    ws_in_client ethtool -K "${WS_CLIENT_VETH}" tso off gso off gro off tx off rx off sg off >/dev/null 2>&1 || true
    ws_verify_offloads_off "${WS_HOST_VETH}"
    ws_verify_offloads_off "${WS_CLIENT_VETH}" ws_in_client

    ip link set "${WS_HOST_VETH}" mtu "${WS_MTU}"
    ws_in_client ip link set "${WS_CLIENT_VETH}" mtu "${WS_MTU}"
}

# Any extra arguments (e.g. --active-open <ip>:<port> --source-port
# <port>) are appended after the required tap/ip/mac positionals.
ws_start_wirestack() {
    [ -x "${WS_BINARY}" ] || ws_die "wirestack binary not found or not executable: ${WS_BINARY}"

    ws_fail_if_exists "${WS_TAP}"

    local out="${WS_EVIDENCE_DIR}/wirestack.out"
    ws_log "starting wirestack (log: ${out})"
    "${WS_BINARY}" "${WS_TAP}" "${WS_SERVER_IP}" "${WS_SERVER_MAC}" "$@" >"${out}" 2>&1 &
    local ws_pid=$!
    echo "${ws_pid}" >"${WS_EVIDENCE_DIR}/${WS_WIRESTACK_PIDFILE_NAME}"
    # /proc/<pid>/comm is truncated to 15 bytes by the kernel.
    ws_record_identity "${ws_pid}" "${WS_EVIDENCE_DIR}/${WS_WIRESTACK_PIDFILE_NAME}" \
        "$(basename "${WS_BINARY}" | cut -c1-15)"

    # Wait for wirestack to create and report the TAP interface rather
    # than sleeping a fixed, racy amount of time.
    local waited=0
    while ! ip link show "${WS_TAP}" >/dev/null 2>&1; do
        if ! kill -0 "${ws_pid}" 2>/dev/null; then
            ws_die "wirestack exited before opening the TAP device -- see ${out}"
        fi
        waited=$((waited + 1))
        [ "${waited}" -gt 100 ] && ws_die "timed out waiting for ${WS_TAP} to appear"
        sleep 0.05
    done
    ws_mark_owned tap

    ip link set "${WS_TAP}" master "${WS_BRIDGE}"
    ip link set "${WS_TAP}" up
    ethtool -K "${WS_TAP}" tso off gso off gro off tx off rx off sg off >/dev/null 2>&1 || true
    ws_verify_offloads_off "${WS_TAP}"
    ip link set "${WS_TAP}" mtu "${WS_MTU}"

    ws_log "wirestack running (pid ${ws_pid}), tap ${WS_TAP} attached to ${WS_BRIDGE}"
}

if [ "${WS_INTEGRATION_SOURCED:-0}" != "1" ]; then
    ws_check_dependencies
    ws_check_privileges
    [ -n "${WS_EVIDENCE_DIR}" ] || ws_make_evidence_dir
    ws_setup_topology
    ws_start_wirestack
    ws_log "topology ready; resources left running for manual inspection"
    ws_log "evidence directory: ${WS_EVIDENCE_DIR}"
fi
