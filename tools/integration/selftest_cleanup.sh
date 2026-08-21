#!/usr/bin/env bash
# Exercises cleanup.sh's ownership and verification logic in isolation,
# against stub `ip`/`tc` commands -- no real interfaces are touched and
# no CAP_NET_ADMIN is required. Run directly:
#
#   bash tools/integration/selftest_cleanup.sh
#
# Each case resets a scratch evidence directory and a scratch "kernel
# state" directory that the stub commands read/write instead of the real
# network stack, then calls the real ws_cleanup() from cleanup.sh.

set -uo pipefail

WS_SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
export WS_INTEGRATION_SOURCED=1
# shellcheck source=./common.sh
. "${WS_SCRIPT_DIR}/common.sh"
# shellcheck source=./cleanup.sh
. "${WS_SCRIPT_DIR}/cleanup.sh"

SELFTEST_ROOT="$(mktemp -d /tmp/wirestack-selftest.XXXXXX)"
STUB_BIN="${SELFTEST_ROOT}/bin"
mkdir -p "${STUB_BIN}"

cat >"${STUB_BIN}/ip" <<'EOF'
#!/usr/bin/env bash
if [ "$1" = "link" ] && [ "$2" = "show" ]; then
    [ -e "${STUB_STATE}/exists.$3" ] && exit 0 || exit 1
fi
if [ "$1" = "link" ] && [ "$2" = "delete" ]; then
    echo "delete $3" >>"${STUB_STATE}/invocations.log"
    [ -e "${STUB_STATE}/fail_delete_exit.$3" ] && exit 1
    [ -e "${STUB_STATE}/fail_delete_silent.$3" ] && exit 0
    rm -f "${STUB_STATE}/exists.$3"
    exit 0
fi
exit 0
EOF

cat >"${STUB_BIN}/tc" <<'EOF'
#!/usr/bin/env bash
exit 0
EOF
chmod +x "${STUB_BIN}/ip" "${STUB_BIN}/tc"

export PATH="${STUB_BIN}:${PATH}"

SELFTEST_FAILURES=0
selftest_pass() { printf '[selftest] PASS: %s\n' "$1"; }
selftest_fail() { SELFTEST_FAILURES=$((SELFTEST_FAILURES + 1)); printf '[selftest] FAIL: %s\n' "$1"; }

selftest_reset() {
    STUB_STATE="$(mktemp -d "${SELFTEST_ROOT}/state.XXXXXX")"
    export STUB_STATE
    : >"${STUB_STATE}/invocations.log"
    WS_EVIDENCE_DIR="$(mktemp -d "${SELFTEST_ROOT}/evidence.XXXXXX")"
}

selftest_deleted() {
    # true if `ip link delete <name>` was invoked during the last case
    grep -q "^delete $1\$" "${STUB_STATE}/invocations.log"
}

# --- case 1: conflicting pre-existing resource, no ownership record -------
selftest_reset
: >"${STUB_STATE}/exists.${WS_TAP}"
ws_cleanup >/dev/null 2>&1
rc=$?
if [ -e "${STUB_STATE}/exists.${WS_TAP}" ] && ! selftest_deleted "${WS_TAP}"; then
    selftest_pass "conflicting pre-existing resource is never deleted"
else
    selftest_fail "conflicting pre-existing resource is never deleted"
fi

# --- case 2: standalone invocation, no evidence dir at all ----------------
selftest_reset
: >"${STUB_STATE}/exists.${WS_TAP}"
: >"${STUB_STATE}/exists.${WS_HOST_VETH}"
: >"${STUB_STATE}/exists.${WS_BRIDGE}"
saved_evidence_dir="${WS_EVIDENCE_DIR}"
WS_EVIDENCE_DIR=""
ws_cleanup >/dev/null 2>&1
if [ -e "${STUB_STATE}/exists.${WS_TAP}" ] && [ -e "${STUB_STATE}/exists.${WS_HOST_VETH}" ] \
    && [ -e "${STUB_STATE}/exists.${WS_BRIDGE}" ] && [ ! -s "${STUB_STATE}/invocations.log" ]; then
    selftest_pass "cleanup with no evidence directory refuses all deletion"
else
    selftest_fail "cleanup with no evidence directory refuses all deletion"
fi
WS_EVIDENCE_DIR="${saved_evidence_dir}"

# --- case 3: partial setup, only some resources owned ---------------------
selftest_reset
: >"${STUB_STATE}/exists.${WS_TAP}"
: >"${STUB_STATE}/exists.${WS_HOST_VETH}"
ws_mark_owned tap
ws_cleanup >/dev/null 2>&1
if [ ! -e "${STUB_STATE}/exists.${WS_TAP}" ] && [ -e "${STUB_STATE}/exists.${WS_HOST_VETH}" ]; then
    selftest_pass "partial setup cleans only the recorded (owned) resource"
else
    selftest_fail "partial setup cleans only the recorded (owned) resource"
fi

# --- case 4: deletion silently fails to take effect ------------------------
selftest_reset
: >"${STUB_STATE}/exists.${WS_HOST_VETH}"
: >"${STUB_STATE}/fail_delete_silent.${WS_HOST_VETH}"
ws_mark_owned host_veth
ws_cleanup >/dev/null 2>&1
rc=$?
if [ "${rc}" != "0" ]; then
    selftest_pass "a deletion that does not actually remove the resource yields nonzero"
else
    selftest_fail "a deletion that does not actually remove the resource yields nonzero"
fi

# --- case 5: deletion command itself reports failure ------------------------
selftest_reset
: >"${STUB_STATE}/exists.${WS_HOST_VETH}"
: >"${STUB_STATE}/fail_delete_exit.${WS_HOST_VETH}"
ws_mark_owned host_veth
ws_cleanup >/dev/null 2>&1
rc=$?
[ "${rc}" != "0" ] && selftest_pass "ip link delete failing is reported as cleanup failure" \
    || selftest_fail "ip link delete failing is reported as cleanup failure"

# --- case 6: repeated cleanup is harmless -----------------------------------
selftest_reset
: >"${STUB_STATE}/exists.${WS_TAP}"
ws_mark_owned tap
ws_cleanup >/dev/null 2>&1
first_rc=$?
ws_cleanup >/dev/null 2>&1
second_rc=$?
if [ "${first_rc}" = "0" ] && [ "${second_rc}" = "0" ]; then
    selftest_pass "repeated cleanup after success remains harmless"
else
    selftest_fail "repeated cleanup after success remains harmless"
fi

# --- case 7: fully owned, everything succeeds -------------------------------
selftest_reset
: >"${STUB_STATE}/exists.${WS_TAP}"
: >"${STUB_STATE}/exists.${WS_HOST_VETH}"
: >"${STUB_STATE}/exists.${WS_BRIDGE}"
ws_mark_owned tap
ws_mark_owned host_veth
ws_mark_owned bridge
ws_cleanup >/dev/null 2>&1
rc=$?
if [ "${rc}" = "0" ] && [ ! -e "${STUB_STATE}/exists.${WS_TAP}" ] \
    && [ ! -e "${STUB_STATE}/exists.${WS_HOST_VETH}" ] && [ ! -e "${STUB_STATE}/exists.${WS_BRIDGE}" ]; then
    selftest_pass "fully owned resources are deleted and verified gone"
else
    selftest_fail "fully owned resources are deleted and verified gone"
fi

rm -rf "${SELFTEST_ROOT}"

printf '[selftest] failures: %s\n' "${SELFTEST_FAILURES}"
[ "${SELFTEST_FAILURES}" = "0" ]
