#!/usr/bin/env bash
# Reproducible short-transfer benchmark against Wirestack and Linux TCP.

set -euo pipefail

WS_BENCH_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
WS_BENCH_HELPER="${WS_BENCH_DIR}/bench.py"
WS_INTEGRATION_DIR="${WS_BENCH_DIR}/../integration"
export WS_INTEGRATION_SOURCED=1
# shellcheck source=../integration/common.sh
. "${WS_INTEGRATION_DIR}/common.sh"
# shellcheck source=../integration/setup.sh
. "${WS_INTEGRATION_DIR}/setup.sh"
# shellcheck source=../integration/cleanup.sh
. "${WS_INTEGRATION_DIR}/cleanup.sh"

WS_LINUX_IP="10.0.0.3"
WS_BENCH_REPETITIONS="${WS_BENCH_REPETITIONS:-30}"
WS_BENCH_WARMUPS="${WS_BENCH_WARMUPS:-5}"

ws_check_dependencies
ws_check_privileges
ws_make_evidence_dir

WS_CLEANED_UP=0
ws_bench_exit() {
    local status=$?
    trap - EXIT
    tc qdisc del dev "${WS_HOST_VETH}" root >/dev/null 2>&1 || true
    if [ "${WS_CLEANED_UP}" != "1" ]; then
        WS_CLEANED_UP=1
        ws_cleanup || status=1
    fi
    [ "${status}" = "0" ] || ws_log "benchmark evidence preserved at: ${WS_EVIDENCE_DIR}"
    exit "${status}"
}
trap ws_bench_exit EXIT

ws_setup_topology
ws_require_cmd sysctl
sysctl -q -w net.ipv4.tcp_timestamps=0
ws_in_client sysctl -q -w net.ipv4.tcp_timestamps=0
ws_start_wirestack
ip addr add "${WS_LINUX_IP}/${WS_PREFIX}" dev "${WS_BRIDGE}"

python3 "${WS_BENCH_HELPER}" server "${WS_LINUX_IP}" "${WS_TCP_PORT}" \
    >"${WS_EVIDENCE_DIR}/linux_server.log" 2>&1 &
WS_LINUX_PID=$!
echo "${WS_LINUX_PID}" >"${WS_EVIDENCE_DIR}/linux_server.pid"
ws_record_identity "${WS_LINUX_PID}" "${WS_EVIDENCE_DIR}/linux_server.pid" python3
for _ in $(seq 1 100); do
    grep -q '^READY' "${WS_EVIDENCE_DIR}/linux_server.log" 2>/dev/null && break
    kill -0 "${WS_LINUX_PID}" 2>/dev/null || ws_die "Linux baseline server exited"
    sleep 0.02
done
grep -q '^READY' "${WS_EVIDENCE_DIR}/linux_server.log" || ws_die "Linux baseline server was not ready"

{
    printf 'repetitions=%s\nwarmups=%s\npayload_bytes=12103\nmtu=%s\ntcp_mss=1460\n' \
        "${WS_BENCH_REPETITIONS}" "${WS_BENCH_WARMUPS}" "${WS_MTU}"
    uname -a
    lscpu
    c++ --version
    cmake --version
    git -C "${WS_REPO_ROOT}" rev-parse HEAD
} >"${WS_EVIDENCE_DIR}/environment.txt"

ws_bench_client() {
    local target="$1" scenario="$2" iteration="$3" server_ip="$4" output="$5" source_trace="${6:-}"
    local go_file="${WS_EVIDENCE_DIR}/${target}_${scenario}_${iteration}.go"
    local log="${WS_EVIDENCE_DIR}/${target}_${scenario}_${iteration}.client.log"
    rm -f "${go_file}"
    ws_in_client python3 "${WS_BENCH_HELPER}" client "${server_ip}" "${WS_TCP_PORT}" \
        "${go_file}" "${output}" "${target}" "${scenario}" "${iteration}" >"${log}" 2>&1 &
    local client_pid=$!
    local pidfile="${WS_EVIDENCE_DIR}/${target}_${scenario}_${iteration}.client.pid"
    echo "${client_pid}" >"${pidfile}"
    ws_record_identity "${client_pid}" "${pidfile}" python3

    local waited=0
    while ! grep -q '^CONNECTED ' "${log}" 2>/dev/null; do
        kill -0 "${client_pid}" 2>/dev/null || break
        waited=$((waited + 1))
        [ "${waited}" -gt 250 ] && break
        sleep 0.02
    done
    grep -q '^CONNECTED ' "${log}" || ws_die "client did not connect: ${log}"
    local client_port
    client_port="$(awk '/^CONNECTED / { print $2; exit }' "${log}")"

    if [ "${scenario}" = "reorder" ]; then
        tc qdisc add dev "${WS_HOST_VETH}" root netem delay 60ms reorder 100% gap 2
    elif [ "${scenario}" = "single" ] || [ "${scenario}" = "double" ]; then
        local synack_seq=""
        waited=0
        while [ -z "${synack_seq}" ]; do
            synack_seq="$(grep "${server_ip}.${WS_TCP_PORT} > ${WS_CLIENT_IP}.${client_port}: Flags \[S\.\]" \
                "${source_trace}" 2>/dev/null \
                | sed -nE 's/.*seq ([0-9]+),.*/\1/p' | tail -1)"
            waited=$((waited + 1))
            [ "${waited}" -gt 250 ] && break
            [ -n "${synack_seq}" ] || sleep 0.02
        done
        [ -n "${synack_seq}" ] || ws_die "SYN-ACK not found for ${target}/${scenario}/${iteration}"

        tc qdisc add dev "${WS_HOST_VETH}" root handle 1: prio bands 3 \
            priomap 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0
        tc qdisc add dev "${WS_HOST_VETH}" parent 1:2 handle 20: netem loss 100%
        local indexes="1" loss_count=1
        if [ "${scenario}" = "double" ]; then
            indexes="1 3"
            loss_count=2
        fi
        local index sequence hex priority
        for index in ${indexes}; do
            sequence=$(( (synack_seq + 1 + index * 1460) & 0xffffffff ))
            printf -v hex '0x%08x' "${sequence}"
            priority=$((index + 1))
            tc filter add dev "${WS_HOST_VETH}" parent 1: protocol ip prio "${priority}" u32 \
                match ip protocol 6 0xff match ip sport "${WS_TCP_PORT}" 0xffff \
                match u32 "${hex}" 0xffffffff at 24 flowid 1:2
        done
        tc filter add dev "${WS_HOST_VETH}" parent 1: protocol ip prio 100 u32 \
            match u32 0 0 at 0 flowid 1:1
        ws_in_client tc qdisc add dev "${WS_CLIENT_VETH}" root netem delay 20ms
        touch "${go_file}"

        local observed_drops=0
        waited=0
        while [ "${observed_drops}" -lt "${loss_count}" ]; do
            kill -0 "${client_pid}" 2>/dev/null || break
            waited=$((waited + 1))
            [ "${waited}" -gt 500 ] && break
            sleep 0.005
            observed_drops="$(tc -s qdisc show dev "${WS_HOST_VETH}" \
                | sed -nE 's/.*\(dropped ([0-9]+),.*/\1/p' | tail -1)"
            observed_drops="${observed_drops:-0}"
        done
        [ "${observed_drops}" -ge "${loss_count}" ] || ws_die "targeted loss was not observed"
        tc qdisc del dev "${WS_HOST_VETH}" root
    fi

    [ "${scenario}" = "single" ] || [ "${scenario}" = "double" ] || touch "${go_file}"
    wait "${client_pid}"
    if [ "${scenario}" = "single" ] || [ "${scenario}" = "double" ]; then
        ws_in_client tc qdisc del dev "${WS_CLIENT_VETH}" root
    fi
    if [ "${scenario}" = "reorder" ]; then
        tc qdisc del dev "${WS_HOST_VETH}" root
    fi
    return 0
}

ws_bench_target() {
    local target="$1" server_ip="$2" source_iface="$3" server_pid="$4"
    local records="${WS_EVIDENCE_DIR}/${target}.jsonl"
    local warmups="${WS_EVIDENCE_DIR}/${target}_warmup.jsonl"
    : >"${records}"
    : >"${warmups}"

    ws_log "${target}: ${WS_BENCH_WARMUPS} separate warm-up transfers"
    local iteration
    for iteration in $(seq 1 "${WS_BENCH_WARMUPS}"); do
        ws_bench_client "${target}" warmup "${iteration}" "${server_ip}" "${warmups}"
    done
    local start_snapshot
    start_snapshot="$(python3 "${WS_BENCH_HELPER}" snapshot "${server_pid}")"

    local scenario name source_pcap live_trace live_log live_pid live_pidfile
    for scenario in normal single double reorder; do
        name="${target}_${scenario}"
        ws_log "${target}/${scenario}: ${WS_BENCH_REPETITIONS} measured transfers"
        ws_capture_start "${name}_source" "${source_iface}"
        ws_capture_start "${name}_host" "${WS_HOST_VETH}"
        source_pcap="${WS_EVIDENCE_DIR}/${name}_source.pcap"
        live_trace="${WS_EVIDENCE_DIR}/${name}.live.txt"
        live_log="${WS_EVIDENCE_DIR}/${name}.live.log"
        tcpdump --immediate-mode -i "${source_iface}" -l -n -S "tcp port ${WS_TCP_PORT}" \
            >"${live_trace}" 2>"${live_log}" &
        live_pid=$!
        live_pidfile="${WS_EVIDENCE_DIR}/${name}.live.pid"
        echo "${live_pid}" >"${live_pidfile}"
        ws_record_identity "${live_pid}" "${live_pidfile}" tcpdump
        for _ in $(seq 1 100); do
            grep -q 'listening on' "${live_log}" 2>/dev/null && break
            sleep 0.02
        done
        grep -q 'listening on' "${live_log}" || ws_die "live tcpdump failed to start"
        for iteration in $(seq 1 "${WS_BENCH_REPETITIONS}"); do
            ws_bench_client "${target}" "${scenario}" "${iteration}" "${server_ip}" \
                "${records}" "${live_trace}"
        done
        kill -INT "${live_pid}" 2>/dev/null || true
        wait "${live_pid}" 2>/dev/null || true
        ws_capture_stop "${name}_source"
        ws_capture_stop "${name}_host"
        tcpdump -r "${source_pcap}" -n -tttt >"${WS_EVIDENCE_DIR}/${name}.oneline.txt" 2>/dev/null
        python3 "${WS_BENCH_HELPER}" trace "${WS_EVIDENCE_DIR}/${name}.oneline.txt" \
            "${server_ip}" "${WS_CLIENT_IP}" "${WS_TCP_PORT}" \
            >"${WS_EVIDENCE_DIR}/${name}.trace.json"
    done

    local end_snapshot
    end_snapshot="$(python3 "${WS_BENCH_HELPER}" snapshot "${server_pid}")"
    python3 "${WS_BENCH_HELPER}" summarize "${records}" "${target}" \
        "${start_snapshot}" "${end_snapshot}" >"${WS_EVIDENCE_DIR}/${target}.summary.json"
    cat "${WS_EVIDENCE_DIR}/${target}.summary.json"
}

WS_WIRESTACK_PID="$(cat "${WS_EVIDENCE_DIR}/${WS_WIRESTACK_PIDFILE_NAME}")"
ws_bench_target wirestack "${WS_SERVER_IP}" "${WS_TAP}" "${WS_WIRESTACK_PID}"
ws_bench_target linux "${WS_LINUX_IP}" "${WS_BRIDGE}" "${WS_LINUX_PID}"

ws_log "benchmark results: ${WS_EVIDENCE_DIR}"
WS_CLEANED_UP=1
ws_cleanup
