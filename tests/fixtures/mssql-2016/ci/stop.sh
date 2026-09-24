#!/usr/bin/env bash
set -Eeuo pipefail

fail() {
    printf 'SQL Server 2016 CI fixture cleanup: %s\n' "$1" >&2
    exit 1
}

require_direct_runner_child() {
    local requested_path="$1"
    local runner_root="$2"
    local resolved_path

    [[ "$requested_path" == /* ]] || fail "fixture directory must be an absolute path"
    [[ ! -L "$requested_path" ]] || fail "fixture directory must not be a symbolic link"
    resolved_path="$(realpath -e -- "$requested_path")"
    [[ "$(dirname -- "$resolved_path")" == "$runner_root" ]] ||
        fail "fixture directory must be a direct child of RUNNER_TEMP"
    printf '%s\n' "$resolved_path"
}

process_is_owned() {
    local pid="$1"
    local fixture_root="$2"
    local executable
    local arguments

    [[ -r "/proc/$pid/exe" && -r "/proc/$pid/cmdline" ]] || return 1
    executable="$(readlink -f -- "/proc/$pid/exe")"
    [[ "$(basename -- "$executable")" == "qemu-system-x86_64" ]] || return 1
    arguments="$(tr '\0' '\n' <"/proc/$pid/cmdline")"
    grep -Fqx -- "file=$fixture_root/sql2016.qcow2,if=ide,format=qcow2" <<<"$arguments" || return 1
    grep -Fqx -- "unix:$fixture_root/qmp.sock,server=on,wait=off" <<<"$arguments" || return 1
}

request_powerdown() {
    local qmp_socket="$1"

    python3 - "$qmp_socket" <<'PY'
import json
import socket
import sys


def receive_response(stream, request_id):
    while True:
        line = stream.readline()
        if not line:
            raise RuntimeError("QMP disconnected before replying")
        message = json.loads(line)
        if message.get("id") == request_id:
            if "error" in message:
                raise RuntimeError(f"QMP command failed: {message['error'].get('class', 'unknown')}")
            return


path = sys.argv[1]
with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as client:
    client.settimeout(5.0)
    client.connect(path)
    with client.makefile("rwb", buffering=0) as stream:
        greeting = json.loads(stream.readline())
        if "QMP" not in greeting:
            raise RuntimeError("QMP greeting is missing")
        stream.write(json.dumps({"execute": "qmp_capabilities", "id": "capabilities"}).encode() + b"\n")
        receive_response(stream, "capabilities")
        stream.write(json.dumps({"execute": "system_powerdown", "id": "powerdown"}).encode() + b"\n")
        receive_response(stream, "powerdown")
PY
}

wait_for_exit() {
    local pid="$1"
    local maximum_seconds="$2"
    local deadline=$((SECONDS + maximum_seconds))

    while ((SECONDS < deadline)); do
        kill -0 "$pid" 2>/dev/null || return 0
        sleep 1
    done
    return 1
}

if (($# != 1)); then
    fail "usage: stop.sh ABSOLUTE_RUNNER_TEMP_CHILD"
fi
unset DFE_MSSQL_2016_SA_PASSWORD
[[ -n "${RUNNER_TEMP:-}" ]] || fail "RUNNER_TEMP is not set"
command -v python3 >/dev/null 2>&1 || fail "required command is unavailable: python3"
runner_root="$(realpath -e -- "$RUNNER_TEMP")"
[[ -d "$runner_root" ]] || fail "RUNNER_TEMP is not a directory"

if [[ ! -e "$1" && ! -L "$1" ]]; then
    exit 0
fi
fixture_root="$(require_direct_runner_child "$1" "$runner_root")"
ownership_file="$fixture_root/.dfe-mssql2016-ci-owned"
[[ -f "$ownership_file" && ! -L "$ownership_file" ]] || fail "ownership marker is missing or invalid"
grep -Fxq 'version=1' "$ownership_file" || fail "ownership marker version is invalid"
grep -Fxq "root=$fixture_root" "$ownership_file" || fail "ownership marker does not match the fixture directory"
grep -Fxq 'vm_name=dfe-sql2016-ci' "$ownership_file" || fail "ownership marker VM name is invalid"

pid_file="$fixture_root/qemu.pid"
if [[ -e "$pid_file" || -L "$pid_file" ]]; then
    [[ -f "$pid_file" && ! -L "$pid_file" ]] || fail "QEMU PID file is not a regular owned file"
    qemu_pid="$(<"$pid_file")"
    [[ "$qemu_pid" =~ ^[1-9][0-9]*$ ]] || fail "QEMU PID file is invalid"
    if kill -0 "$qemu_pid" 2>/dev/null; then
        process_is_owned "$qemu_pid" "$fixture_root" || fail "PID $qemu_pid is not the owned QEMU process"
        if [[ -S "$fixture_root/qmp.sock" ]]; then
            if ! request_powerdown "$fixture_root/qmp.sock"; then
                printf 'SQL Server 2016 CI fixture cleanup: QMP powerdown failed; bounded signal cleanup will continue\n' >&2
            fi
        fi
        if ! wait_for_exit "$qemu_pid" 120; then
            process_is_owned "$qemu_pid" "$fixture_root" || fail "QEMU ownership changed before termination"
            kill -TERM "$qemu_pid"
            if ! wait_for_exit "$qemu_pid" 15; then
                process_is_owned "$qemu_pid" "$fixture_root" || fail "QEMU ownership changed before forced termination"
                kill -KILL "$qemu_pid"
                wait_for_exit "$qemu_pid" 10 || fail "owned QEMU process did not terminate"
            fi
        fi
    fi
elif [[ -S "$fixture_root/qmp.sock" ]]; then
    fail "QMP socket exists without an owned QEMU PID file"
fi

fixture_root="$(require_direct_runner_child "$fixture_root" "$runner_root")"
[[ -f "$fixture_root/.dfe-mssql2016-ci-owned" && ! -L "$fixture_root/.dfe-mssql2016-ci-owned" ]] ||
    fail "ownership marker changed before cleanup"
grep -Fxq "root=$fixture_root" "$fixture_root/.dfe-mssql2016-ci-owned" ||
    fail "ownership marker changed before cleanup"
rm -rf --one-file-system -- "$fixture_root"
