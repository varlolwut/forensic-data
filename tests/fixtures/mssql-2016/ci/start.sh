#!/usr/bin/env bash
set -Eeuo pipefail

readonly WINDOWS_ISO_URL="https://software-static.download.prss.microsoft.com/dbazure/988969d5-f34g-4e03-ac9d-1f9786c66749/17763.3650.221105-1748.rs5_release_svc_refresh_SERVER_EVAL_x64FRE_en-us.iso"
readonly WINDOWS_ISO_BYTES="5652088832"
readonly WINDOWS_ISO_SHA256="6dae072e7f78f4ccab74a45341de0d6e2d45c39be25f1f5920a2ab4f51d7bcbb"
readonly SQL_EXPRESS_URL="https://download.microsoft.com/download/f/9/8/f982347c-fee3-4b3e-a8dc-c95383aa3020/sql16_sp3_dlc/en-us/SQLEXPR_x64_ENU.exe"
readonly SQL_EXPRESS_BYTES="564016512"
readonly SQL_EXPRESS_SHA256="123f35eb622e56a45a6a0ad951760aaba0df8b908f30ed5d4aa0f93bc93fd448"
readonly SQL_GDR_URL="https://catalog.s.download.windowsupdate.com/d/msdownload/update/software/secu/2026/06/sqlserver2016-kb5102340-x64_35e5ef7a44a1851cd658c5aef3294559d67cb817.exe"
readonly SQL_GDR_BYTES="536162048"
readonly SQL_GDR_SHA256="e86109191b199a1347ad7ff62d2c785d1caa5538fedafdf096c87ed0e78e0201"
readonly EXPECTED_READY="DFE_SQL2016_READY product_version=13.0.6500.1 instance=SQLEXPRESS tcp_port=1433"
readonly HOST_SQL_PORT="51416"
readonly INSTALL_TIMEOUT_SECONDS="3600"
readonly MINIMUM_FREE_KIB=$((28 * 1024 * 1024))
readonly MINIMUM_AVAILABLE_MEMORY_KIB=$((7 * 1024 * 1024))

fail() {
    printf 'SQL Server 2016 CI fixture: %s\n' "$1" >&2
    exit 1
}

require_command() {
    command -v "$1" >/dev/null 2>&1 || fail "required command is unavailable: $1"
}

require_direct_runner_child() {
    local requested_path="$1"
    local runner_root="$2"
    local normalized_path

    [[ "$requested_path" == /* ]] || fail "fixture directory must be an absolute path"
    normalized_path="$(realpath -m -- "$requested_path")"
    [[ "$(dirname -- "$normalized_path")" == "$runner_root" ]] ||
        fail "fixture directory must be a direct child of RUNNER_TEMP"
    printf '%s\n' "$normalized_path"
}

validate_password() {
    local password="$1"

    ((${#password} >= 16 && ${#password} <= 64)) ||
        fail "DFE_MSSQL_2016_SA_PASSWORD must contain 16 to 64 ASCII characters"
    [[ "$password" =~ ^[A-Za-z0-9_.!@#%+=,-]+$ ]] ||
        fail "DFE_MSSQL_2016_SA_PASSWORD contains a character unsafe for unattended provisioning"
    [[ "$password" =~ [A-Z] ]] || fail "DFE_MSSQL_2016_SA_PASSWORD must contain an uppercase letter"
    [[ "$password" =~ [a-z] ]] || fail "DFE_MSSQL_2016_SA_PASSWORD must contain a lowercase letter"
    [[ "$password" =~ [0-9] ]] || fail "DFE_MSSQL_2016_SA_PASSWORD must contain a digit"
    [[ "$password" =~ [_.!@#%+=,-] ]] || fail "DFE_MSSQL_2016_SA_PASSWORD must contain punctuation"
}

download_verified() {
    local url="$1"
    local expected_bytes="$2"
    local expected_sha256="$3"
    local destination="$4"
    local partial_path="${destination}.part"
    local actual_bytes
    local actual_sha256

    curl --fail --location --silent --show-error \
        --retry 3 --retry-all-errors --retry-max-time 1800 \
        --connect-timeout 30 --max-time 1800 \
        --output "$partial_path" "$url"
    actual_bytes="$(stat --format='%s' -- "$partial_path")"
    [[ "$actual_bytes" == "$expected_bytes" ]] ||
        fail "downloaded media size mismatch for $(basename -- "$destination"): expected=$expected_bytes actual=$actual_bytes"
    actual_sha256="$(sha256sum -- "$partial_path" | cut -d ' ' -f 1)"
    [[ "$actual_sha256" == "$expected_sha256" ]] ||
        fail "downloaded media SHA-256 mismatch for $(basename -- "$destination"): expected=$expected_sha256 actual=$actual_sha256"
    mv -- "$partial_path" "$destination"
}

require_port_available() {
    python3 - "$HOST_SQL_PORT" <<'PY'
import socket
import sys

port = int(sys.argv[1])
try:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as listener:
        listener.bind(("127.0.0.1", port))
except OSError:
    raise SystemExit(1)
PY
}

wait_for_host_port() {
    local deadline=$((SECONDS + 120))

    while ((SECONDS < deadline)); do
        if python3 - "$HOST_SQL_PORT" <<'PY'
import socket
import sys

port = int(sys.argv[1])
try:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as client:
        client.settimeout(2.0)
        client.connect(("127.0.0.1", port))
except OSError:
    raise SystemExit(1)
PY
        then
            return
        fi
        sleep 2
    done
    fail "guest reported ready, but SQL Server did not accept the loopback TCP forwarding within 120 seconds"
}

send_boot_key() {
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
        stream.write(
            json.dumps(
                {
                    "execute": "send-key",
                    "arguments": {
                        "keys": [{"type": "qcode", "data": "spc"}],
                        "hold-time": 100,
                    },
                    "id": "boot-key",
                }
            ).encode()
            + b"\n"
        )
        receive_response(stream, "boot-key")
PY
}

if (($# != 1)); then
    fail "usage: start.sh ABSOLUTE_RUNNER_TEMP_CHILD"
fi
fixture_password="${DFE_MSSQL_2016_SA_PASSWORD:-}"
unset DFE_MSSQL_2016_SA_PASSWORD
validate_password "$fixture_password"

for required_command in \
    curl cut df dirname grep kill mkdir mv nproc python3 qemu-img \
    qemu-system-x86_64 realpath sha256sum stat tr xorriso; do
    require_command "$required_command"
done

[[ -n "${RUNNER_TEMP:-}" ]] || fail "RUNNER_TEMP is not set"
runner_root="$(realpath -e -- "$RUNNER_TEMP")"
[[ -d "$runner_root" ]] || fail "RUNNER_TEMP is not a directory"
fixture_root="$(require_direct_runner_child "$1" "$runner_root")"
[[ ! -e "$fixture_root" && ! -L "$fixture_root" ]] || fail "fixture directory already exists: $fixture_root"

[[ -c /dev/kvm && -r /dev/kvm && -w /dev/kvm ]] || fail "/dev/kvm is unavailable to the current user"
logical_cpu_count="$(nproc)"
[[ "$logical_cpu_count" =~ ^[0-9]+$ ]] || fail "could not read the logical CPU count"
((logical_cpu_count >= 4)) || fail "at least four logical CPUs are required"
available_memory_kib="$(awk '/^MemAvailable:/ { print $2 }' /proc/meminfo)"
[[ "$available_memory_kib" =~ ^[0-9]+$ ]] || fail "could not read available host memory"
((available_memory_kib >= MINIMUM_AVAILABLE_MEMORY_KIB)) ||
    fail "at least 7 GiB of available host memory is required"
available_disk_kib="$(df -Pk -- "$runner_root" | awk 'NR == 2 { print $4 }')"
[[ "$available_disk_kib" =~ ^[0-9]+$ ]] || fail "could not read available runner disk space"
((available_disk_kib >= MINIMUM_FREE_KIB)) || fail "at least 28 GiB of free runner disk is required"
require_port_available || fail "loopback TCP port $HOST_SQL_PORT is already in use"

script_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"
umask 077
mkdir -- "$fixture_root"
fixture_root="$(realpath -e -- "$fixture_root")"
printf 'version=1\nroot=%s\nvm_name=dfe-sql2016-ci\n' "$fixture_root" >"$fixture_root/.dfe-mssql2016-ci-owned"

cleanup_required=1
cleanup_on_exit() {
    local exit_code=$?
    trap - EXIT INT TERM
    if ((cleanup_required != 0)) && [[ -d "$fixture_root" ]]; then
        if ! bash "$script_dir/stop.sh" "$fixture_root"; then
            printf 'SQL Server 2016 CI fixture: automatic cleanup failed for %s\n' "$fixture_root" >&2
        fi
    fi
    exit "$exit_code"
}
trap cleanup_on_exit EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

mkdir -- "$fixture_root/media" "$fixture_root/provision-src"
template="$(<"$script_dir/Autounattend.xml.in")"
[[ "$(grep -o '@@ADMIN_PASSWORD_XML@@' <<<"$template" | wc -l)" == "1" ]] ||
    fail "Autounattend template must contain exactly one password placeholder"
printf '%s' "${template//@@ADMIN_PASSWORD_XML@@/$fixture_password}" >"$fixture_root/provision-src/Autounattend.xml"
printf '%s' "$fixture_password" >"$fixture_root/provision-src/fixture-secret.txt"
fixture_password=''
unset fixture_password template

cp -- "$script_dir/bootstrap.cmd" "$fixture_root/provision-src/bootstrap.cmd"
cp -- "$script_dir/bootstrap.ps1" "$fixture_root/provision-src/bootstrap.ps1"
cp -- "$script_dir/dfe-sql2016-ci.marker" "$fixture_root/provision-src/dfe-sql2016-ci.marker"

windows_iso="$fixture_root/media/windows-server-2019-eval.iso"
sql_express="$fixture_root/media/SQLEXPR_x64_ENU.exe"
sql_gdr="$fixture_root/media/SQLServer2016-KB5102340-x64.exe"
download_verified "$WINDOWS_ISO_URL" "$WINDOWS_ISO_BYTES" "$WINDOWS_ISO_SHA256" "$windows_iso"
download_verified "$SQL_EXPRESS_URL" "$SQL_EXPRESS_BYTES" "$SQL_EXPRESS_SHA256" "$sql_express"
download_verified "$SQL_GDR_URL" "$SQL_GDR_BYTES" "$SQL_GDR_SHA256" "$sql_gdr"
cp -- "$sql_express" "$fixture_root/provision-src/SQLEXPR_x64_ENU.exe"
cp -- "$sql_gdr" "$fixture_root/provision-src/SQLServer2016-KB5102340-x64.exe"

provision_iso="$fixture_root/provision.iso"
xorriso -as mkisofs -quiet -iso-level 3 -J -R -V DFE_SQL2016_CI \
    -o "$provision_iso" "$fixture_root/provision-src"
disk="$fixture_root/sql2016.qcow2"
serial_log="$fixture_root/serial.log"
qmp_socket="$fixture_root/qmp.sock"
pid_file="$fixture_root/qemu.pid"
qemu-img create -q -f qcow2 "$disk" 60G

qemu-system-x86_64 \
    -name dfe-sql2016-ci \
    -machine type=pc,accel=kvm \
    -enable-kvm \
    -cpu host \
    -smp 4 \
    -m 6144 \
    -drive "file=$disk,if=ide,format=qcow2" \
    -drive "file=$windows_iso,media=cdrom,if=ide,format=raw,readonly=on" \
    -drive "file=$provision_iso,media=cdrom,if=ide,format=raw,readonly=on" \
    -boot once=d,menu=off \
    -netdev "user,id=net0,restrict=on,hostfwd=tcp:127.0.0.1:$HOST_SQL_PORT-:1433" \
    -device e1000,netdev=net0 \
    -display none \
    -serial "file:$serial_log" \
    -qmp "unix:$qmp_socket,server=on,wait=off" \
    -daemonize \
    -pidfile "$pid_file"

qemu_pid="$(<"$pid_file")"
[[ "$qemu_pid" =~ ^[1-9][0-9]*$ ]] || fail "QEMU did not publish a valid PID"
kill -0 "$qemu_pid" 2>/dev/null || fail "QEMU exited immediately after launch"
for boot_key_attempt in 1 2 3; do
    sleep 2
    kill -0 "$qemu_pid" 2>/dev/null || fail "QEMU exited before the Windows installation media booted"
    send_boot_key "$qmp_socket"
done

deadline=$((SECONDS + INSTALL_TIMEOUT_SECONDS))
last_stage=''
while ((SECONDS < deadline)); do
    kill -0 "$qemu_pid" 2>/dev/null || fail "QEMU exited before SQL Server became ready"
    if [[ -f "$serial_log" ]]; then
        error_line="$(tr -d '\r' <"$serial_log" | grep -a '^DFE_SQL2016_ERROR ' | tail -n 1 || true)"
        [[ -z "$error_line" ]] || fail "guest provisioning failed: $error_line"
        if tr -d '\r' <"$serial_log" | grep -aFxq "$EXPECTED_READY"; then
            wait_for_host_port
            cleanup_required=0
            printf 'SQL Server 2016 CI fixture is ready at 127.0.0.1:%s (PID %s).\n' "$HOST_SQL_PORT" "$qemu_pid"
            exit 0
        fi
        current_stage="$(tr -d '\r' <"$serial_log" | grep -a '^DFE_SQL2016_STAGE ' | tail -n 1 || true)"
        if [[ -n "$current_stage" && "$current_stage" != "$last_stage" ]]; then
            printf '%s\n' "$current_stage"
            last_stage="$current_stage"
        fi
    fi
    sleep 5
done

fail "guest did not report SQL Server 13.0.6500.1 ready within $INSTALL_TIMEOUT_SECONDS seconds; last_stage=${last_stage:-none}"
