#!/usr/bin/env bash
set -euo pipefail

readonly GREENPLUM_HOME=/usr/local/gpdb
readonly DEMO_ROOT=/workspace/gpdb/gpAux/gpdemo
readonly DATA_ROOT=/home/gpadmin/gpdemo-data
readonly MASTER_DATA_DIRECTORY=/home/gpadmin/gpdemo-data/qddir/demoDataDir-1
readonly INITIALIZATION_MARKER=/home/gpadmin/gpdemo-data/.dfe-initialized
readonly INTEGRATION_READY_MARKER=/home/gpadmin/gpdemo-data/.dfe-integration-ready
readonly READER_PASSWORD_FILE=/run/secrets/dfe-original-greenplum-reader-password
readonly WRITER_PASSWORD_FILE=/run/secrets/dfe-original-greenplum-writer-password
export MASTER_DATA_DIRECTORY

run_as_gpadmin() {
  local command="$1"
  runuser --user gpadmin -- \
    env HOME=/home/gpadmin USER=gpadmin LOGNAME=gpadmin \
    /bin/bash -c "${command}"
}

wait_for_self_ssh() {
  local attempt
  for attempt in $(seq 1 30); do
    if run_as_gpadmin \
      "ssh -o BatchMode=yes -o ConnectTimeout=1 -o StrictHostKeyChecking=no original-gp true"; then
      return 0
    fi
    echo "Original Greenplum self-SSH is not ready (attempt ${attempt}/30)." >&2
    sleep 1
  done
  echo "Original Greenplum self-SSH did not become ready after 30 attempts." >&2
  return 1
}

shutdown_cluster() {
  trap - TERM INT
  local status=0
  if [[ -f "${MASTER_DATA_DIRECTORY}/PG_VERSION" ]]; then
    set +e
    run_as_gpadmin \
      "source ${GREENPLUM_HOME}/greenplum_path.sh && gpstop -a -M fast -t 120 -d ${MASTER_DATA_DIRECTORY}"
    status=$?
    set -e
  fi
  if (( status != 0 )); then
    echo "Original Greenplum did not stop cleanly; gpstop exited ${status}." >&2
  fi
  exit "${status}"
}

test "$(/workspace/gpdb/getversion)" = "4.3.99.00 build dev"
install --directory --owner=gpadmin --group=gpadmin "${DATA_ROOT}"
if [[ -e "${READER_PASSWORD_FILE}" || -e "${WRITER_PASSWORD_FILE}" ]]; then
  rm -f "${INTEGRATION_READY_MARKER}"
  if [[ ! -f "${READER_PASSWORD_FILE}" || ! -f "${WRITER_PASSWORD_FILE}" ]]; then
    echo "Original Greenplum integration requires both reader and writer password secrets." >&2
    exit 1
  fi
fi
install --directory --owner=gpadmin --group=gpadmin --mode=0700 /home/gpadmin/.ssh
ssh-keygen -A
if [[ ! -f /home/gpadmin/.ssh/id_ed25519 ]]; then
  run_as_gpadmin "ssh-keygen -q -t ed25519 -N '' -f /home/gpadmin/.ssh/id_ed25519"
fi
cp /home/gpadmin/.ssh/id_ed25519.pub /home/gpadmin/.ssh/authorized_keys
chown gpadmin:gpadmin /home/gpadmin/.ssh/authorized_keys
chmod 0600 /home/gpadmin/.ssh/authorized_keys
/usr/sbin/sshd
wait_for_self_ssh
trap shutdown_cluster TERM INT

run_as_gpadmin \
  "open_files=\$(ssh -o BatchMode=yes -o ConnectTimeout=1 original-gp 'ulimit -n'); if (( open_files < 65536 )); then echo 'gpadmin self-SSH nofile limit is below 65536.' >&2; exit 1; fi"

if [[ -f "${INITIALIZATION_MARKER}" ]]; then
  if [[ ! -f "${MASTER_DATA_DIRECTORY}/PG_VERSION" ]]; then
    echo "Original Greenplum initialization marker exists without a coordinator. Remove the fixture volume and recreate it." >&2
    exit 1
  fi
  run_as_gpadmin \
    "source ${GREENPLUM_HOME}/greenplum_path.sh && gpstart -a -d ${MASTER_DATA_DIRECTORY}"
else
  if find "${DATA_ROOT}" -mindepth 1 -print -quit | grep --quiet .; then
    echo "Original Greenplum data exists without a completed initialization marker. Remove the fixture volume and recreate it." >&2
    exit 1
  fi
  run_as_gpadmin \
    "source ${GREENPLUM_HOME}/greenplum_path.sh && cd ${DEMO_ROOT} && NUM_PRIMARY_MIRROR_PAIRS=2 DATADIRS=${DATA_ROOT} MASTER_PORT=15432 PORT_BASE=25432 make check && NUM_PRIMARY_MIRROR_PAIRS=2 DATADIRS=${DATA_ROOT} MASTER_PORT=15432 PORT_BASE=25432 make cluster"
  run_as_gpadmin /usr/local/bin/dfe-original-greenplum-healthcheck
  touch "${INITIALIZATION_MARKER}"
  chown gpadmin:gpadmin "${INITIALIZATION_MARKER}"
fi

if [[ -e "${READER_PASSWORD_FILE}" && -e "${WRITER_PASSWORD_FILE}" ]]; then
  /usr/local/bin/dfe-original-greenplum-setup-integration \
    "${READER_PASSWORD_FILE}" \
    "${WRITER_PASSWORD_FILE}"
  touch "${INTEGRATION_READY_MARKER}"
  chown gpadmin:gpadmin "${INTEGRATION_READY_MARKER}"
fi

run_as_gpadmin /usr/local/bin/dfe-original-greenplum-healthcheck

while true; do
  sleep 3600 &
  wait $!
done
