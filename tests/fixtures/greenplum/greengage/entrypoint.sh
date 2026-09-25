#!/usr/bin/env bash
set -euo pipefail

readonly GREENGAGE_HOME=/opt/greengagedb/greengage7
readonly COORDINATOR_DATA_DIRECTORY=/data/coordinator/ggseg-1
readonly INITIALIZATION_MARKER=/data/.dfe-initialized
readonly INTEGRATION_READY_MARKER=/data/.dfe-integration-ready
readonly READER_PASSWORD_FILE=/run/secrets/dfe-greengage-reader-password

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
      "ssh -o BatchMode=yes -o ConnectTimeout=1 -o StrictHostKeyChecking=no greengage true"; then
      return 0
    fi
    echo "Greengage self-SSH is not ready (attempt ${attempt}/30)." >&2
    sleep 1
  done
  echo "Greengage self-SSH did not become ready after 30 attempts." >&2
  return 1
}

shutdown_cluster() {
  trap - TERM INT
  local status=0
  if [[ -f "${COORDINATOR_DATA_DIRECTORY}/PG_VERSION" ]]; then
    set +e
    run_as_gpadmin \
      "source ${GREENGAGE_HOME}/greengage_path.sh && export COORDINATOR_DATA_DIRECTORY=${COORDINATOR_DATA_DIRECTORY} && gpstop -a -M fast -t 120"
    status=$?
    set -e
  fi
  if (( status != 0 )); then
    echo "Greengage did not stop cleanly; gpstop exited ${status}." >&2
  fi
  exit "${status}"
}

install --directory --owner=gpadmin --group=gpadmin /data/coordinator /data/primary1 /data/primary2
if [[ -e "${READER_PASSWORD_FILE}" ]]; then
  rm -f "${INTEGRATION_READY_MARKER}"
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
  "open_files=\$(ssh -o BatchMode=yes -o ConnectTimeout=1 greengage 'ulimit -n'); if (( open_files < 65536 )); then echo 'gpadmin self-SSH nofile limit is below 65536.' >&2; exit 1; fi"

if [[ -f "${INITIALIZATION_MARKER}" ]]; then
  if [[ ! -f "${COORDINATOR_DATA_DIRECTORY}/PG_VERSION" ]]; then
    echo "Greengage initialization marker exists without a coordinator. Remove the fixture volume and recreate it." >&2
    exit 1
  fi
  run_as_gpadmin \
    "source ${GREENGAGE_HOME}/greengage_path.sh && export COORDINATOR_DATA_DIRECTORY=${COORDINATOR_DATA_DIRECTORY} && gpstart -a"
else
  if find /data/coordinator /data/primary1 /data/primary2 -mindepth 1 -print -quit | grep --quiet .; then
    echo "Greengage data exists without a completed initialization marker. Remove the fixture volume and recreate it." >&2
    exit 1
  fi
  printf '%s\n' greengage >/home/gpadmin/hostfile
  chown gpadmin:gpadmin /home/gpadmin/hostfile
  run_as_gpadmin \
    "source ${GREENGAGE_HOME}/greengage_path.sh && gpinitsystem -a -c /home/gpadmin/gpinitsystem_config"
  run_as_gpadmin /usr/local/bin/dfe-greengage-healthcheck
  touch "${INITIALIZATION_MARKER}"
  chown gpadmin:gpadmin "${INITIALIZATION_MARKER}"
fi

if [[ -e "${READER_PASSWORD_FILE}" ]]; then
  /usr/local/bin/dfe-greengage-setup-integration "${READER_PASSWORD_FILE}"
  touch "${INTEGRATION_READY_MARKER}"
  chown gpadmin:gpadmin "${INTEGRATION_READY_MARKER}"
fi

run_as_gpadmin /usr/local/bin/dfe-greengage-healthcheck

while true; do
  sleep 3600 &
  wait $!
done
