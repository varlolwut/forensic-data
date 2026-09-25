#!/usr/bin/env bash
set -euo pipefail

FIXTURE_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
readonly FIXTURE_ROOT
readonly BASE_COMPOSE_FILE="${FIXTURE_ROOT}/compose.yaml"
readonly INTEGRATION_COMPOSE_FILE="${FIXTURE_ROOT}/compose.integration.yaml"
readonly -a COMPOSE_FILES=(
  --file "${BASE_COMPOSE_FILE}"
  --file "${INTEGRATION_COMPOSE_FILE}"
)

verify_runtime_configuration() {
  local service="$1"
  local package_manifest="$2"
  local container_port="$3"
  local host_port="$4"
  local container_id
  container_id="$(docker compose "${COMPOSE_FILES[@]}" ps --quiet "${service}")"
  if [[ -z "${container_id}" ]]; then
    echo "Compose service ${service} is not running." >&2
    return 1
  fi

  local published_ports
  published_ports="$(docker port "${container_id}")"
  local expected_port="${container_port}/tcp -> 127.0.0.1:${host_port}"
  if [[ "${published_ports}" != "${expected_port}" ]]; then
    echo "Compose service ${service} has unexpected published ports: ${published_ports}" >&2
    return 1
  fi

  local runtime_values
  runtime_values="$(docker inspect \
    --format '{{.HostConfig.Memory}}|{{.HostConfig.NanoCpus}}|{{.HostConfig.ShmSize}}|{{.HostConfig.RestartPolicy.Name}}' \
    "${container_id}")"
  if [[ "${runtime_values}" != "4294967296|4000000000|1073741824|no" ]]; then
    echo "Compose service ${service} has unexpected runtime limits: ${runtime_values}" >&2
    return 1
  fi

  local image_id
  image_id="$(docker inspect --format '{{.Image}}' "${container_id}")"
  local ssh_material
  ssh_material="$(docker run --rm --entrypoint /bin/sh "${image_id}" -c \
    "find /home/gpadmin/.ssh -mindepth 1 -type f -print && find /etc/ssh -maxdepth 1 -type f -name 'ssh_host_*_key' -print")"
  if [[ -n "${ssh_material}" ]]; then
    echo "Compose service ${service} image contains generated SSH material." >&2
    return 1
  fi

  printf '%s|IMAGE_ID|%s\n' "${service}" "${image_id}"
  docker run --rm --entrypoint test "${image_id}" -s "${package_manifest}"
  docker run --rm --entrypoint sha256sum "${image_id}" "${package_manifest}"
  printf '%s|LOOPBACK_PORT|%s\n' "${service}" "${published_ports}"
  printf '%s|RUNTIME_LIMITS|%s\n' "${service}" "${runtime_values}"
}

verify_original_greenplum_source_pruning() {
  local container_id
  container_id="$(docker compose "${COMPOSE_FILES[@]}" ps --quiet original-greenplum)"
  local image_id
  image_id="$(docker inspect --format '{{.Image}}' "${container_id}")"
  if ! docker run --rm --entrypoint /bin/sh "${image_id}" -c \
    'test ! -e /workspace/gpdb/ci && test ! -e /workspace/gpdb/concourse'; then
    echo "Original Greenplum image retains excluded upstream CI material." >&2
    return 1
  fi
}

if [[ -z "${DFE_GREENGAGE_PORT:-}" || -z "${DFE_ORIGINAL_GREENPLUM_PORT:-}" ]]; then
  echo "Integration verification requires both explicit fixture port variables." >&2
  exit 1
fi

docker compose "${COMPOSE_FILES[@]}" exec --no-TTY --user gpadmin \
  greengage /usr/local/bin/dfe-greengage-healthcheck
docker compose "${COMPOSE_FILES[@]}" exec --no-TTY --user gpadmin \
  original-greenplum /usr/local/bin/dfe-original-greenplum-healthcheck
docker compose "${COMPOSE_FILES[@]}" exec --no-TTY --user gpadmin \
  greengage /usr/local/bin/dfe-greengage-verify
docker compose "${COMPOSE_FILES[@]}" exec --no-TTY --user gpadmin \
  original-greenplum /usr/local/bin/dfe-original-greenplum-verify
docker compose "${COMPOSE_FILES[@]}" exec --no-TTY greengage \
  test -f /data/.dfe-integration-ready
docker compose "${COMPOSE_FILES[@]}" exec --no-TTY original-greenplum \
  test -f /home/gpadmin/gpdemo-data/.dfe-integration-ready

verify_runtime_configuration \
  greengage \
  /opt/greengagedb/greengage7/dfe-build-dpkg-manifest.txt \
  5432 \
  "${DFE_GREENGAGE_PORT}"
verify_runtime_configuration \
  original-greenplum \
  /usr/local/gpdb/dfe-build-rpm-manifest.txt \
  15432 \
  "${DFE_ORIGINAL_GREENPLUM_PORT}"
verify_original_greenplum_source_pruning

echo "Original Greenplum and Greengage integration fixture verification passed."
