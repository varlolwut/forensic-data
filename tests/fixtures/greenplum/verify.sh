#!/usr/bin/env bash
set -euo pipefail

FIXTURE_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
readonly FIXTURE_ROOT
readonly COMPOSE_FILE="${FIXTURE_ROOT}/compose.yaml"

verify_runtime_configuration() {
  local service="$1"
  local package_manifest="$2"
  local container_id
  container_id="$(docker compose --file "${COMPOSE_FILE}" ps --quiet "${service}")"
  if [[ -z "${container_id}" ]]; then
    echo "Compose service ${service} is not running." >&2
    return 1
  fi

  local runtime_values
  runtime_values="$(docker inspect \
    --format '{{.HostConfig.Memory}}|{{.HostConfig.NanoCpus}}|{{.HostConfig.ShmSize}}|{{.HostConfig.RestartPolicy.Name}}' \
    "${container_id}")"
  if [[ "${runtime_values}" != "4294967296|4000000000|1073741824|no" ]]; then
    echo "Compose service ${service} has unexpected memory, CPU, shared-memory, or restart limits: ${runtime_values}" >&2
    return 1
  fi

  local published_ports
  published_ports="$(docker port "${container_id}")"
  if [[ -n "${published_ports}" ]]; then
    echo "Compose service ${service} unexpectedly publishes a host port: ${published_ports}" >&2
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
  printf '%s|RUNTIME_LIMITS|%s\n' "${service}" "${runtime_values}"
}

verify_original_greenplum_source_pruning() {
  local container_id
  container_id="$(docker compose --file "${COMPOSE_FILE}" ps --quiet original-greenplum)"
  local image_id
  image_id="$(docker inspect --format '{{.Image}}' "${container_id}")"
  if ! docker run --rm --entrypoint /bin/sh "${image_id}" -c \
    'test ! -e /workspace/gpdb/ci && test ! -e /workspace/gpdb/concourse'; then
    echo "Original Greenplum image retains excluded upstream CI material." >&2
    return 1
  fi
}

docker compose --file "${COMPOSE_FILE}" exec --no-TTY --user gpadmin \
  greengage /usr/local/bin/dfe-greengage-healthcheck
docker compose --file "${COMPOSE_FILE}" exec --no-TTY --user gpadmin \
  original-greenplum /usr/local/bin/dfe-original-greenplum-healthcheck
docker compose --file "${COMPOSE_FILE}" exec --no-TTY --user gpadmin \
  greengage /usr/local/bin/dfe-greengage-verify
docker compose --file "${COMPOSE_FILE}" exec --no-TTY --user gpadmin \
  original-greenplum /usr/local/bin/dfe-original-greenplum-verify

verify_runtime_configuration \
  greengage \
  /opt/greengagedb/greengage7/dfe-build-dpkg-manifest.txt
verify_runtime_configuration \
  original-greenplum \
  /usr/local/gpdb/dfe-build-rpm-manifest.txt
verify_original_greenplum_source_pruning

echo "Original Greenplum and Greengage fixture verification passed."
