#!/usr/bin/env bash
set -euo pipefail

FIXTURE_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
readonly FIXTURE_ROOT
readonly ARTIFACT_ROOT="${FIXTURE_ROOT}/artifacts"
readonly UPSTREAM_ARTIFACT_ROOT="${ARTIFACT_ROOT}/upstream-original-greenplum"
readonly ORIGINAL_GREENPLUM_COMMIT="62378f1767f22217f7f0474260abfeeb5c2615b9"
readonly ORIGINAL_GREENPLUM_ARCHIVE="gpdb-archive-${ORIGINAL_GREENPLUM_COMMIT}.tar.gz"
readonly ORIGINAL_GREENPLUM_URL="https://codeload.github.com/greenplum-db/gpdb-archive/tar.gz/${ORIGINAL_GREENPLUM_COMMIT}"
readonly ORIGINAL_GREENPLUM_SIZE="76390954"
readonly ORIGINAL_GREENPLUM_SHA256="c171f871d36183da659cf2d41363a98f31a12ac2e1ef066688005d3c1d3a94ef"
readonly SANITIZED_GREENPLUM_ARCHIVE="gpdb-sanitized-${ORIGINAL_GREENPLUM_COMMIT}.tar"
readonly SANITIZED_GREENPLUM_SIZE="418805760"
readonly SANITIZED_GREENPLUM_SHA256="f654c454e0c6a5b8a9d2631888392cee6af5cb68da51d1b5dc773c7e8a4a73af"
readonly SANITIZER="${FIXTURE_ROOT}/sanitize-original-greenplum.py"
readonly GREENGAGE_PACKAGE="greengage7_7.5.0.ubuntu22.04_amd64.deb"
readonly GREENGAGE_URL="https://github.com/GreengageDB/greengage/releases/download/7.5.0/${GREENGAGE_PACKAGE}"
readonly GREENGAGE_SIZE="25807136"
readonly GREENGAGE_SHA256="2ca71f84f4fbb6175de77e193f4b1fa5732f0439f2e6f7458cb7b4cade34d0a0"
readonly CA_CERTIFICATES_PACKAGE="ca-certificates_20260601~22.04.1_all.deb"
readonly CA_CERTIFICATES_URL="https://snapshot.ubuntu.com/ubuntu/20260924T000000Z/pool/main/c/ca-certificates/${CA_CERTIFICATES_PACKAGE}"
readonly CA_CERTIFICATES_SIZE="140666"
readonly CA_CERTIFICATES_SHA256="6e8cdcc8c86103acd4fc14649eac62ff2037108389074a7b167567af33c32245"

verify_artifact() {
  local destination="$1"
  local expected_sha256="$2"
  local expected_size="$3"
  local actual_size
  actual_size="$(stat --format='%s' "${destination}")"
  if [[ "${actual_size}" != "${expected_size}" ]]; then
    echo "Artifact ${destination} has size ${actual_size}; expected ${expected_size}. Remove it and rerun preparation." >&2
    return 1
  fi
  printf '%s  %s\n' "${expected_sha256}" "${destination}" | sha256sum --check --strict
}

download_artifact() {
  local url="$1"
  local destination="$2"
  local expected_sha256="$3"
  local expected_size="$4"

  if [[ ! -f "${destination}" ]]; then
    local temporary_path
    temporary_path="$(mktemp "${destination}.download.XXXXXX")"
    if ! curl \
      --fail \
      --location \
      --connect-timeout 15 \
      --max-time 600 \
      --retry 4 \
      --retry-all-errors \
      --retry-delay 2 \
      --show-error \
      --silent \
      --output "${temporary_path}" \
      "${url}"; then
      rm -f -- "${temporary_path}"
      echo "Failed to download ${url} after four retries." >&2
      return 1
    fi
    mv -- "${temporary_path}" "${destination}"
  fi

  verify_artifact "${destination}" "${expected_sha256}" "${expected_size}"
}

derive_original_greenplum_artifact() {
  local source_path="$1"
  local destination_path="$2"
  local expected_sha256="$3"
  local expected_size="$4"
  local temporary_path
  temporary_path="$(mktemp "${UPSTREAM_ARTIFACT_ROOT}/sanitized.XXXXXX")"
  if ! python3 "${SANITIZER}" "${source_path}" "${temporary_path}"; then
    rm -f -- "${temporary_path}"
    echo "Failed to derive the sanitized original Greenplum source archive." >&2
    return 1
  fi
  if ! verify_artifact "${temporary_path}" "${expected_sha256}" "${expected_size}"; then
    rm -f -- "${temporary_path}"
    return 1
  fi
  mv -- "${temporary_path}" "${destination_path}"
}

mkdir -p \
  "${ARTIFACT_ROOT}/greengage" \
  "${ARTIFACT_ROOT}/original-greenplum" \
  "${UPSTREAM_ARTIFACT_ROOT}"

readonly ORIGINAL_GREENPLUM_ARCHIVE_PATH="${UPSTREAM_ARTIFACT_ROOT}/${ORIGINAL_GREENPLUM_ARCHIVE}"
readonly SANITIZED_GREENPLUM_ARCHIVE_PATH="${ARTIFACT_ROOT}/original-greenplum/${SANITIZED_GREENPLUM_ARCHIVE}"
readonly GREENGAGE_PACKAGE_PATH="${ARTIFACT_ROOT}/greengage/${GREENGAGE_PACKAGE}"
readonly CA_CERTIFICATES_PACKAGE_PATH="${ARTIFACT_ROOT}/greengage/${CA_CERTIFICATES_PACKAGE}"

download_artifact \
  "${ORIGINAL_GREENPLUM_URL}" \
  "${ORIGINAL_GREENPLUM_ARCHIVE_PATH}" \
  "${ORIGINAL_GREENPLUM_SHA256}" \
  "${ORIGINAL_GREENPLUM_SIZE}"
derive_original_greenplum_artifact \
  "${ORIGINAL_GREENPLUM_ARCHIVE_PATH}" \
  "${SANITIZED_GREENPLUM_ARCHIVE_PATH}" \
  "${SANITIZED_GREENPLUM_SHA256}" \
  "${SANITIZED_GREENPLUM_SIZE}"
download_artifact \
  "${GREENGAGE_URL}" \
  "${GREENGAGE_PACKAGE_PATH}" \
  "${GREENGAGE_SHA256}" \
  "${GREENGAGE_SIZE}"
download_artifact \
  "${CA_CERTIFICATES_URL}" \
  "${CA_CERTIFICATES_PACKAGE_PATH}" \
  "${CA_CERTIFICATES_SHA256}" \
  "${CA_CERTIFICATES_SIZE}"

echo "Prepared the sanitized original Greenplum source, exact Greengage package, and Ubuntu TLS bootstrap package under ${ARTIFACT_ROOT}."
