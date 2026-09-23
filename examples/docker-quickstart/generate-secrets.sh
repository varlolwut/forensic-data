#!/usr/bin/env bash
set -euo pipefail

state_directory=/state
secrets_directory="${state_directory}/secrets"
output_directory="${state_directory}/output"
host_uid="${DFE_HOST_UID:?DFE_HOST_UID is required}"
host_gid="${DFE_HOST_GID:?DFE_HOST_GID is required}"

if [[ ! "${host_uid}" =~ ^[0-9]+$ ]] || [[ ! "${host_gid}" =~ ^[0-9]+$ ]]; then
  echo "DFE_HOST_UID and DFE_HOST_GID must be nonnegative decimal integers." >&2
  exit 1
fi

required_files=(
  metadata_admin_password
  metadata_migrator_password
  metadata_writer_password
  metadata_reader_password
  metadata_migrator_dsn
  metadata_writer_dsn
  metadata_reader_dsn
  demo_admin_password
  demo_reader_password
  reference_dsn
  target_dsn
)

prepare_output_directory() {
  mkdir -p "${output_directory}"
  if ! chown "${host_uid}:10001" "${output_directory}" 2>/dev/null; then
    echo "Host filesystem keeps ownership of the output bind; verifying container write access."
  fi
  if ! chmod 0770 "${output_directory}" 2>/dev/null; then
    echo "Host filesystem keeps permissions on the output bind; verifying container write access."
  fi
  if ! gosu 10001:10001 test -w "${output_directory}"; then
    echo "The Docker runtime user cannot write .local/docker-quickstart/output." >&2
    exit 1
  fi
}

prepare_secret_directory() {
  if ! chown -R "${host_uid}:${host_gid}" "${secrets_directory}" 2>/dev/null; then
    echo "Host filesystem keeps ownership of the secret bind."
  fi
  chmod 0700 "${secrets_directory}"
  chmod 0444 "${secrets_directory}"/*
}

if ! chown "${host_uid}:${host_gid}" "${state_directory}" 2>/dev/null; then
  echo "Host filesystem keeps ownership of the quickstart state directory."
fi

if [[ -d "${secrets_directory}" ]]; then
  for required_file in "${required_files[@]}"; do
    if [[ ! -s "${secrets_directory}/${required_file}" ]]; then
      echo "Secret setup is incomplete; restore the original missing secret from backup." >&2
      exit 1
    fi
  done
  prepare_secret_directory
  prepare_output_directory
  echo "Docker quickstart secrets already exist; nothing was overwritten."
  exit 0
fi

temporary_directory="$(mktemp -d "${state_directory}/.secrets.XXXXXX")"
cleanup() {
  rm -rf -- "${temporary_directory}"
}
trap cleanup EXIT

random_secret() {
  od -An -N24 -tx1 /dev/urandom | tr -d ' \n'
}

metadata_admin_password="$(random_secret)"
metadata_migrator_password="$(random_secret)"
metadata_writer_password="$(random_secret)"
metadata_reader_password="$(random_secret)"
demo_admin_password="$(random_secret)"
demo_reader_password="$(random_secret)"

printf '%s\n' "${metadata_admin_password}" > "${temporary_directory}/metadata_admin_password"
printf '%s\n' "${metadata_migrator_password}" > "${temporary_directory}/metadata_migrator_password"
printf '%s\n' "${metadata_writer_password}" > "${temporary_directory}/metadata_writer_password"
printf '%s\n' "${metadata_reader_password}" > "${temporary_directory}/metadata_reader_password"
printf '%s\n' "${demo_admin_password}" > "${temporary_directory}/demo_admin_password"
printf '%s\n' "${demo_reader_password}" > "${temporary_directory}/demo_reader_password"

printf '%s\n' \
  "host=metadata port=5432 dbname=dfe_metadata user=dfe_metadata_migrator_login password=${metadata_migrator_password} sslmode=disable connect_timeout=5" \
  > "${temporary_directory}/metadata_migrator_dsn"
printf '%s\n' \
  "host=metadata port=5432 dbname=dfe_metadata user=dfe_metadata_writer_login password=${metadata_writer_password} sslmode=disable connect_timeout=5" \
  > "${temporary_directory}/metadata_writer_dsn"
printf '%s\n' \
  "host=metadata port=5432 dbname=dfe_metadata user=dfe_metadata_reader_login password=${metadata_reader_password} sslmode=disable connect_timeout=5" \
  > "${temporary_directory}/metadata_reader_dsn"
printf '%s\n' \
  "host=demo-postgres port=5432 dbname=dfe_demo user=dfe_demo_reader password=${demo_reader_password} sslmode=disable connect_timeout=5" \
  > "${temporary_directory}/reference_dsn"
printf '%s\n' \
  "host=demo-postgres port=5432 dbname=dfe_demo user=dfe_demo_reader password=${demo_reader_password} sslmode=disable connect_timeout=5" \
  > "${temporary_directory}/target_dsn"

chmod 0444 "${temporary_directory}"/*
mv -- "${temporary_directory}" "${secrets_directory}"
trap - EXIT
prepare_secret_directory
prepare_output_directory
echo "Created local Docker secrets and the writable output directory."
