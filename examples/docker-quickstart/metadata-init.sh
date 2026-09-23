#!/usr/bin/env bash
set -euo pipefail

read_generated_password() {
  local path="$1"
  local value
  if [[ ! -r "${path}" ]]; then
    echo "Required metadata secret is not readable." >&2
    exit 1
  fi
  value="$(<"${path}")"
  if [[ ! "${value}" =~ ^[0-9a-f]{48}$ ]]; then
    echo "Required metadata secret has an invalid format." >&2
    exit 1
  fi
  printf '%s' "${value}"
}

PGPASSWORD="$(read_generated_password /run/secrets/metadata_admin_password)"
DFE_METADATA_MIGRATOR_PASSWORD="$(
  read_generated_password /run/secrets/metadata_migrator_password
)"
DFE_METADATA_WRITER_PASSWORD="$(
  read_generated_password /run/secrets/metadata_writer_password
)"
DFE_METADATA_READER_PASSWORD="$(
  read_generated_password /run/secrets/metadata_reader_password
)"
export PGPASSWORD
export DFE_METADATA_MIGRATOR_PASSWORD
export DFE_METADATA_WRITER_PASSWORD
export DFE_METADATA_READER_PASSWORD

psql \
  --no-psqlrc \
  --set=ON_ERROR_STOP=1 \
  --single-transaction \
  --file=/opt/forensic-data/bootstrap.sql \
  --file=/opt/forensic-data/metadata-logins.sql

echo "Metadata bootstrap and login-role validation completed."
