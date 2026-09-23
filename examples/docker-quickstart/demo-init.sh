#!/usr/bin/env bash
set -euo pipefail

if [[ ! -r /run/secrets/demo_reader_password ]]; then
  echo "Required demo reader secret is not readable." >&2
  exit 1
fi

export DFE_DEMO_READER_PASSWORD="$(</run/secrets/demo_reader_password)"
if [[ ! "${DFE_DEMO_READER_PASSWORD}" =~ ^[0-9a-f]{48}$ ]]; then
  echo "Required demo reader secret has an invalid format." >&2
  exit 1
fi

psql \
  --no-psqlrc \
  --set=ON_ERROR_STOP=1 \
  --single-transaction \
  --username "${POSTGRES_USER}" \
  --dbname "${POSTGRES_DB}" \
  --file /opt/forensic-data/demo.sql
