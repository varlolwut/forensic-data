#!/usr/bin/env bash
source /opt/greengagedb/greengage7/greengage_path.sh
set -euo pipefail

export COORDINATOR_DATA_DIRECTORY=/data/coordinator/ggseg-1

psql --no-psqlrc --set=ON_ERROR_STOP=1 --tuples-only --no-align --dbname postgres \
  --command="SELECT version() LIKE '%Greengage Database 7.5.0 build commit:677398e45766110a32e318266f186cf0cbe720a5%' AND (SELECT count(*) FROM gp_segment_configuration) = 3 AND (SELECT count(*) FROM gp_segment_configuration WHERE content = -1 AND role = 'p' AND preferred_role = 'p' AND status = 'u' AND hostname = 'greengage' AND port = 5432) = 1 AND (SELECT count(*) FROM gp_segment_configuration WHERE content = 0 AND role = 'p' AND preferred_role = 'p' AND status = 'u' AND hostname = 'greengage' AND port = 6000) = 1 AND (SELECT count(*) FROM gp_segment_configuration WHERE content = 1 AND role = 'p' AND preferred_role = 'p' AND status = 'u' AND hostname = 'greengage' AND port = 6001) = 1 AND (SELECT count(DISTINCT gp_segment_id) FROM gp_dist_random('gp_id')) = 2;" \
  | grep --quiet --line-regexp t
