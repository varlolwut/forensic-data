#!/usr/bin/env bash
source /usr/local/gpdb/greenplum_path.sh
set -euo pipefail

export MASTER_DATA_DIRECTORY=/home/gpadmin/gpdemo-data/qddir/demoDataDir-1
export PGPORT=15432

psql --no-psqlrc --set=ON_ERROR_STOP=1 --tuples-only --no-align --dbname template1 \
  --command="SELECT version() LIKE '%Greenplum Database 4.3.99.00 build dev%' AND (SELECT count(*) FROM gp_segment_configuration) = 5 AND (SELECT count(*) FROM gp_segment_configuration WHERE content = -1 AND role = 'p' AND preferred_role = 'p' AND mode = 's' AND status = 'u' AND hostname = 'original-gp' AND port = 15432) = 1 AND (SELECT count(*) FROM gp_segment_configuration WHERE content = 0 AND role = 'p' AND preferred_role = 'p' AND mode = 's' AND status = 'u' AND hostname = 'original-gp' AND port = 25432) = 1 AND (SELECT count(*) FROM gp_segment_configuration WHERE content = 1 AND role = 'p' AND preferred_role = 'p' AND mode = 's' AND status = 'u' AND hostname = 'original-gp' AND port = 25433) = 1 AND (SELECT count(*) FROM gp_segment_configuration WHERE content = 0 AND role = 'm' AND preferred_role = 'm' AND mode = 's' AND status = 'u' AND hostname = 'original-gp' AND port = 25434) = 1 AND (SELECT count(*) FROM gp_segment_configuration WHERE content = 1 AND role = 'm' AND preferred_role = 'm' AND mode = 's' AND status = 'u' AND hostname = 'original-gp' AND port = 25435) = 1 AND (SELECT count(DISTINCT gp_segment_id) FROM gp_dist_random('gp_id')) = 2;" \
  | grep --quiet --line-regexp t
