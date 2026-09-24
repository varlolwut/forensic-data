#!/usr/bin/env bash
source /usr/local/gpdb/greenplum_path.sh
set -euo pipefail

export MASTER_DATA_DIRECTORY=/home/gpadmin/gpdemo-data/qddir/demoDataDir-1
export PGPORT=15432

printf '%s\n' ORIGINAL_GREENPLUM_SOURCE_IDENTITY
/workspace/gpdb/getversion
printf '%s\n' ORIGINAL_GREENPLUM_SERVER_IDENTITY
psql --no-psqlrc --set=ON_ERROR_STOP=1 --tuples-only --no-align --dbname template1 \
  --command='SELECT version();'
printf '%s\n' ORIGINAL_GREENPLUM_TOPOLOGY
psql --no-psqlrc --set=ON_ERROR_STOP=1 --field-separator='|' --tuples-only --no-align --dbname template1 \
  --command='SELECT dbid, content, role, preferred_role, mode, status, hostname, address, port FROM gp_segment_configuration ORDER BY dbid;'
printf '%s\n' ORIGINAL_GREENPLUM_DISTRIBUTED_EXECUTION
psql --no-psqlrc --set=ON_ERROR_STOP=1 --field-separator='|' --tuples-only --no-align --dbname template1 \
  --command="SELECT gp_segment_id, count(*) FROM gp_dist_random('gp_id') GROUP BY gp_segment_id ORDER BY gp_segment_id;"
printf 'ORIGINAL_GREENPLUM_GPADMIN_SELF_SSH_NOFILE|%s\n' \
  "$(ssh -o BatchMode=yes -o ConnectTimeout=1 original-gp 'ulimit -n')"
