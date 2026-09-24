#!/usr/bin/env bash
source /opt/greengagedb/greengage7/greengage_path.sh
set -euo pipefail

export COORDINATOR_DATA_DIRECTORY=/data/coordinator/ggseg-1

printf '%s\n' GREENGAGE_PACKAGE
dpkg-query --show --showformat='greengage7=${Version}\n' greengage7
printf '%s\n' GREENGAGE_SERVER_IDENTITY
psql --no-psqlrc --set=ON_ERROR_STOP=1 --tuples-only --no-align --dbname postgres \
  --command='SELECT version();'
printf '%s\n' GREENGAGE_TOPOLOGY
psql --no-psqlrc --set=ON_ERROR_STOP=1 --field-separator='|' --tuples-only --no-align --dbname postgres \
  --command='SELECT dbid, content, role, preferred_role, status, port, hostname FROM gp_segment_configuration ORDER BY dbid;'
printf '%s\n' GREENGAGE_DISTRIBUTED_EXECUTION
psql --no-psqlrc --set=ON_ERROR_STOP=1 --field-separator='|' --tuples-only --no-align --dbname postgres \
  --command="SELECT gp_segment_id, count(*) FROM gp_dist_random('gp_id') GROUP BY gp_segment_id ORDER BY gp_segment_id;"
printf 'GREENGAGE_GPADMIN_SELF_SSH_NOFILE|%s\n' \
  "$(ssh -o BatchMode=yes -o ConnectTimeout=1 greengage 'ulimit -n')"
