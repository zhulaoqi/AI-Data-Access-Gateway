#!/bin/bash
LOGS_DIR="/docker/log/$HOSTIP"
mkdir -p "$LOGS_DIR" /dianyi/
ln -sfn "$LOGS_DIR" /dianyi/log

case "${PROFILE:-test-ali}" in
  prod|PRO|pro|prod-ali) export ADG_APOLLO_ENV=pro ;;
  *) export ADG_APOLLO_ENV=dev ;;
esac

# SELECT * 暂时放行：展开成该表已允许的列。要重新拒绝，启动前设 ADG_SQL_REJECT_WILDCARD=true。
export ADG_SQL_REJECT_WILDCARD="${ADG_SQL_REJECT_WILDCARD:-false}"

cd /dianyi/app/sqlgw-executor
exec uvicorn adg.app.main:create_app --factory --host 0.0.0.0 --port "${ADG_BACKEND_PORT:-8000}"
