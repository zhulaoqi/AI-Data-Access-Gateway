#!/bin/bash
LOGS_DIR="/docker/log/$HOSTIP"
mkdir -p "$LOGS_DIR" /dianyi/
ln -sfn "$LOGS_DIR" /dianyi/log

case "${PROFILE:-test-ali}" in
  prod|PRO|pro|prod-ali) export ADG_APOLLO_ENV=pro ;;
  *) export ADG_APOLLO_ENV=dev ;;
esac

cd /dianyi/app/sqlgw-executor
exec uvicorn adg.app.main:create_app --factory --host 0.0.0.0 --port "${ADG_BACKEND_PORT:-8000}"
