#!/bin/bash
cd "$(dirname "$0")/.."
echo "[INFO] $(date '+%Y-%m-%d %H:%M:%S') build sqlgw-executor"
docker build -f docker/Dockerfile -t sqlgw-executor:latest .
if [ $? -ne 0 ]; then
  echo "[ERROR] $(date '+%Y-%m-%d %H:%M:%S') Compilation failed, request the developer to confirm it."
  exit 1
fi
