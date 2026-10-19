#!/bin/bash
cd "$(dirname "$0")/.."
echo "[INFO] $(date '+%Y-%m-%d %H:%M:%S') build sqlgw-executor"
python -c 'import sys; assert sys.version_info >= (3, 12), sys.version'
if [ $? -ne 0 ]; then
  echo "[ERROR] $(date '+%Y-%m-%d %H:%M:%S') Compilation failed, request the developer to confirm it."
  exit 1
fi
