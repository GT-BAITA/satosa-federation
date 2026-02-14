#!/bin/bash
set -euo pipefail

TARGET="debian@yourdomain"
REMOTE_DIR="./satosa"

rsync -avz --exclude='.git' --exclude='__pycache__' \
    docker-compose.yml Dockerfile Caddyfile \
    plugin etc generate_keys.sh tests \
    "${TARGET}:${REMOTE_DIR}/"

echo "Deployed. To start:"
echo "  ssh ${TARGET} 'cd ${REMOTE_DIR} && docker compose up --build -d'"
