#!/bin/bash
set -euo pipefail

TARGET="debian@yourdomain"
REMOTE_DIR="./satosarp"

rsync -avz --exclude='.git' --exclude='__pycache__' \
    docker-compose.yml Dockerfile Caddyfile \
    etc generate_keys.sh \
    "${TARGET}:${REMOTE_DIR}/"

# Also sync the shared plugin directory
rsync -avz --exclude='__pycache__' \
    ../plugin/ \
    "${TARGET}:${REMOTE_DIR}/plugin/"

echo "Deployed. To start:"
echo "  ssh ${TARGET} 'cd ${REMOTE_DIR} && docker compose up --build -d'"
