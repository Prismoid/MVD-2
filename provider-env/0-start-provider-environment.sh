#!/bin/bash

set -e

BASE_DIR="$(cd "$(dirname "$0")" && pwd)"

echo "Starting authz..."
cd "$BASE_DIR/authz"
docker compose -p provider-authz up -d

echo "Starting connector..."
cd "$BASE_DIR/connector"
docker compose -p provider-connector up -d

echo "Starting file-server..."
cd "$BASE_DIR/file-server"
docker compose -p provider-file-server up -d

echo "Starting provider-dashboard"
cd "$BASE_DIR/dashboard"
docker compose -p provider-dashboard up -d

echo "Provider environment started."
