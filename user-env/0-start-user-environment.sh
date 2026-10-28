#!/bin/bash

set -e

BASE_DIR="$(cd "$(dirname "$0")" && pwd)"

echo "Starting authz..."
cd "$BASE_DIR/authz"
docker compose -p user-authz up -d

echo "Starting connector..."
cd "$BASE_DIR/connector"
docker compose -p user-connector up -d

echo "Starting file-server..."
cd "$BASE_DIR/file-server"
docker compose -p user-file-server up -d

echo "Starting user-dashboard"
cd "$BASE_DIR/dashboard"
docker compose -p user-dashboard up -d

echo "User environment started."
