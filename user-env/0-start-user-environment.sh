#!/bin/bash

set -e

BASE_DIR="$(cd "$(dirname "$0")" && pwd)"

echo "Starting authz..."
cd "$BASE_DIR/authz"
docker compose up -d

echo "Starting connector..."
cd "$BASE_DIR/connector"
docker compose up -d

echo "Starting file-server..."
cd "$BASE_DIR/file-server"
docker compose up -d

echo "Starting user-console"
cd "$BASE_DIR/user-console"
docker compose up -d

echo "User environment started."
