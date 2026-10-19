#!/bin/bash

set -e

BASE_DIR="$(cd "$(dirname "$0")" && pwd)"

echo "Starting federated-catalog..."
cd "$BASE_DIR/federated-catalog"
docker compose up -d

echo "Starting public-key-registry..."
cd "$BASE_DIR/public-key-registry"
docker compose up -d

echo "Starting fc-pkr-viewer..."
cd "$BASE_DIR/fc-pkr-viewer"
docker compose up -d

echo "Support systems started."
