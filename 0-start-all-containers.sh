#!/bin/bash
set -e

for dir in \
  support-system/public-key-registry \
  support-system/federated-catalog \
  support-system/fc-pkr-viewer \
  user-env/connector \
  user-env/authz \
  user-env/file-server \
  user-env/dashboard \
  provider-env/connector \
  provider-env/authz \
  provider-env/file-server \
  provider-env/dashboard
do
  (cd "$dir" && docker compose up -d)
done
