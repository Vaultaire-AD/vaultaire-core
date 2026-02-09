#!/usr/bin/env bash
# Dev stack: build (image only, no app compile) and start. Source is mounted.
# Run from repo root: ./deployments/dev/up.sh
# Restart after code changes: docker compose -f deployments/dev/docker-compose.yml restart vaultaire-dev

set -e
REPO_ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
cd "$REPO_ROOT"

echo "Building dev image (no app compile)..."
docker compose -f deployments/dev/docker-compose.yml build

echo "Starting dev stack (source mounted from $REPO_ROOT)..."
docker compose -f deployments/dev/docker-compose.yml up -d

echo "Containers:"
docker compose -f deployments/dev/docker-compose.yml ps
echo ""
echo "Restart to try updates: docker compose -f deployments/dev/docker-compose.yml restart vaultaire-dev"
echo "Run tests only: docker compose -f deployments/dev/docker-compose.yml run --rm vaultaire-dev go run ./main --test"
