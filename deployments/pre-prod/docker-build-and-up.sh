#!/usr/bin/env bash
# Build and run pre-prod stack with Docker.
# Run from repo root: ./deployments/pre-prod/docker-build-and-up.sh

set -e
REPO_ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
cd "$REPO_ROOT"

echo "Building image (context: $REPO_ROOT)..."
docker compose -f deployments/pre-prod/docker-compose.yml build --no-cache

echo "Stopping existing containers..."
docker compose -f deployments/pre-prod/docker-compose.yml down 2>/dev/null || true

echo "Starting stack..."
docker compose -f deployments/pre-prod/docker-compose.yml up -d

echo "Containers:"
docker compose -f deployments/pre-prod/docker-compose.yml ps

echo "Done (pre-prod = test/staging). Logs: docker compose -f deployments/pre-prod/docker-compose.yml logs -f vaultaire-ad"
