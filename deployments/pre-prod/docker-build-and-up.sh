#!/usr/bin/env bash
# Build and run pre-prod stack with Docker.
# Run from repo root: ./deployments/pre-prod/docker-build-and-up.sh

set -e
REPO_ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
cd "$REPO_ROOT"

# Les binaires ne sont plus dans git : sans release installée, le conteneur
# démarrerait en boucle sur « binaire absent ».
if [ ! -x cmd/vaultaire_server/vaultaire_serveur ]; then
    echo "ERREUR : aucun binaire dans cmd/. Installez d'abord une release :" >&2
    echo "         ./deployments/pre-prod/docker-update.sh [--version X.Y.Z]" >&2
    exit 1
fi

echo "Building image (context: $REPO_ROOT)..."
docker compose -f deployments/pre-prod/docker-compose.yml build --no-cache

echo "Stopping existing containers..."
docker compose -f deployments/pre-prod/docker-compose.yml down 2>/dev/null || true

echo "Starting stack..."
docker compose -f deployments/pre-prod/docker-compose.yml up -d

echo "Containers:"
docker compose -f deployments/pre-prod/docker-compose.yml ps

echo "Done (pre-prod = test/staging). Logs: docker compose -f deployments/pre-prod/docker-compose.yml logs -f vaultaire-ad"
