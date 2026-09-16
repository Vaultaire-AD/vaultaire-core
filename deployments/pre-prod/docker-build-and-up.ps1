# Build and run pre-prod stack with Docker.
# Run from repo root: .\deployments\pre-prod\docker-build-and-up.ps1

$ErrorActionPreference = "Stop"
$RepoRoot = Resolve-Path (Join-Path $PSScriptRoot "../..")

Push-Location $RepoRoot
try {
    # Les binaires ne sont plus dans git : ils viennent d'une release.
    if (-not (Test-Path "cmd/vaultaire_server/vaultaire_serveur")) {
        throw "Aucun binaire dans cmd/. Sur l'hote Linux : ./deployments/pre-prod/docker-update.sh [--version X.Y.Z]"
    }

    Write-Host "Building image (context: $RepoRoot)..."
    docker compose -f deployments/pre-prod/docker-compose.yml build --no-cache

    Write-Host "Stopping existing containers..."
    docker compose -f deployments/pre-prod/docker-compose.yml down

    Write-Host "Starting stack..."
    docker compose -f deployments/pre-prod/docker-compose.yml up -d

    Write-Host "Containers:"
    docker compose -f deployments/pre-prod/docker-compose.yml ps

    Write-Host "Done. Logs: docker compose -f deployments/pre-prod/docker-compose.yml logs -f vaultaire-ad"
} finally {
    Pop-Location
}
