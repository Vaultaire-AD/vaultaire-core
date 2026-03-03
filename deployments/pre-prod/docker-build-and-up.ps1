# Build and run pre-prod stack with Docker.
# Run from repo root: .\deployments\pre-prod\docker-build-and-up.ps1

$ErrorActionPreference = "Stop"
$RepoRoot = Resolve-Path (Join-Path $PSScriptRoot "../..")

Push-Location $RepoRoot
try {
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
