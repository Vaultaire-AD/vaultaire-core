# Pre-prod deployment

Deploys the **compiled** Vaultaire app for **testing** or **staging** (not production).

- **Build**: Multi-stage Docker build (Go binary + Rocky runtime).
- **Run**: Start the stack; the app runs the built binary. No local source mount.
- **Use case**: Deploy a fixed image to test features, run integration tests, or simulate a simple staging environment.

## Quick start

From repo root:

```bash
./deployments/pre-prod/docker-build-and-up.sh
# or
docker compose -f deployments/pre-prod/docker-compose.yml build
docker compose -f deployments/pre-prod/docker-compose.yml up -d
```

## Run tests (optional)

To run the test suite inside the pre-prod container:

```bash
docker compose -f deployments/pre-prod/docker-compose.yml run --rm vaultaire-ad ./vaultaire_serveur --test
```

## Services

- **vaultaire-ad**: Vaultaire server (compiled binary).
- **vaultaire-db**: MariaDB.

Config: `deployments/configs/serveur_conf.yaml` (copied into image at build time).
