# Image du core — rootless, distroless

Image de **production** du core Vaultaire : `ghcr.io/vaultaire-ad/vaultaire-server`.

| Fichier | Rôle |
|---|---|
| [`Dockerfile`](./Dockerfile) | construction multi-étages depuis les sources : core + CLI (Go statique), agent et modules PAM/NSS (Rocky 9 et Ubuntu 22.04), image finale distroless |
| [`Dockerfile.dockerignore`](./Dockerfile.dockerignore) | contexte de construction réduit à ce que le Dockerfile copie |
| [`serveur_conf.yaml`](./serveur_conf.yaml) | configuration embarquée : ports non privilégiés, chemins inscriptibles, **aucun secret** |

Ce que l'image garantit, comment la vérifier (cosign, provenance, SBOM) et
comment la déployer : [`docs/Installation/Kubernetes.md`](../../docs/Installation/Kubernetes.md).
Toutes les variables : [`docs/Installation/Variables_environnement.md`](../../docs/Installation/Variables_environnement.md).

```bash
# Construire (depuis la racine du dépôt)
docker build -f deployments/docker/Dockerfile --build-arg VAULTAIRE_VERSION=2.3.0 -t vaultaire-server:2.3.0 .

# Lancer, au plus strict
docker run -d --name vaultaire --read-only --cap-drop ALL --security-opt no-new-privileges \
  --tmpfs /run/vaultaire:uid=65532,gid=65532,mode=0700 \
  --tmpfs /var/log/vaultaire:uid=65532,gid=65532,mode=0700 \
  -v vaultaire-data:/var/lib/vaultaire \
  -e VAULTAIRE_DB_HOST=db.acme.lan \
  -e VAULTAIRE_DB_PASSWORD_FILE=/run/secrets/db-password \
  -e VAULTAIRE_ADMIN_PASSWORD_FILE=/run/secrets/admin-password \
  -v "$PWD/secrets:/run/secrets:ro" \
  -p 389:3389 -p 636:3636 -p 6666:6666 -p 443:4443 -p 6643:6643 \
  vaultaire-server:2.3.0

# Administrer
docker exec -it vaultaire /opt/vaultaire/bin/vaultaire_cli
```

Les piles `dev/`, `dev-comp/` et `pre-prod/` restent des environnements de
**test** (binaires montés, root, clé de démonstration) : ne pas les exposer.
