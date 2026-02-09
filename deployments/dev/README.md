# Dev deployment

Runs Vaultaire **without compiling** the app in the image: the Go source is **mounted** from your local folder. Restart the container to try new updates (no image rebuild).

- **Image**: Go only (no app copy). Source is bind-mounted at runtime.
- **Use case**: Edit code locally, restart containers to run the new code; optional run of tests.

## Quick start

From **repo root**:

```bash
# Build dev image (once) and start
docker compose -f deployments/dev/docker-compose.yml build
docker compose -f deployments/dev/docker-compose.yml up -d

# After code changes: restart to pick up updates
docker compose -f deployments/dev/docker-compose.yml restart vaultaire-dev
```

## Run tests (no server start)

Run the test suite and exit:

```bash
docker compose -f deployments/dev/docker-compose.yml run --rm vaultaire-dev go run ./main --test
```

## Run server after tests

Start the server as usual (default command):

```bash
docker compose -f deployments/dev/docker-compose.yml up -d vaultaire-dev
```

## Services

- **vaultaire-dev**: Vaultaire server (`go run ./main` from mounted `src/vaultaire_serveur`). Config at `/opt/vaultaire/serveur_conf.yaml` (mounted from `deployments/configs`).
- **vaultaire-db-dev**: MariaDB.
- **rocky-ssh-dev**: Rocky Linux 9 avec SSH (root / root). Permet de tester la connexion SSH depuis le serveur (client Ducky / PAM).

### Tester la connexion SSH (client)

- Depuis la machine hôte : `ssh -p 2222 root@localhost` (mot de passe : `root`).
- Depuis le conteneur vaultaire-dev : `docker compose -f deployments/dev/docker-compose.yml exec vaultaire-dev sh -c 'apk add --no-cache openssh-client && ssh -o StrictHostKeyChecking=no root@rocky-ssh'` (mdp : `root`), ou après avoir enregistré ce client dans Vaultaire et installé vaultaire_client sur rocky-ssh, tester le flux complet (PAM / Ducky).

### Enregistrer le conteneur Rocky comme client (create -c -join)

La commande `create -c` crée un client dans Vaultaire ; `-join` pousse la config et les clés sur la machine cible via SSH. **Elle doit être exécutée depuis l’hôte** (ou depuis un conteneur qui a accès au socket/API et qui peut SSH vers `rocky-ssh`). En dev, le CLI tourne souvent sur l’hôte et parle au serveur dans le conteneur ; le **serveur** (vaultaire-dev) fait le SSH vers Rocky. Il faut donc que la commande soit envoyée au serveur (socket ou API) et que le serveur ait accès à `rocky-ssh:22`.

Depuis le **conteneur serveur** (vaultaire-dev), avec le CLI en local qui pointe vers le serveur, ou en entrant dans le conteneur :

1. **Créer le client et l’intégrer sur Rocky** (type `rocky`, non serveur, join sur `rocky-ssh` avec user `root`) :

```bash
create -c rocky not -join rocky-ssh root
```

- **rocky** : type du client (nom libre).
- **not** : ce n’est pas un “serveur” (oui/non).
- **-join rocky-ssh root** : le serveur va SSH vers `rocky-ssh` (nom du service Docker) avec l’utilisateur **root** pour déployer la config et les clés du nouveau client.

2. Le mot de passe **root** sera demandé quand le serveur se connecte en SSH à `rocky-ssh` (mdp : `root`).

3. Ensuite, ajouter le client à un groupe pour qu’un utilisateur puisse s’y connecter (ex. groupe `dev` ou `visiteur`) :

```bash
add -c <computeur_id> -g <nom_du_groupe>
```

Le `<computeur_id>` est affiché à la création (ex. `Abc12Def34Gh-02-01-2026`). Vérifier avec `get -c`.

Logs : `docker compose -f deployments/dev/docker-compose.yml logs -f vaultaire-dev`
