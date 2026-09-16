# Déploiement pre-prod

Environnement de **test / staging**, pas de production.

Les binaires ne sont **ni compilés ici ni versionnés dans git**. Chaque fusion
`preprod` → `main` publie une **release GitHub** (`.github/workflows/release.yaml`) ;
l'hôte pre-prod la télécharge, vérifie ses sommes SHA-256, place le dépôt sur le
tag correspondant et redémarre le conteneur. L'image ne se reconstruit que si
le `Dockerfile`, l'entrypoint ou le compose changent entre les deux versions.

## Mettre à jour

Sur l'hôte, à la racine du dépôt :

```bash
./deployments/pre-prod/docker-update.sh                    # dernière release
./deployments/pre-prod/docker-update.sh --version 2.1.3    # version précise (retour arrière compris)
./deployments/pre-prod/docker-update.sh --list             # releases disponibles + version installée
./deployments/pre-prod/docker-update.sh --build            # force la reconstruction de l'image
./deployments/pre-prod/docker-update.sh --force            # réinstalle la même version
./deployments/pre-prod/docker-update.sh --no-download      # redémarrage seul
```

Depuis le poste de développement, la même chose par SSH :

```bash
PREPROD_HOST=root@192.168.30.3 ./deployments/pre-prod/deploy.sh --version 2.1.3
```

| Variable | Rôle | Défaut |
|---|---|---|
| `PREPROD_HOST` | cible SSH de `deploy.sh` | — (obligatoire) |
| `PREPROD_PATH` | dépôt sur l'hôte | `/srv/vaultaire-core` |
| `VAULTAIRE_REPO` | dépôt GitHub des releases | `Vaultaire-AD/vaultaire-core` |
| `GITHUB_TOKEN` | jeton, si le dépôt devient privé ou si l'API limite | — |

**Seules les 5 dernières releases sont conservées** : un retour arrière plus
ancien n'est pas possible.

Le script refuse de tourner si le dépôt de l'hôte a des modifications locales
(hors binaires) : le checkout du tag les écraserait.

## Ce qui se passe à chaque mise à jour

1. choix de la release (`--version`, sinon la dernière) ;
2. téléchargement des quatre archives et contrôle `SHA256SUMS` — **rien n'est
   touché** si une archive manque ou ne correspond pas ;
3. `git checkout --detach vX.Y.Z` : templates, compose et configuration
   correspondent exactement aux binaires ;
4. installation dans `cmd/` (fichiers remplacés dans les répertoires montés,
   mode 0755) et écriture de `cmd/.release` ;
5. redémarrage de `vaultaire-ad`, et de `vlt-proxy` s'il tourne sur l'hôte.

## Volumes montés

| Hôte | Conteneur | Contenu |
|------|-----------|---------|
| `cmd/vaultaire_server` | `/opt/vaultaire/bin` | serveur et CLI |
| `cmd/vaultaire_client` | `/opt/vaultaire/vaultaire_client` | binaire client et modules PAM |
| `web_packet` | `/opt/vaultaire/web_packet` | templates et fichiers statiques |

Montés en lecture seule : le conteneur ne doit pas pouvoir réécrire les sources
de l'hôte.

Conséquence pratique : **modifier un template HTML ne demande ni recompilation
ni redémarrage**, seulement un rechargement de page — les templates sont relus à
chaque requête.

## Première installation sur un hôte

```bash
git clone https://github.com/Vaultaire-AD/vaultaire-core /srv/vaultaire-core
cd /srv/vaultaire-core
./deployments/pre-prod/docker-update.sh
```

Le premier passage construit l'image (l'absence d'image est détectée).

### Hôte déjà installé avec l'ancienne méthode (rsync)

L'ancien `docker-update.sh` ne sait pas télécharger de release. Une seule fois,
récupérer le nouveau script puis le lancer :

```bash
cd /srv/vaultaire-core
git fetch origin --tags
git checkout --force --detach origin/main   # les binaires suivis disparaissent, c'est attendu
./deployments/pre-prod/docker-update.sh
```

Le conteneur ne trouve plus ses binaires entre le checkout et la fin du script :
compter une coupure de quelques secondes.

## Dépôt allégé

Les binaires ont été versionnés jusqu'en 2.1 : le dépôt approche 800 Mo.
Ils ne sont plus suivis (`.gitignore`), mais l'historique garde leur poids.
`automatisation/purge-binaires-historique.sh` le réécrit — opération
destructive, voir `docs/exploitation/Releases.md` avant de la lancer.

## Tests

```bash
docker compose -f deployments/pre-prod/docker-compose.yml \
    run --rm vaultaire-ad /opt/vaultaire/bin/vaultaire_serveur --test
```

## Services

- **vaultaire-ad** : serveur Vaultaire (binaire monté)
- **vaultaire-db** : MariaDB
- **vaultaire-keycloak** : Keycloak

Configuration : `deployments/configs/serveur_conf.yaml`, copiée dans l'image à
la construction. La modifier demande donc une reconstruction (`--build`).
