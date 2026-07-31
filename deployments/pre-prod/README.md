# Déploiement pre-prod

Environnement de **test / staging**, pas de production.

Les binaires sont **compilés sur le poste de développement**, transférés par
rsync, puis **montés en volume** dans le conteneur. L'image ne contient aucun
binaire applicatif et ne se reconstruit que si le `Dockerfile` change.

## Boucle de travail

```bash
# Depuis le poste de developpement, a la racine du depot
PREPROD_HOST=root@192.168.30.3 ./deployments/pre-prod/deploy.sh
```

Ce que fait le script : compilation, `git push` du code, `rsync` des binaires,
puis `docker-update.sh` sur l'hôte, qui fait un `git pull` et redémarre le
conteneur. **Aucune reconstruction d'image.**

Variantes :

```bash
./deployments/pre-prod/deploy.sh --no-compile   # binaires deja a jour
./deployments/pre-prod/deploy.sh --no-push      # ne pas pousser le code
```

Directement sur l'hôte, sans passer par le poste de développement :

```bash
./deployments/pre-prod/docker-update.sh             # git pull + restart
./deployments/pre-prod/docker-update.sh --build     # force la reconstruction
./deployments/pre-prod/docker-update.sh --no-pull   # restart seul
```

## Pourquoi ce fonctionnement

L'ancienne boucle supprimait l'image (`podman rmi`) puis la reconstruisait avec
`--no-cache`. Deux conséquences :

- la couche `dnf install sudo openssh-server openssh-clients`, qui ne change
  jamais, était réinstallée à chaque itération ;
- la reconstruction ne servait qu'à recopier des binaires **déjà compilés** —
  le `Dockerfile` ne compile rien.

Les binaires étaient par ailleurs versionnés dans git, soit environ 32 Mo
d'artefacts et ~17 Mo ajoutés à l'historique à chaque itération. Un historique
git ne se dégonfle pas : supprimer les fichiers plus tard n'y change rien.

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
git clone <depot> /srv/vaultaire-core
cd /srv/vaultaire-core
git checkout feature/pre-prod
# depuis le poste de developpement :
PREPROD_HOST=root@<hote> ./deployments/pre-prod/deploy.sh
```

Le premier passage construit l'image (l'absence d'image est détectée), les
suivants se contentent d'un redémarrage.

## Détacher les binaires déjà suivis par git

Le `.gitignore` n'a aucun effet sur des fichiers **déjà suivis**. Après avoir
récupéré ces changements, à faire une fois :

```bash
git rm --cached -r cmd/
git rm --cached src/vaultaire_client/pam_module/*.so \
                src/vaultaire_client/pam_module/*.so.2
git commit -m "build: sortir les artefacts de compilation du suivi git"
```

`--cached` retire du suivi **sans supprimer les fichiers du disque** : les
binaires restent en place et le déploiement continue de fonctionner.

Attention : les révisions passées gardent les binaires, le dépôt reste donc
lourd à cloner. Seul un `git filter-repo` réécrirait l'historique — opération
destructive qui invalide tous les clones existants, à ne pas lancer sans
sauvegarde et sans prévenir les autres utilisateurs du dépôt.

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
