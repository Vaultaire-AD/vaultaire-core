#!/usr/bin/env bash
# ====================================================================
# Mise à jour pre-prod — sans reconstruction d'image
# ====================================================================
#
# Les binaires et les fichiers statiques sont montés en volume : les rafraîchir
# suffit, le conteneur n'a qu'à redémarrer. L'ancienne version supprimait
# l'image puis la reconstruisait avec --no-cache, ce qui rejouait l'installation
# des paquets système à chaque itération pour ne déplacer que des binaires déjà
# compilés.
#
# L'image n'est reconstruite que si le Dockerfile a changé — ce script le
# détecte à partir des fichiers réellement modifiés par le pull, plutôt que de
# le deviner.
#
# Usage, depuis la racine du dépôt :
#     ./deployments/pre-prod/docker-update.sh            # git pull + restart
#     ./deployments/pre-prod/docker-update.sh --build    # force la reconstruction
#     ./deployments/pre-prod/docker-update.sh --no-pull  # restart seul

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
cd "$REPO_ROOT"

COMPOSE_FILE="deployments/pre-prod/docker-compose.yml"
DOCKERFILE="deployments/pre-prod/Dockerfile"
ENTRYPOINT="deployments/pre-prod/entrypoint.sh"

FORCE_BUILD=0
DO_PULL=1
for arg in "$@"; do
    case "$arg" in
        --build)   FORCE_BUILD=1 ;;
        --no-pull) DO_PULL=0 ;;
        *) echo "Option inconnue : $arg" >&2; exit 1 ;;
    esac
done

# docker ou podman-compose selon ce qui est disponible sur l'hôte.
if command -v docker >/dev/null 2>&1; then
    COMPOSE="docker compose -f $COMPOSE_FILE"
elif command -v podman-compose >/dev/null 2>&1; then
    COMPOSE="podman-compose -f $COMPOSE_FILE"
else
    echo "Ni docker ni podman-compose trouve sur cette machine." >&2
    exit 1
fi

# --- Récupération du code -------------------------------------------
BEFORE=""
if [ "$DO_PULL" -eq 1 ]; then
    BEFORE="$(git rev-parse HEAD)"
    echo "==> git pull origin"
    git pull origin --no-rebase
fi

# --- L'image doit-elle être reconstruite ? --------------------------
# Seul un changement du Dockerfile, de l'entrypoint ou du compose le justifie :
# tout le reste est monté.
NEED_BUILD=$FORCE_BUILD
if [ "$NEED_BUILD" -eq 0 ] && [ -n "$BEFORE" ]; then
    if git diff --name-only "$BEFORE" HEAD -- \
        "$DOCKERFILE" "$ENTRYPOINT" "$COMPOSE_FILE" | grep -q .; then
        echo "==> Dockerfile, entrypoint ou compose modifie : reconstruction necessaire"
        NEED_BUILD=1
    fi
fi

# Image absente : premier déploiement sur cette machine.
if ! $COMPOSE images 2>/dev/null | grep -q "vaultaire-preprod"; then
    echo "==> Image absente, construction initiale"
    NEED_BUILD=1
fi

# --- Contrôle des binaires ------------------------------------------
# Le conteneur les monte : s'ils manquent, il refusera de démarrer. Autant le
# dire ici, avec la commande qui répare, plutôt que de laisser l'utilisateur
# lire les logs d'un conteneur en boucle de redémarrage.
SERVER_BIN="cmd/vaultaire_server/vaultaire_serveur"
if [ ! -f "$SERVER_BIN" ]; then
    echo "ERREUR : $SERVER_BIN absent." >&2
    echo "         Compilez d'abord sur le poste de developpement (./auto-compil.sh)," >&2
    echo "         puis deployez avec ./deployments/pre-prod/deploy.sh" >&2
    exit 1
fi
[ -x "$SERVER_BIN" ] || chmod +x "$SERVER_BIN"

echo "==> Binaire serveur : $(date -r "$SERVER_BIN" '+%Y-%m-%d %H:%M:%S') ($(stat -c%s "$SERVER_BIN") octets)"

# --- Application -----------------------------------------------------
if [ "$NEED_BUILD" -eq 1 ]; then
    # Sans --no-cache : les couches système sont réutilisées, seules celles qui
    # dépendent d'un fichier modifié sont rejouées.
    echo "==> Reconstruction de l'image"
    $COMPOSE build
    $COMPOSE up -d
else
    echo "==> Redemarrage du conteneur (aucune reconstruction)"
    $COMPOSE restart vaultaire-ad
fi

echo "==> Etat :"
$COMPOSE ps

echo
echo "Termine. Logs : $COMPOSE logs -f vaultaire-ad"
