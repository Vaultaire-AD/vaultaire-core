#!/usr/bin/env bash
# ====================================================================
# Déploiement pre-prod depuis le poste de développement
# ====================================================================
#
# Compile, transfère les binaires vers l'hôte pre-prod, redémarre le conteneur.
# Les binaires ne transitent PLUS par git : rsync les envoie directement.
#
# Pourquoi : chaque itération ajoutait ~17 Mo de binaires à l'historique git
# (serveur, cli, client, modules PAM). Git est fait pour du texte ; un dépôt qui
# grossit de 17 Mo par test devient lent à cloner et à pousser, définitivement —
# supprimer les fichiers plus tard ne réduit pas l'historique.
#
# Le code, lui, continue de passer par git : l'hôte pre-prod fait son pull pour
# récupérer templates, configuration et scripts.
#
# Configuration, par variables d'environnement :
#     PREPROD_HOST   utilisateur@hote            (obligatoire)
#     PREPROD_PATH   chemin du depot sur l'hote  (defaut: /srv/vaultaire-core)
#     VAULTAIRE_BRANCH  branche a pousser        (defaut: feature/pre-prod)
#
# Usage, depuis la racine du dépôt :
#     PREPROD_HOST=root@192.168.30.3 ./deployments/pre-prod/deploy.sh
#     ./deployments/pre-prod/deploy.sh --no-compile   # binaires deja compiles
#     ./deployments/pre-prod/deploy.sh --no-push      # pas de git push

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
cd "$REPO_ROOT"

PREPROD_HOST="${PREPROD_HOST:-}"
PREPROD_PATH="${PREPROD_PATH:-/srv/vaultaire-core}"
BRANCH="${VAULTAIRE_BRANCH:-feature/pre-prod}"

DO_COMPILE=1
DO_PUSH=1
for arg in "$@"; do
    case "$arg" in
        --no-compile) DO_COMPILE=0 ;;
        --no-push)    DO_PUSH=0 ;;
        *) echo "Option inconnue : $arg" >&2; exit 1 ;;
    esac
done

if [ -z "$PREPROD_HOST" ]; then
    echo "ERREUR : PREPROD_HOST non defini." >&2
    echo "         Exemple : PREPROD_HOST=root@192.168.30.3 $0" >&2
    exit 1
fi

# --- Compilation -----------------------------------------------------
if [ "$DO_COMPILE" -eq 1 ]; then
    echo "==> Compilation"
    ./auto-compil.sh
fi

SERVER_BIN="cmd/vaultaire_server/vaultaire_serveur"
[ -f "$SERVER_BIN" ] || { echo "ERREUR : $SERVER_BIN absent apres compilation." >&2; exit 1; }

# --- Code par git ----------------------------------------------------
# Le code source, les templates et la configuration passent par git : ce sont
# des fichiers texte, versionnés et diffables, et l'hôte doit pouvoir retrouver
# quelle révision il exécute.
if [ "$DO_PUSH" -eq 1 ]; then
    if [ -n "$(git status --porcelain --untracked-files=no)" ]; then
        echo "ATTENTION : des modifications ne sont pas committees." >&2
        echo "            L'hote recevra les binaires a jour mais pas ce code." >&2
        read -r -p "Continuer quand meme ? [y/N] " answer
        [ "$answer" = "y" ] || exit 1
    fi
    echo "==> git push origin $BRANCH"
    git push origin "$BRANCH"
fi

# --- Binaires par rsync ----------------------------------------------
# --checksum plutôt que la date : auto-compil.sh réécrit les binaires à chaque
# passage, même quand rien n'a changé. Comparer le contenu évite de retransférer
# 14 Mo pour un binaire identique.
echo "==> Transfert des binaires vers $PREPROD_HOST:$PREPROD_PATH"
rsync -az --checksum --info=stats1 \
    --rsync-path="mkdir -p $PREPROD_PATH/cmd && rsync" \
    cmd/vaultaire_server cmd/vaultaire_client cmd/vaultaire_ctl \
    "$PREPROD_HOST:$PREPROD_PATH/cmd/"

# --- Mise à jour distante --------------------------------------------
echo "==> Mise a jour de l'hote"
ssh "$PREPROD_HOST" "cd '$PREPROD_PATH' && ./deployments/pre-prod/docker-update.sh"

echo
echo "Termine."
echo "Logs : ssh $PREPROD_HOST 'cd $PREPROD_PATH && docker compose -f deployments/pre-prod/docker-compose.yml logs -f vaultaire-ad'"
