#!/usr/bin/env bash
# ====================================================================
# Déploiement pre-prod depuis le poste de développement
# ====================================================================
#
# Ne compile plus rien et ne transfère plus aucun binaire : la CI publie une
# release à chaque fusion preprod → main, et l'hôte la télécharge lui-même.
# Ce script ne fait que lancer docker-update.sh sur l'hôte, par SSH, en lui
# passant les options.
#
# Configuration, par variables d'environnement :
#     PREPROD_HOST   utilisateur@hote            (obligatoire)
#     PREPROD_PATH   chemin du depot sur l'hote  (defaut: /srv/vaultaire-core)
#
# Usage :
#     PREPROD_HOST=root@192.168.30.3 ./deployments/pre-prod/deploy.sh                  # derniere release
#     PREPROD_HOST=root@192.168.30.3 ./deployments/pre-prod/deploy.sh --version 2.1.3  # version precise
#     PREPROD_HOST=root@192.168.30.3 ./deployments/pre-prod/deploy.sh --list
#
# Toutes les options sont celles de docker-update.sh (--version, --list,
# --build, --force, --no-download).

set -euo pipefail

PREPROD_HOST="${PREPROD_HOST:-}"
PREPROD_PATH="${PREPROD_PATH:-/srv/vaultaire-core}"

if [ -z "$PREPROD_HOST" ]; then
    echo "ERREUR : PREPROD_HOST non defini." >&2
    echo "         Exemple : PREPROD_HOST=root@192.168.30.3 $0 --version 2.1.3" >&2
    exit 1
fi

# Les options sont transmises telles quelles, protégées pour le shell distant.
ARGS=""
for a in "$@"; do
    ARGS="$ARGS $(printf '%q' "$a")"
done

echo "==> $PREPROD_HOST:$PREPROD_PATH — docker-update.sh$ARGS"
ssh "$PREPROD_HOST" "cd $(printf '%q' "$PREPROD_PATH") && ./deployments/pre-prod/docker-update.sh$ARGS"

echo
echo "Logs : ssh $PREPROD_HOST 'cd $PREPROD_PATH && docker compose -f deployments/pre-prod/docker-compose.yml logs -f vaultaire-ad'"
