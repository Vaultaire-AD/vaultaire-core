#!/usr/bin/env bash
# ====================================================================
# Purge des binaires de l'historique git — OPÉRATION DESTRUCTIVE
# ====================================================================
#
# Jusqu'en 2.1, cmd/ et les modules PAM compilés étaient versionnés : ~18 Mo
# par commit pour le seul serveur, un dépôt de près de 800 Mo. Ils ne sont plus
# suivis, mais l'historique garde leur poids. Ce script le réécrit.
#
# CONSÉQUENCES — à lire avant de lancer :
#   - TOUS les hashes de commit changent, sur toutes les branches et tous les tags ;
#   - chaque clone existant (postes, hôte pre-prod, CI) doit être RE-CLONÉ :
#     un pull sur un ancien clone réintroduirait les binaires ;
#   - les PR ouvertes deviennent inutilisables ;
#   - la protection de branche doit autoriser le force-push le temps de l'opération ;
#   - GitHub garde les anciens objets en cache un moment : la taille affichée ne
#     baisse pas immédiatement.
#
# Le script travaille sur une copie miroir FRAÎCHE, jamais sur votre clone.
# Sans --push, il s'arrête avant d'envoyer quoi que ce soit.
#
# Prérequis : git-filter-repo  (pip install git-filter-repo, ou dnf/apt)
#
# Usage :
#     ./automatisation/purge-binaires-historique.sh            # simulation : réécrit et mesure
#     ./automatisation/purge-binaires-historique.sh --push     # réécrit ET force-push

set -euo pipefail

REPO_URL="${VAULTAIRE_REPO_URL:-git@github.com:Vaultaire-AD/vaultaire-core.git}"
DO_PUSH=0
for arg in "$@"; do
    case "$arg" in
        --push) DO_PUSH=1 ;;
        -h|--help) sed -n '2,27p' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
        *) echo "Option inconnue : $arg" >&2; exit 1 ;;
    esac
done

command -v git-filter-repo >/dev/null 2>&1 || {
    echo "ERREUR : git-filter-repo introuvable (pip install git-filter-repo)." >&2
    exit 1
}

WORK="$(mktemp -d -t vaultaire-purge.XXXXXX)"
echo "==> Copie miroir de $REPO_URL dans $WORK"
git clone --quiet --mirror "$REPO_URL" "$WORK/repo.git"
cd "$WORK/repo.git"

AVANT="$(git count-objects -vH | sed -n 's/^size-pack: //p')"

echo "==> Réécriture : suppression de cmd/ et des .so compilés"
git filter-repo --force --invert-paths \
    --path cmd/ \
    --path-glob 'src/vaultaire_client/pam_module/*.so' \
    --path-glob 'src/vaultaire_client/pam_module/*.so.*'

git reflog expire --expire=now --all
git gc --prune=now --aggressive --quiet
APRES="$(git count-objects -vH | sed -n 's/^size-pack: //p')"

echo
echo "Taille du dépôt : $AVANT  ->  $APRES"
echo "Copie réécrite  : $WORK/repo.git"

if [ "$DO_PUSH" -eq 0 ]; then
    echo
    echo "Simulation terminée, rien n'a été envoyé."
    echo "Pour publier : relancer avec --push (après avoir prévenu tous les utilisateurs)."
    exit 0
fi

echo
echo "ATTENTION : tous les clones existants devront être supprimés et re-clonés."
read -r -p "Taper « PURGER » pour force-pusher toutes les branches et tous les tags : " ok
[ "$ok" = "PURGER" ] || { echo "Abandon."; exit 1; }

# filter-repo retire le remote par sécurité : on le remet explicitement.
git remote add origin "$REPO_URL"
git push --force --all  origin
git push --force --tags origin

echo
echo "Terminé. Prochaines étapes :"
echo "  1. re-cloner le dépôt partout (postes, hôte pre-prod) ;"
echo "  2. rétablir la protection de branche ;"
echo "  3. les releases existantes restent attachées à leurs tags (réécrits)."
