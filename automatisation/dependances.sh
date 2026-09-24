#!/usr/bin/env bash
#
# Régénère la page d'inventaire des dépendances.
#
#     ./automatisation/dependances.sh
#
# Elle relit les neuf go.mod, les Dockerfiles et le fichier des rôles
# (docs/Developement/dependances.roles), puis réécrit la section délimitée de
# docs/Developement/how it work/Dependances.md.
#
# # Pourquoi ce script ne fait que trois lignes
#
# Tout le travail est dans le paquet Go `core/dependances`, parce qu'il doit
# servir DEUX fois : ici pour produire la page, et dans `go test` pour refuser
# qu'elle dérive. Réécrire la même analyse en bash aurait donné deux
# implémentations à tenir d'accord — c'est-à-dire, tôt ou tard, deux réponses
# différentes à la même question.
#
# Le test est ce qui compte : un rapport qu'on lance à la main finit par ne plus
# être lancé. Ce script n'est que le geste d'écriture.

set -euo pipefail

ICI="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
RACINE="$(dirname "$ICI")"

cd "$RACINE/src/vaultaire_serveur"

# -count=1 : sans lui, un résultat en cache ferait croire à une régénération qui
# n'a pas eu lieu.
go test ./core/dependances/ -run TestInventaireAJour -update -count=1 -v \
  | grep -vE "^(=== RUN|--- PASS|PASS|ok)" || true

cd "$RACINE"
if git diff --quiet -- "docs/Developement/how it work/Dependances.md" 2>/dev/null; then
    echo "Inventaire déjà à jour."
else
    echo "Inventaire mis à jour : docs/Developement/how it work/Dependances.md"
fi
