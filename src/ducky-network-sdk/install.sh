#!/usr/bin/env bash
#
# Copie le dossier duckynetwork/ dans un projet Go et réécrit ses imports.
#
# ── Pourquoi ce script existe ─────────────────────────────────────────────────
#
# Go n'a pas d'imports relatifs. Un dossier à sous-paquets porte donc toujours,
# dans ses propres imports, le nom du module qui l'héberge. Copier le dossier
# sans rien faire d'autre donnerait des imports pointant vers « duckynetwork »,
# qui est le module de DÉVELOPPEMENT de ce dépôt et n'existe pas chez vous.
#
# La réécriture est purement textuelle et porte sur un seul préfixe :
#
#   duckynetwork/duckynetwork/...   ->   <votre-module>/<destination>/...
#
# ── Usage ─────────────────────────────────────────────────────────────────────
#
#   ./install.sh /chemin/vers/mon-projet [sous-dossier]
#
# Le sous-dossier vaut « duckynetwork » par défaut. Le module de destination est
# lu dans le go.mod du projet.
#
# Relancer le script sur un projet déjà équipé MET À JOUR le dossier : c'est le
# mode d'emploi des montées de version. Vos ajouts propres doivent donc vivre
# HORS de duckynetwork/ — voir doc/AJOUTER_UNE_TRAME.md.

set -euo pipefail

SOURCE_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/duckynetwork"
DEV_MODULE_PREFIX="duckynetwork/duckynetwork"

TARGET_PROJECT="${1:-}"
SUBDIR="${2:-duckynetwork}"

if [[ -z "$TARGET_PROJECT" ]]; then
    echo "usage: $0 /chemin/vers/projet [sous-dossier]" >&2
    exit 1
fi
if [[ ! -d "$SOURCE_DIR" ]]; then
    echo "erreur : dossier source introuvable : $SOURCE_DIR" >&2
    exit 1
fi
if [[ ! -f "$TARGET_PROJECT/go.mod" ]]; then
    echo "erreur : $TARGET_PROJECT ne contient pas de go.mod" >&2
    exit 1
fi

# tr -d supprime les retours chariot : un go.mod édité sous Windows est en CRLF,
# et le « \r » se retrouverait au milieu du chemin d'import, produisant un
# « invalid import path » que rien dans le message n'explique.
MODULE="$(awk '/^module[[:space:]]/ { print $2; exit }' "$TARGET_PROJECT/go.mod" | tr -d '\r')"
if [[ -z "$MODULE" ]]; then
    echo "erreur : nom de module illisible dans $TARGET_PROJECT/go.mod" >&2
    exit 1
fi

DEST="$TARGET_PROJECT/$SUBDIR"
NEW_PREFIX="$MODULE/$SUBDIR"

# Le dossier de destination est ENTIÈREMENT remplacé.
#
# Une fusion laisserait en place les fichiers d'une version antérieure supprimés
# depuis : ils compileraient encore, et rien ne signalerait qu'ils sont morts.
if [[ -d "$DEST" ]]; then
    echo "→ remplacement de $DEST"
    rm -rf "$DEST"
fi
mkdir -p "$(dirname "$DEST")"
cp -R "$SOURCE_DIR" "$DEST"

# Le go.mod de développement n'est jamais copié : il ferait de la destination un
# module imbriqué, que le module hôte cesserait de compiler.
rm -f "$DEST/go.mod" "$DEST/go.sum"

echo "→ réécriture des imports : $DEV_MODULE_PREFIX -> $NEW_PREFIX"
find "$DEST" -name '*.go' -type f -exec \
    sed -i.bak "s|\"$DEV_MODULE_PREFIX/|\"$NEW_PREFIX/|g" {} +
find "$DEST" -name '*.go.bak' -type f -delete

if command -v gofmt >/dev/null 2>&1; then
    gofmt -w "$DEST"
fi

echo
echo "duckynetwork installé dans $DEST"
echo "Importez-le ainsi :"
echo "    import \"$NEW_PREFIX/session\""
echo
echo "Vérification :  (cd $TARGET_PROJECT && go build ./...)"
