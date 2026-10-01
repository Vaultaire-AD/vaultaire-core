#!/usr/bin/env bash
# Compile vaultaire_nexus seul, sans toucher à auto-compil.sh.
#
#   ./build.sh                 → dist/vaultaire_nexus
#   ./build.sh -o /chemin/bin  → sortie ailleurs
#   NEXUS_VERSION=2.1.4 ./build.sh
#
# Même contrat que auto-compil.sh : binaire statique (CGO_ENABLED=0), commit et
# date injectés, version sémantique injectée si fournie. L'intégration à
# auto-compil.sh et à la release est décrite dans CORE_CHANGEMENTS.md § 7.
set -euo pipefail

ICI="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)"
RACINE="$(cd "$ICI/../.." && pwd -P)"
SORTIE="$ICI/dist/vaultaire_nexus"

while [ $# -gt 0 ]; do
    case "$1" in
        -o) SORTIE="$2"; shift 2 ;;
        -h|--help) sed -n '2,10p' "$0"; exit 0 ;;
        *) echo "option inconnue : $1" >&2; exit 2 ;;
    esac
done

command -v go >/dev/null || { echo "❌ go introuvable" >&2; exit 1; }

COMMIT="dev"
DATE="inconnue"
if git -C "$RACINE" rev-parse --git-dir >/dev/null 2>&1; then
    COMMIT="g$(git -C "$RACINE" rev-parse --short=7 HEAD)"
    git -C "$RACINE" diff --quiet HEAD -- "src/vaultaire_nexus" 2>/dev/null || COMMIT="$COMMIT-modifié"
    DATE="$(git -C "$RACINE" log -1 --format=%cs)"
fi

LDFLAGS="-s -w -X vaultaire_nexus/version.Commit=$COMMIT -X vaultaire_nexus/version.Date=$DATE"
LDFLAGS="$LDFLAGS -X duckynetworkclient/V1/duckynetwork/version.Commit=$COMMIT -X duckynetworkclient/V1/duckynetwork/version.Date=$DATE"
if [ -n "${NEXUS_VERSION:-}" ]; then
    LDFLAGS="$LDFLAGS -X vaultaire_nexus/version.Version=${NEXUS_VERSION#v}"
fi

mkdir -p "$(dirname "$SORTIE")"
echo "🛠  vaultaire_nexus ($(go env GOVERSION)) → $SORTIE"
(cd "$ICI" && CGO_ENABLED=0 go build -trimpath -buildvcs=false -ldflags "$LDFLAGS" -o "$SORTIE" .)

# Une valeur -X sur un chemin inexistant est ignorée sans erreur : on relit.
ANNONCE="$("$SORTIE" -version)"
echo "✅ $ANNONCE"
case "$ANNONCE" in
    *"build local"*) [ "$COMMIT" = "dev" ] || { echo "❌ commit non injecté" >&2; exit 1; } ;;
esac
