#!/usr/bin/env bash
# ====================================================================
# build.sh — compiler l'agent Windows et fabriquer son archive
# ====================================================================
#
# Produit dist/vaultaire-client-windows-<version>.tar, à décompresser sur le
# poste Windows et à installer À LA MAIN avec install.ps1.
#
#   ./build.sh                    compile tout, fabrique l'archive
#   ./build.sh --version 2.2.1    impose la version injectée dans les binaires
#   ./build.sh --sans-dll         n'essaie pas de compiler le Credential Provider
#   ./build.sh --sortie <dir>     répertoire de sortie (défaut : ./dist)
#
# # Pourquoi une archive .tar et pas un installeur MSI
#
# Un MSI demande une chaîne de construction Windows (WiX, signature), et surtout
# il installe TOUT SEUL : services, DLL du Credential Provider, clés de
# registre. Sur la porte d'entrée d'une machine, c'est exactement ce qu'on ne
# veut pas tant que la V1 n'a pas tourné sur de vraies machines. L'archive se
# lit, se vérifie, et install.ps1 demande avant d'agir.
#
# La compilation croisée se fait depuis Linux : CGO n'est pas nécessaire (aucune
# bibliothèque C n'est liée à l'agent), donc `GOOS=windows go build` suffit.

set -euo pipefail

ICI="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)"
RACINE="$(cd "$ICI/../.." && pwd -P)"

SORTIE="$ICI/dist"
VERSION_IMPOSEE=""
AVEC_DLL=1

while [ $# -gt 0 ]; do
    case "$1" in
        --version)   VERSION_IMPOSEE="${2:-}"; shift ;;
        --sortie)    SORTIE="${2:-}"; shift ;;
        --sans-dll)  AVEC_DLL=0 ;;
        -h|--help)   sed -n '2,20p' "$0"; exit 0 ;;
        *) echo "option inconnue : $1"; exit 1 ;;
    esac
    shift
done

info() { echo -e "\033[1;34m[windows]\033[0m $*"; }
erreur() { echo -e "\033[1;31m[windows]\033[0m $*" >&2; exit 1; }

command -v go >/dev/null || erreur "go introuvable"

# --- version ---------------------------------------------------------------
#
# Même règle que le reste du dépôt : la série vient du fichier VERSION, le
# commit et la date de git. Un binaire qui ne sait pas d'où il vient est
# inexploitable sur un parc.
SERIE="$(tr -d '[:space:]' < "$RACINE/VERSION")"
VERSION="${VERSION_IMPOSEE:-${SERIE}.0}"
[[ "$VERSION" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]] || erreur "--version doit être X.Y.Z (reçu : $VERSION)"

COMMIT="$(git -C "$RACINE" rev-parse --short HEAD 2>/dev/null || echo inconnu)"
if ! git -C "$RACINE" diff --quiet 2>/dev/null; then COMMIT="${COMMIT}-dirty"; fi
DATE="$(date '+%Y-%m-%d')"

CHEMIN_VERSION="vaultaire_client_windows/version"
CHEMIN_SDK="duckynetworkclient/V1/duckynetwork/version"
LDFLAGS="-X ${CHEMIN_VERSION}.Version=${VERSION} -X ${CHEMIN_VERSION}.Commit=${COMMIT} -X ${CHEMIN_VERSION}.Date=${DATE}"
LDFLAGS="${LDFLAGS} -X ${CHEMIN_SDK}.Commit=${COMMIT} -X ${CHEMIN_SDK}.Date=${DATE}"

ETAPE="$SORTIE/vaultaire-client-windows-$VERSION"
rm -rf "$ETAPE"
mkdir -p "$ETAPE"

# --- l'agent et l'outil de test --------------------------------------------
info "compilation de l'agent ($VERSION, commit $COMMIT)"
(cd "$ICI" && GOOS=windows GOARCH=amd64 CGO_ENABLED=0 \
    go build -buildvcs=false -ldflags "$LDFLAGS" -o "$ETAPE/vaultaire_client_windows.exe" .)

info "compilation de vaultaire_login"
(cd "$ICI" && GOOS=windows GOARCH=amd64 CGO_ENABLED=0 \
    go build -buildvcs=false -ldflags "$LDFLAGS" -o "$ETAPE/vaultaire_login.exe" ./cmd/vaultaire_login)

# --- le Credential Provider ------------------------------------------------
#
# Son absence n'arrête PAS la fabrication : l'agent et vaultaire_login suffisent
# à éprouver toute la chaîne d'authentification, et c'est ce qu'on fait en
# premier. L'archive dit alors clairement ce qui lui manque.
if [ "$AVEC_DLL" = 1 ] && command -v "${MINGW_CXX:-x86_64-w64-mingw32-g++}" >/dev/null; then
    info "compilation du Credential Provider"
    "$ICI/credential_provider/build-cp.sh" "$ETAPE" >/dev/null
    info "  $(basename "$ETAPE")/VaultaireCredentialProvider.dll"
else
    [ "$AVEC_DLL" = 1 ] && info "mingw-w64 absent : archive SANS Credential Provider"
fi

# --- ce qui accompagne les binaires ----------------------------------------

# Les scripts PowerShell partent avec une marque d'ordre des octets (BOM).
#
# C'est l'inverse de ce que fait install.ps1 pour les fichiers qu'il ÉCRIT, et
# les deux règles sont justes :
#
#   - un fichier LU PAR WINDOWS POWERSHELL 5.1 — celui livré avec Windows —
#     doit porter un BOM. Sans lui, l'interpréteur suppose l'encodage ANSI de la
#     machine (Windows-1252) et les accents deviennent des « Ã© ». Tout ce
#     script est en français : sans BOM, la moitié des messages est illisible ;
#   - un fichier LU PAR L'AGENT (JSON, empreinte) ne doit PAS en porter : la
#     norme JSON l'interdit, et le décodeur Go refuse le document.
#
# PowerShell 7 lit l'UTF-8 par défaut et se moque du BOM : l'ajouter ne coûte
# rien là où il n'est pas nécessaire.
ajouter_bom() {
    local source="$1" cible="$2"
    if head -c 3 "$source" | od -An -tx1 | grep -q "ef bb bf"; then
        cp "$source" "$cible"
    else
        printf '\xEF\xBB\xBF' > "$cible"
        cat "$source" >> "$cible"
    fi
}
ajouter_bom "$ICI/install.ps1" "$ETAPE/install.ps1"
ajouter_bom "$ICI/uninstall.ps1" "$ETAPE/uninstall.ps1"
cp "$ICI/README.md" "$ETAPE/LISEZMOI.md"

cat > "$ETAPE/client_conf.exemple.json" <<'JSON'
{
  "servers": [
    { "ip": "10.0.0.10", "port": 6666 }
  ]
}
JSON

cat > "$ETAPE/VERSION.txt" <<TXT
vaultaire_client_windows $VERSION
commit  : $COMMIT
compilé : $DATE
contenu :
  vaultaire_client_windows.exe   l'agent (service Windows)
  vaultaire_login.exe            éprouver l'authentification sans écran de connexion
  VaultaireCredentialProvider.dll  tuile de l'écran de connexion (si présente)
  install.ps1 / uninstall.ps1    installation manuelle assistée
TXT

# --- l'archive -------------------------------------------------------------
ARCHIVE="$SORTIE/vaultaire-client-windows-$VERSION.tar"
rm -f "$ARCHIVE"
tar -C "$SORTIE" -cf "$ARCHIVE" "$(basename "$ETAPE")"

info "archive : $ARCHIVE"
info "contenu :"
tar -tf "$ARCHIVE" | sed 's/^/    /'
