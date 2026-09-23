#!/usr/bin/env bash
# ====================================================================
# build-cp.sh — compiler le Credential Provider (DLL COM)
# ====================================================================
#
# Deux chaînes possibles, la même DLL :
#
#   MinGW (Linux, WSL)  ./build-cp.sh
#   MSVC  (Windows)     voir README.md, section « Compiler avec MSVC »
#
# MinGW par défaut parce que c'est ce dont dispose la chaîne de compilation du
# dépôt : auto-compil.sh tourne sous Linux, et exiger Visual Studio ferait de
# la DLL le seul artefact qu'on ne sait pas produire.
#
# Sortie : build/VaultaireCredentialProvider.dll

set -euo pipefail

ICI="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)"
SORTIE="${1:-$ICI/build}"
CIBLE="$SORTIE/VaultaireCredentialProvider.dll"

CXX="${MINGW_CXX:-x86_64-w64-mingw32-g++}"
command -v "$CXX" >/dev/null || {
    echo "❌ $CXX introuvable."
    echo "   Debian/Ubuntu : apt install mingw-w64"
    echo "   Ou compilez avec MSVC — voir README.md."
    exit 1
}

mkdir -p "$SORTIE"

# -static-libgcc -static-libstdc++ : la DLL est chargée par LogonUI, qui ne
# cherchera JAMAIS libstdc++-6.dll à côté d'elle. Une dépendance manquante ici
# ne donne pas un message d'erreur : la tuile n'apparaît simplement pas.
#
# -municode n'est pas utilisé : il impose wmain, et une DLL n'en a pas.
"$CXX" -shared -o "$CIBLE" \
    "$ICI/vaultaire_dll.cpp" \
    "$ICI/vaultaire_provider.cpp" \
    "$ICI/vaultaire_credential.cpp" \
    "$ICI/vaultaire_kerb.cpp" \
    "$ICI/vaultaire_pipe.cpp" \
    "$ICI/vaultaire_cp.def" \
    -I"$ICI" \
    -O2 -std=c++17 -Wall -Wextra -Wno-unused-parameter \
    -DUNICODE -D_UNICODE -DWIN32_LEAN_AND_MEAN \
    -static-libgcc -static-libstdc++ \
    -lole32 -loleaut32 -luuid -lsecur32 -ladvapi32 -lshlwapi

echo "✅ $CIBLE"
