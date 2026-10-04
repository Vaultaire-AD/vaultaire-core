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
    echo "❌ $CXX introuvable." >&2
    echo "   Debian/Ubuntu : apt install mingw-w64" >&2
    echo "   Ou compilez avec MSVC — voir README.md." >&2
    exit 1
}

mkdir -p "$SORTIE"

# --- contrôle des formats larges (TO-DO 140) --------------------------------
#
# Dans un format LARGE (L"…"), MinGW lit `%s` comme une chaîne ÉTROITE —
# l'inverse de MSVC. Une chaîne large passée à `%s` s'arrête après un
# caractère : c'est ainsi que le fournisseur s'est inscrit sous le CLSID « { »
# au lieu de son GUID, et que son journal ne nommait plus rien. `%ls` a le même
# sens dans les deux compilateurs.
#
# GCC ne vérifie PAS les formats larges (-Wformat ne les lit pas) : ce contrôle
# est le seul. Les lignes de commentaire sont écartées — elles ont le droit de
# citer le défaut.
#
# Tous les refus de ce script vont sur la sortie d'ERREUR : build.sh l'appelle
# avec « >/dev/null », et un refus écrit sur la sortie standard y disparaissait
# — la fabrication s'arrêtait sans dire pourquoi.
if fautifs="$(grep -nE 'L"[^"]*%[-+ #0-9.]*s' "$ICI"/*.cpp "$ICI"/*.h | grep -vE '^[^:]+:[0-9]+:[[:space:]]*//')"; then
    {
        echo "❌ \`%s\` dans un format large : écrire \`%ls\` (voir vaultaire_pipe.h, Journaliser)."
        echo "$fautifs" | sed 's/^/     /'
    } >&2
    exit 1
fi

# -static, en plus de -static-libgcc -static-libstdc++ (TO-DO 139).
#
# La DLL est chargée par LogonUI, qui ne cherchera JAMAIS une dépendance à côté
# d'elle. Une dépendance manquante ne donne pas un message d'erreur : la tuile
# n'apparaît simplement pas.
#
# Les deux options -static-lib* ne couvrent QUE libgcc et libstdc++. Un MinGW
# au modèle de threads POSIX — le seul livré par certaines distributions, et
# une simple alternative sous Debian — lie en plus libwinpthread-1.dll, que
# l'archive ne contient pas. Selon la machine qui compilait, la DLL en
# dépendait ou non, sans que rien le dise. -static lie winpthreads dans la DLL
# quel que soit le modèle : le résultat ne dépend plus du compilateur.
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
    -static -static-libgcc -static-libstdc++ \
    -lole32 -loleaut32 -luuid -lsecur32 -ladvapi32 -lshlwapi

# --- contrôle des imports (TO-DO 139) ---------------------------------------
#
# C'est la CLASSE d'erreur qu'on ferme, pas seulement winpthreads : la DLL ne
# doit dépendre que de ce que Windows fournit lui-même. Toute autre dépendance
# arrête la fabrication ici, en la nommant — plutôt qu'à l'écran de connexion
# d'un poste, sans un mot.
#
# La liste est CLOSE : une DLL système de plus s'y ajoute en connaissance de
# cause, le jour où le code en a besoin.
OBJDUMP="${MINGW_OBJDUMP:-x86_64-w64-mingw32-objdump}"
command -v "$OBJDUMP" >/dev/null || OBJDUMP="objdump"
command -v "$OBJDUMP" >/dev/null || {
    echo "❌ objdump introuvable : les dépendances de la DLL ne peuvent pas être contrôlées." >&2
    echo "   Il est livré avec mingw-w64 (binutils-mingw-w64-x86-64)." >&2
    exit 1
}

entete="$("$OBJDUMP" -p "$CIBLE")" || { echo "❌ $CIBLE illisible par $OBJDUMP" >&2; exit 1; }

# 64 bits : LogonUI est un processus 64 bits, une DLL 32 bits n'y entre pas.
# (Chaîne-ici et non « echo | grep -q » : sous pipefail, grep -q qui sort au
# premier résultat fait échouer echo, et le contrôle refuse une DLL correcte.)
grep -q 'file format pei-x86-64' <<<"$entete" || {
    echo "❌ $CIBLE n'est pas une DLL x86-64 :" >&2
    grep 'file format' <<<"$entete" | sed 's/^/     /' >&2
    exit 1
}

SYSTEME='^(advapi32|kernel32|msvcrt|ole32|oleaut32|secur32|shlwapi|user32|rpcrt4)\.dll$'
imports="$(sed -n 's/^[[:space:]]*DLL Name: //p' <<<"$entete" | tr -d '\r')"
etrangers="$(grep -viE "$SYSTEME" <<<"$imports" || true)"
if [ -n "$etrangers" ]; then
    {
        echo "❌ la DLL dépend de bibliothèques que Windows ne fournit pas :"
        echo "$etrangers" | sed 's/^/     /'
        echo "   LogonUI ne les trouvera pas, et la tuile n'apparaîtra pas — sans message."
        echo "   Les lier statiquement, ou les ajouter à la liste si elles sont système."
    } >&2
    # La DLL fautive ne reste pas dans le répertoire de sortie : build.sh
    # l'emporterait dans l'archive à la fabrication suivante.
    rm -f "$CIBLE"
    exit 1
fi

echo "✅ $CIBLE"
echo "   imports : $(echo "$imports" | tr '\n' ' ')"
