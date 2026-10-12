#!/usr/bin/env bash
# ====================================================================
# essai-wine.sh — éprouver la DLL du Credential Provider sous wine (TO-DO 149)
# ====================================================================
#
#   ./essai-wine.sh <VaultaireCredentialProvider.dll>
#
# Les défauts des TO-DO 139 et 140 — une dépendance manquante, une inscription
# sous le CLSID « { » — n'ont été vus qu'à l'écran de connexion d'un vrai
# Windows Server. Un essai de vingt lignes les montrait tous les deux. Le voici,
# dans la fabrication :
#
#   0. poste existant   un autre fournisseur, et les clés « { » qu'une DLL
#                       antérieure au TO-DO 140 a laissées ;
#   1. inscription      regsvr32, comme install.ps1 ;
#   2. registre         le GUID de vaultaire_guid.h sous les DEUX clés que
#                       LogonUI lit, la DLL pour InprocServer32, Apartment ;
#                       aucune clé « { » ;
#   3. activation       faux_logonui.exe : CoCreateInstance du CLSID, puis la
#                       suite d'appels de LogonUI, agent absent, muet et
#                       répondant (voir essai/faux_logonui.cpp) ;
#   4. trace            la même suite, témoin de trace posé : chaque entrée de
#                       méthode a sa sortie, et ni le mot de passe ni le code
#                       tapés n'apparaissent dans le journal ;
#   4bis. variantes     les trois variantes d'essai du TO-DO 157 posées dans le
#                       registre : la suite voit ce qu'elles changent, et le
#                       journal les nomme ;
#   5. retrait          regsvr32 /u : plus rien de Vaultaire dans le registre,
#                       l'autre fournisseur intact.
#
# Ce n'est PAS LogonUI. La tuile elle-même — qu'elle apparaisse, qu'on puisse
# s'y connecter — reste une recette manuelle sur un vrai poste (A_TESTER.md).
#
# Un préfixe wine NEUF à chaque essai, effacé à la fin : un registre hérité
# d'un essai précédent ferait passer une inscription cassée pour bonne.
#
# Code de sortie : 0 si tout est juste, 1 sinon, 2 si l'essai n'a pas pu
# tourner (wine ou mingw absents, DLL introuvable).

set -euo pipefail

ICI="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)"
DLL="${1:-$ICI/build/VaultaireCredentialProvider.dll}"

info()   { echo -e "\033[1;34m[essai-wine]\033[0m $*"; }
ok()     { echo -e "  \033[1;32mok\033[0m     $*"; }
echec()  { echo -e "  \033[1;31mECHEC\033[0m  $*"; ECHECS=$((ECHECS + 1)); }
fatal()  { echo -e "\033[1;31m[essai-wine]\033[0m $*" >&2; exit 2; }

ECHECS=0

[ -f "$DLL" ] || fatal "DLL introuvable : $DLL"
WINE="${WINE:-wine}"
command -v "$WINE" >/dev/null || fatal "wine introuvable (Debian/Ubuntu : apt install wine64)"
CXX="${MINGW_CXX:-x86_64-w64-mingw32-g++}"
command -v "$CXX" >/dev/null || fatal "$CXX introuvable (apt install mingw-w64)"

# --- le GUID attendu, lu dans DEFINE_GUID ---------------------------------
#
# Lu dans la définition, pas dans le commentaire qui la précède : c'est la
# définition que le compilateur a mise dans la DLL, et un commentaire peut
# diverger sans que rien ne le dise.
#
# printf de bash et non awk : strtonum n'existe que dans gawk, et l'awk par
# défaut de Debian et d'Ubuntu est mawk.
IFS=, read -r -a PARTS <<<"$(tr -d '\n' < "$ICI/vaultaire_guid.h" \
    | sed -n 's/.*DEFINE_GUID([[:space:]]*CLSID_VaultaireProvider,\([^)]*\)).*/\1/p' \
    | tr -d ' \t')"
GUID=""
if [ "${#PARTS[@]}" -eq 11 ]; then
    GUID="$(printf '{%08X-%04X-%04X-%02X%02X-%02X%02X%02X%02X%02X%02X}' "${PARTS[@]}" 2>/dev/null || true)"
fi
[[ "$GUID" =~ ^\{[0-9A-F]{8}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{12}\}$ ]] \
    || fatal "GUID illisible dans vaultaire_guid.h (lu : « $GUID »)"
LIBELLE="Vaultaire Credential Provider"

CLE_COM='HKLM\Software\Classes\CLSID'
CLE_CP='HKLM\Software\Microsoft\Windows\CurrentVersion\Authentication\Credential Providers'

# --- le préfixe wine --------------------------------------------------------
TRAVAIL="$(mktemp -d "${TMPDIR:-/tmp}/vaultaire-essai-wine.XXXXXX")"
export WINEPREFIX="$TRAVAIL/prefixe"
export WINEARCH=win64
export WINEDEBUG=-all
# Pas de fenêtre ni de demande d'installer Mono ou Gecko : l'essai tourne sans
# écran, en CI comme dans un terminal.
export WINEDLLOVERRIDES="mscoree,mshtml="
export DISPLAY=""

nettoyer() {
    WINEPREFIX="$WINEPREFIX" wineserver -k >/dev/null 2>&1 || true
    rm -rf "$TRAVAIL"
}
trap nettoyer EXIT

# Les sorties de wine — avertissements « fixme », « wine32 is missing » — vont
# dans un fichier, montré seulement si une étape échoue.
BRUIT="$TRAVAIL/wine.log"
w() { "$WINE" "$@" 2>>"$BRUIT"; }

info "faux LogonUI : compilation"
"$CXX" -o "$TRAVAIL/faux_logonui.exe" "$ICI/essai/faux_logonui.cpp" -I"$ICI" \
    -O2 -std=c++17 -Wall -Wextra -Wno-unused-parameter -DUNICODE -D_UNICODE \
    -static -static-libgcc -static-libstdc++ -lole32 -luuid -lgdi32 \
    || fatal "faux_logonui.cpp ne compile pas"

info "préfixe wine neuf ($WINEPREFIX)"
"$WINE" wineboot -i >>"$BRUIT" 2>&1 || { cat "$BRUIT" >&2; fatal "wineboot a échoué"; }
wineserver -w 2>/dev/null || true

C="$WINEPREFIX/drive_c"
# Là où install.ps1 la pose, pour que le chemin inscrit ressemble à celui d'un
# poste.
DEST="$C/Program Files/Vaultaire"
mkdir -p "$DEST" "$C/ProgramData/Vaultaire/logs"
cp "$DLL" "$DEST/VaultaireCredentialProvider.dll"
cp "$TRAVAIL/faux_logonui.exe" "$DEST/faux_logonui.exe"
DLL_WIN='C:\Program Files\Vaultaire\VaultaireCredentialProvider.dll'
JOURNAL="$C/ProgramData/Vaultaire/logs/credential_provider.log"
TEMOIN="$C/ProgramData/Vaultaire/logs/credential_provider.trace"

# valeur <clé> [<nom>] : la donnée d'une valeur (défaut si pas de nom), ou rien.
valeur() {
    local cle="$1" nom="${2:-}" sortie
    if [ -z "$nom" ]; then
        sortie="$(w reg query "$cle" /ve)" || return 0
    else
        sortie="$(w reg query "$cle" /v "$nom")" || return 0
    fi
    tr -d '\r' <<<"$sortie" | sed -n 's/^[[:space:]]*[^[:space:]].*REG_SZ[[:space:]]*//p' | head -n1
}
existe() { w reg query "$1" >/dev/null; }

# --- 0. un poste qui n'est pas vierge -------------------------------------------
#
# Un préfixe neuf ne ressemble à aucun poste. On y pose ce qu'un poste réel
# porte et que l'inscription et le retrait doivent traiter correctement :
#
#   - un AUTRE fournisseur, que le retrait ne doit pas toucher ;
#   - les clés « { » au libellé de Vaultaire, laissées par une DLL antérieure au
#     TO-DO 140 : l'inscription doit les retirer (RetirerInscriptionTronquee).
VOISIN='{0D15EA5E-0000-4000-8000-000000000149}'
echo
info "0. poste existant : un autre fournisseur, une inscription tronquée d'avant le 140"
w reg add "$CLE_CP\\$VOISIN" /ve /d "Voisin de l'essai" /f >/dev/null || fatal "reg add impossible"
w reg add "$CLE_COM\\{" /ve /d "$LIBELLE" /f >/dev/null || fatal "reg add impossible"
w reg add "$CLE_CP\\{" /ve /d "$LIBELLE" /f >/dev/null || fatal "reg add impossible"
existe "$CLE_COM\\{" && existe "$CLE_CP\\{" && existe "$CLE_CP\\$VOISIN" \
    && ok "posés : $VOISIN, CLSID\\{ et Credential Providers\\{" \
    || fatal "le registre du préfixe ne garde pas les clés posées"

# --- 1. inscription ---------------------------------------------------------
echo
info "1. inscription (regsvr32)"
if w regsvr32 /s "$DLL_WIN"; then
    ok "regsvr32 rend 0"
else
    echec "regsvr32 rend $? — 3 : la DLL ne se charge pas (dépendance, architecture)"
fi

# --- 2. registre --------------------------------------------------------------
echo
info "2. registre (GUID attendu $GUID)"
v="$(valeur "$CLE_COM\\$GUID")"
[ "$v" = "$LIBELLE" ] && ok "CLSID\\$GUID = « $v »" || echec "CLSID\\$GUID absent ou mal nommé (« $v »)"

v="$(valeur "$CLE_COM\\$GUID\\InprocServer32")"
[ "${v,,}" = "${DLL_WIN,,}" ] && ok "InprocServer32 = $v" || echec "InprocServer32 = « $v », attendu « $DLL_WIN »"

v="$(valeur "$CLE_COM\\$GUID\\InprocServer32" ThreadingModel)"
[ "$v" = "Apartment" ] && ok "ThreadingModel = Apartment" || echec "ThreadingModel = « $v »"

v="$(valeur "$CLE_CP\\$GUID")"
[ "$v" = "$LIBELLE" ] && ok "Credential Providers\\$GUID = « $v »" || echec "Credential Providers\\$GUID absent (« $v »)"

# Le défaut du TO-DO 140, nommé : une inscription tronquée au premier caractère.
# Les clés « { » posées à l'étape 0 doivent AUSSI avoir disparu : une clé
# restante est soit une inscription neuve tronquée, soit un nettoyage qui ne se
# fait plus.
if existe "$CLE_COM\\{" || existe "$CLE_CP\\{"; then
    echec "une clé « { » existe : GUID tronqué (format large, %s au lieu de %ls ?) ou ancienne inscription non retirée"
else
    ok "aucune clé « { » (l'ancienne inscription tronquée est retirée)"
fi

grep -q "fournisseur inscrit" "$JOURNAL" 2>/dev/null \
    && ok "journal : « $(grep -m1 'fournisseur inscrit' "$JOURNAL" | tr -d '\r' | cut -d' ' -f3-) »" \
    || echec "journal : pas de ligne « fournisseur inscrit »"

# --- 3. activation et suite de LogonUI ------------------------------------------
# Le chien de garde est dans faux_logonui.exe (90 s), qui nomme l'endroit du
# blocage. Le « timeout » ne couvre que wine lui-même : un wineserver figé ne
# doit pas tenir la fabrication indéfiniment.
lancer_faux_logonui() {
    local sortie="$1" rc=0
    shift
    ( cd "$DEST" && timeout 180 "$WINE" faux_logonui.exe "$@" ) >"$sortie" 2>>"$BRUIT" || rc=$?
    [ "$rc" = 124 ] && echo "  ECHEC  wine n'a pas rendu la main en 180 s" >>"$sortie"
    tr -d '\r' < "$sortie" | sed 's/^/    /'
    return $rc
}

echo
info "3. activation par COM et suite d'appels de LogonUI"
if lancer_faux_logonui "$TRAVAIL/suite.txt"; then
    ok "faux LogonUI : aucun échec"
else
    echec "faux LogonUI : $(grep -c 'ECHEC' "$TRAVAIL/suite.txt" || true) échec(s) — voir ci-dessus"
fi

# --- 4. la même suite, trace allumée ----------------------------------------------
echo
info "4. même suite, témoin de trace posé"
: > "$JOURNAL"
: > "$TEMOIN"
if lancer_faux_logonui "$TRAVAIL/suite-trace.txt" >/dev/null; then
    ok "faux LogonUI sous trace : aucun échec"
else
    echec "faux LogonUI sous trace : $(grep -c 'ECHEC' "$TRAVAIL/suite-trace.txt" || true) échec(s)"
    tr -d '\r' < "$TRAVAIL/suite-trace.txt" | grep 'ECHEC' | sed 's/^/    /'
fi
rm -f "$TEMOIN"

# Le journal est en UTF-8 (ccs=UTF-8) ; on le lit tel quel.
TRACE="$(tr -d '\r' < "$JOURNAL" | sed -n 's/.* trace fil=[0-9]* //p')"
entrees="$(grep -c '^> ' <<<"$TRACE" || true)"
if [ "${entrees:-0}" -gt 0 ]; then
    ok "trace : $entrees entrée(s) de méthode"
else
    echec "trace : aucune entrée — le témoin n'a pas été lu"
fi

# Chaque « > Méthode » doit avoir son « < Méthode ». Une entrée sans sortie est
# exactement ce que la trace sert à montrer sur un poste (TO-DO 157) : ici, elle
# ne doit jamais apparaître.
orphelines="$(awk '
    /^> / { m = $2; ouvertes[m]++ }
    /^< / { m = $2; ouvertes[m]-- }
    END { for (m in ouvertes) if (ouvertes[m] != 0) printf "%s (%+d) ", m, ouvertes[m] }
' <<<"$TRACE")"
[ -z "$orphelines" ] && ok "trace : chaque entrée a sa sortie" || echec "trace : entrées et sorties déséquilibrées : $orphelines"

# Rien de ce qui a été tapé ne doit être écrit (vaultaire_trace.h, « Ce qui n'y
# entre JAMAIS »). Valeurs tenues en accord avec essai/faux_logonui.cpp.
fuite=0
for secret in "MotDePasse-Essai-149" "314159"; do
    if grep -q -- "$secret" "$JOURNAL"; then
        echec "journal : la valeur tapée « $secret » y figure"
        fuite=1
    fi
done
[ "$fuite" = 0 ] && ok "journal : ni le mot de passe ni le code tapés"

# --- 4bis. les variantes d'essai (TO-DO 157) ---------------------------------------
echo
info "4bis. variantes d'essai posées (TuileParDefaut, ModeV1, SansImage)"
CLE_VARIANTES='HKLM\Software\Vaultaire\CredentialProvider'
for v in TuileParDefaut ModeV1 SansImage; do
    w reg add "$CLE_VARIANTES" /v "$v" /t REG_DWORD /d 1 /f >/dev/null
done
: > "$JOURNAL"
if lancer_faux_logonui "$TRAVAIL/suite-variantes.txt" --variantes >/dev/null; then
    ok "faux LogonUI, variantes posées : aucun échec"
else
    echec "faux LogonUI, variantes posées : $(grep -c 'ECHEC' "$TRAVAIL/suite-variantes.txt" || true) échec(s)"
    tr -d '\r' < "$TRAVAIL/suite-variantes.txt" | grep 'ECHEC' | sed 's/^/    /'
fi
# Une recette qui oublierait une variante posée conclurait sur le mauvais
# comportement : la DLL les nomme au journal.
if tr -d '\r' < "$JOURNAL" | grep -q "variantes d'essai actives : TuileParDefaut=1 ModeV1=1 SansImage=1"; then
    ok "journal : les variantes actives sont nommées"
else
    echec "journal : aucune ligne « variantes d'essai actives »"
fi
w reg delete 'HKLM\Software\Vaultaire' /f >/dev/null

# --- 5. retrait ---------------------------------------------------------------
echo
info "5. retrait (regsvr32 /u)"
if w regsvr32 /u /s "$DLL_WIN"; then ok "regsvr32 /u rend 0"; else echec "regsvr32 /u rend $?"; fi
restes=""
for cle in "$CLE_COM\\$GUID" "$CLE_CP\\$GUID" "$CLE_COM\\{" "$CLE_CP\\{"; do
    existe "$cle" && restes="$restes $cle"
done
[ -z "$restes" ] && ok "plus rien de Vaultaire dans le registre" || echec "clés restantes :$restes"

# Le retrait ne touche qu'à ses clés.
existe "$CLE_CP\\$VOISIN" && ok "l'autre fournisseur est intact" || echec "le retrait a effacé l'autre fournisseur $VOISIN"

# --- verdict ------------------------------------------------------------------
echo
if [ "$ECHECS" -ne 0 ]; then
    info "\033[1;31m$ECHECS échec(s)\033[0m — sorties de wine :"
    tail -n 40 "$BRUIT" | sed 's/^/    /' >&2
    exit 1
fi
info "\033[1;32mDLL éprouvée sous wine\033[0m : inscription, activation, suite de LogonUI, trace, retrait."
info "Ce n'est pas LogonUI : la tuile reste à voir sur un vrai poste (A_TESTER.md)."
