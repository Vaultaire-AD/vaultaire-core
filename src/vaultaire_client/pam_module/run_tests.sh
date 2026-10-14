#!/bin/sh
# Tests des modules NSS et PAM.
#
#   ./run_tests.sh
#
# Aucune installation dans /lib, aucune modification de nsswitch.conf : les
# fonctions sont appelees directement. Tester le module NSS « pour de vrai »
# demanderait de l'installer sur la machine de developpement, donc de risquer
# d'y casser la resolution des comptes.
set -e

ICI="$(cd "$(dirname "$0")" && pwd)"
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

UID_COURANT="$(id -u)"

# ---------------------------------------------------------------------------
echo "=== Module NSS : identifiants des utilisateurs du domaine ==="
# ---------------------------------------------------------------------------

cat > "$TMP/uid.map" <<'MAP'
# carte de test
alice@dom:5001:5001
bob@dom:5002:5002
pirate@dom:0:0
horsplage@dom:99999:99999
pasunnombre@dom:abc:5003
MAP

sed "s#\"/etc/vaultaire/uid.map\"#\"$TMP/uid.map\"#" "$ICI/nss_vaultaire.c" > "$TMP/nss.c"
cc -Wall -Wextra -Werror -o "$TMP/nsstest" "$ICI/nss_vaultaire_test.c" "$TMP/nss.c"
"$TMP/nsstest"

# ---------------------------------------------------------------------------
echo
echo "=== Garde-fou du socket PAM ==="
# ---------------------------------------------------------------------------
#
# Le proprietaire attendu est deplace vers l'uid courant : aucune machine de
# developpement ne permet de creer un fichier appartenant a root sans etre root.
# La LOGIQUE testee est identique — seule la cible change.

cc -Wall -Wextra -Werror -DVAULTAIRE_SOCKET_OWNER="$UID_COURANT" \
   -o "$TMP/socktest" "$ICI/socket_security_test.c" "$ICI/pam_common.c" -lcrypt
"$TMP/socktest"

# Second passage : le controle attend un AUTRE proprietaire que celui des
# fichiers crees. C'est le coeur de l'attaque — un socket parfaitement forme,
# mais qui n'appartient pas a l'agent.
echo
echo "--- avec un proprietaire attendu different (usurpation)"
AUTRE=$((UID_COURANT + 1))
cc -Wall -Wextra -Werror -DVAULTAIRE_SOCKET_OWNER="$AUTRE" \
   -o "$TMP/socktest_autre" "$ICI/socket_security_test.c" "$ICI/pam_common.c" -lcrypt
VAULTAIRE_TEST_ATTEND_AUTRE_UID=1 "$TMP/socktest_autre"

# ---------------------------------------------------------------------------
echo
echo "=== Durcissement : points majeurs de l'audit ==="
# ---------------------------------------------------------------------------
#
#   5  mot de passe injecte dans du JSON sans echappement
#   6  liste blanche des noms
#   8  phase account qui ne refusait jamais rien
#
# (4 et 9, authorized_keys : cote agent depuis le TO-DO 197.)

cc -Wall -Wextra -Werror -I"$ICI" -o "$TMP/hardening" \
   "$ICI/hardening_test.c" "$ICI/pam_common.c" -lcrypt
"$TMP/hardening"

# ---------------------------------------------------------------------------
echo
echo "=== TO-DO 198 : le module n'attend pas l'agent sans fin ==="
# ---------------------------------------------------------------------------
#
# Echeance ramenee a 400 ms pour le test : la logique est la meme qu'a 20 s.

cc -Wall -Wextra -Werror -I"$ICI" -DVAULTAIRE_DELAI_REPONSE_MS=400 -o "$TMP/delai" \
   "$ICI/delai_test.c" "$ICI/pam_common.c" -lcrypt
"$TMP/delai"

# ---------------------------------------------------------------------------
echo
echo "=== TO-DO 199 : chronometrage, en mode debug seulement ==="
# ---------------------------------------------------------------------------

cc -Wall -Wextra -Werror -I"$ICI" -o "$TMP/chrono" \
   "$ICI/chrono_test.c" "$ICI/pam_common.c" -lcrypt
"$TMP/chrono"

# ---------------------------------------------------------------------------
echo
echo "=== TO-DO 197 : le module ne gere plus le compte ==="
# ---------------------------------------------------------------------------
#
# Le compte est l'affaire de l'agent : creation, authorized_keys, groupe
# d'administration, SELinux. Le module les refaisait juste apres lui, a chaque
# connexion — et reecrivait authorized_keys VIDE, faute de recevoir les cles
# (TO-DO 188). Il ne garde que le mot de passe local.
#
# Le controle porte sur le SOURCE compile dans les modules, hors commentaires :
# aucune des commandes ni des fonctions du compte ne doit y reapparaitre.

verif_197() {
    fichier="$1"
    if grep -nE '"(/usr/sbin/)?(useradd|usermod|gpasswd|groupadd|adduser|deluser|restorecon)"|setup_user_ssh_keys|write_ssh_keys|sudo_group' "$fichier" \
        | grep -vE '^[0-9]+:[[:space:]]*(/\*|\*|//)' >/dev/null; then
        echo "  [FAIL] $(basename "$fichier") touche encore au compte"
        return 1
    fi
    echo "  [PASS] $(basename "$fichier") ne touche qu'au mot de passe local"
    return 0
}

ECHEC197=0
for f in "$ICI/pam_common.c" "$ICI/pam_ssh_auth_module.c" "$ICI/pam_login_custom_module.c"; do
    verif_197 "$f" || ECHEC197=1
done
for f in "$ICI/pam_ssh_auth_module.c" "$ICI/pam_login_custom_module.c"; do
    if ! grep -q 'vaultaire_sync_local_password(username, password)' "$f"; then
        echo "  [FAIL] $(basename "$f") n'aligne plus le mot de passe local"
        ECHEC197=1
    fi
done

# Le garde-fou teste sur lui-meme : un usermod reintroduit doit etre vu.
printf 'static void f(void){ const char *a[]={"usermod","-aG","sudo",0}; (void)a; }\n' > "$TMP/fautif197.c"
if verif_197 "$TMP/fautif197.c" >/dev/null 2>&1; then
    echo "  [FAIL] le controle ci-dessus ne detecte PAS un usermod reintroduit"
    exit 1
fi
echo "  [PASS] le controle detecte bien un usermod reintroduit"
[ "$ECHEC197" -eq 0 ] || exit 1

echo
echo "Tous les tests sont passes."
