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
echo "=== Arguments de useradd ==="
# ---------------------------------------------------------------------------
#
# Les arguments etaient dans le desordre : --shell consommait -c comme valeur,
# et useradd refusait la commande a CHAQUE appel. Le defaut restait invisible
# parce que l'ancien module NSS repondait pour tout nom du domaine, si bien que
# getpwnam reussissait et que useradd n'etait jamais appele.
#
# On extrait les arguments du code source et on les soumet au vrai binaire.
# Verifier a la main ne protege de rien : c'est l'ordre dans le CODE qui doit
# rester correct.

if [ -x /usr/sbin/useradd ]; then
    "$ICI/check_useradd_args.sh" "$ICI/pam_common.c"
else
    echo "  [SKIP] useradd absent de cette machine"
fi

echo
echo "Tous les tests sont passes."
