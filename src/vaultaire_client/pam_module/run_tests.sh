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
#   4  authorized_keys ecrit en root sans protection contre les liens
#   5  mot de passe injecte dans du JSON sans echappement
#   6  injection shell dans la gestion du groupe sudo
#   8  phase account qui ne refusait jamais rien

cc -Wall -Wextra -Werror -I"$ICI" -o "$TMP/hardening" \
   "$ICI/hardening_test.c" "$ICI/pam_common.c" -lcrypt
"$TMP/hardening"

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

# ---------------------------------------------------------------------------
echo
echo "=== Point 9 : les cles revoquees ne survivent pas a la connexion ==="
# ---------------------------------------------------------------------------
#
# Le comportement du parseur est verifie par hardening_test.c. Ce qui suit
# verifie ses APPELANTS, qu'aucun test ne peut exercer sans un daemon vivant et
# un serveur au bout : les deux modules PAM appellent le parseur depuis
# pam_sm_authenticate.
#
# Le defaut tenait a trois caracteres. « == 0 && keys » sautait l'ecriture des
# que la liste etait vide, donc laissait l'ancien authorized_keys intact apres
# une revocation totale — la seule revocation qui ne prenait jamais effet.
#
# On verifie les deux sens : que la forme fautive est absente, ET que l'appel
# attendu est bien present. Sans le second controle, deplacer ou renommer
# l'appel ferait passer ce garde-fou au vert sans plus rien surveiller.

verif_point9() {
    fichier="$1"
    if grep -q 'vaultaire_json_get_ssh_keys(resp, &keys, &key_count) == 0 && keys' "$fichier"; then
        echo "  [FAIL] $(basename "$fichier") : l'ecriture des cles est sautee quand la liste est vide"
        return 1
    fi
    if ! grep -q 'vaultaire_json_get_ssh_keys(resp, &keys, &key_count) == 0)' "$fichier"; then
        echo "  [FAIL] $(basename "$fichier") : appel a vaultaire_json_get_ssh_keys introuvable sous la forme attendue"
        return 1
    fi
    echo "  [PASS] $(basename "$fichier") reecrit authorized_keys meme sans aucune cle"
    return 0
}

verif_point9 "$ICI/pam_ssh_auth_module.c"
verif_point9 "$ICI/pam_login_custom_module.c"

# Le garde-fou teste sur lui-meme : soumis a la forme fautive, il doit refuser.
# Un controle par grep qui ne verrait plus rien passerait silencieusement.
sed 's/&key_count) == 0)/\&key_count) == 0 \&\& keys)/' \
    "$ICI/pam_ssh_auth_module.c" > "$TMP/fautif.c"
if verif_point9 "$TMP/fautif.c" >/dev/null 2>&1; then
    echo "  [FAIL] le controle ci-dessus ne detecte PAS la forme fautive"
    exit 1
fi
echo "  [PASS] le controle detecte bien la forme fautive"

echo
echo "Tous les tests sont passes."
