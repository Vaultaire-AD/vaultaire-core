#!/bin/sh
# Verifie que les arguments passes a useradd par pam_common.c sont acceptes par
# le vrai binaire.
#
# On ne cree aucun compte : useradd est appele avec un nom de connexion
# volontairement invalide. Ce qui compte est le MOTIF du refus.
#
#   - « invalid shell », « unrecognized option », « too many arguments »
#     -> les arguments sont mal formes : ECHEC
#   - « invalid user name », « Permission denied », « cannot lock »
#     -> les arguments ont ete acceptes, seul le nom ou les droits bloquent : OK
set -e
SRC="$1"
LC_ALL=C
export LC_ALL

# Extraction des arguments litteraux de l'appel execl, dans l'ordre du source.
ARGS="$(sed -n '/execl("\/usr\/sbin\/useradd"/,/NULL)/p' "$SRC" \
        | grep -oE '"[^"]*"' \
        | tr -d '"' \
        | grep -v '^/usr/sbin/useradd$' \
        | grep -v '^useradd$' \
        | tr '\n' ' ')"

if [ -z "$ARGS" ]; then
    echo "  [FAIL] arguments de useradd introuvables dans $SRC"
    exit 1
fi

echo "  arguments releves dans le code : $ARGS"

# Nom de connexion volontairement invalide : on ne veut surtout pas creer de
# compte sur la machine qui execute les tests.
SORTIE="$(/usr/sbin/useradd $ARGS -- '..invalide..' 2>&1 || true)"

case "$SORTIE" in
    *"invalid shell"*|*"unrecognized option"*|*"too many arguments"*|*"invalid option"*)
        echo "  [FAIL] useradd rejette les ARGUMENTS : $SORTIE"
        exit 1
        ;;
    *)
        echo "  [PASS] les arguments sont acceptes par useradd"
        echo "         (refus attendu sur le nom ou les droits : $SORTIE)"
        ;;
esac
