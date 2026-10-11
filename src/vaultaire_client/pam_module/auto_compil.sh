#!/usr/bin/env bash
# ====================================================================
# Compilation des modules natifs de l'agent — TO-DO 173
# ====================================================================
#
#     ./auto_compil.sh <répertoire de sortie>
#
# Produit, dans le répertoire de sortie, les quatre fichiers que le core envoie
# à un poste :
#
#     pam_login_custom_module.so   pam_logout_custom_module.so
#     pam_ssh_auth_module.so       libnss_vaultaire.so.2
#
# C'est la SEULE recette : auto-compil.sh l'appelle pour le poste de
# développement et la CI de release, et la CI l'appelle seule dans l'image
# Debian. Deux copies des lignes gcc avaient divergé une fois ; une seule ne
# le peut pas.
#
# # Un module natif ne tourne que sur une glibc au moins aussi récente
#
# Les modules sont liés à la glibc et à la libcrypt de la machine qui les
# compile. Sur un poste plus ancien, ils ne se chargent pas — et derrière
# « default=die », un module PAM qui ne se charge pas refuse TOUT le monde,
# root compris. D'où une compilation par FAMILLE de distributions, chacune sur
# la plus ancienne version prise en charge :
#
#     rocky   rockylinux:9   glibc 2.34   libcrypt.so.2 (libxcrypt)
#     debian  ubuntu:22.04   glibc 2.35   libcrypt.so.1
#
# La libcrypt suffirait à interdire un binaire unique : Rocky 9 n'a nativement
# que la .so.2, Debian et Ubuntu que la .so.1.
#
# # Le garde-fou
#
#     VAULTAIRE_GLIBC_MAX=2.34 ./auto_compil.sh sortie/
#
# Après compilation, la plus haute version de glibc qu'un des fichiers exige
# est lue dans sa table de symboles (objdump -T). Si elle dépasse
# VAULTAIRE_GLIBC_MAX, le script échoue : c'est le cas d'une CI dont l'image
# aurait changé sans qu'on le voie. Sans la variable, la version est seulement
# affichée.
#
# -lcurl a été retiré : aucun module n'appelle libcurl, et le lien en faisait
# une dépendance à installer sur chaque poste.
set -euo pipefail

if [ $# -ne 1 ]; then
    echo "usage : $0 <répertoire de sortie>" >&2
    exit 2
fi

ICI="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)"
mkdir -p "$1"
SORTIE="$(cd "$1" && pwd -P)"

cd "$ICI"
CFLAGS_MODULES="-fPIC -shared -O2 -Wall"
for module in pam_login_custom_module pam_logout_custom_module pam_ssh_auth_module; do
    # shellcheck disable=SC2086
    gcc $CFLAGS_MODULES -o "$SORTIE/$module.so" "$module.c" pam_common.c -lpam -lcrypt
done
# shellcheck disable=SC2086
gcc $CFLAGS_MODULES -o "$SORTIE/libnss_vaultaire.so.2" nss_vaultaire.c

FICHIERS=(
    "$SORTIE/pam_login_custom_module.so"
    "$SORTIE/pam_logout_custom_module.so"
    "$SORTIE/pam_ssh_auth_module.so"
    "$SORTIE/libnss_vaultaire.so.2"
)
chmod 755 "${FICHIERS[@]}"

# glibc_requise rend la plus haute version GLIBC_x.y que le fichier exige.
glibc_requise() {
    objdump -T "$1" 2>/dev/null \
        | grep -oE 'GLIBC_[0-9]+\.[0-9]+(\.[0-9]+)?' \
        | sed 's/^GLIBC_//' \
        | sort -t. -k1,1n -k2,2n -k3,3n \
        | tail -n1
}

# version_superieure A B : vrai si A > B (versions x.y[.z]).
version_superieure() {
    [ "$1" != "$2" ] && [ "$(printf '%s\n%s\n' "$1" "$2" | sort -t. -k1,1n -k2,2n -k3,3n | tail -n1)" = "$1" ]
}

if ! command -v objdump >/dev/null 2>&1; then
    if [ -n "${VAULTAIRE_GLIBC_MAX:-}" ]; then
        echo "❌ objdump introuvable (paquet binutils) : impossible de vérifier VAULTAIRE_GLIBC_MAX." >&2
        exit 1
    fi
    echo "⚠️  objdump introuvable : version de glibc requise non vérifiée."
    exit 0
fi

ECHEC=0
for f in "${FICHIERS[@]}"; do
    requise="$(glibc_requise "$f")"
    requise="${requise:-?}"
    # Aucun module ne doit plus dépendre de libcurl.
    if objdump -p "$f" | grep -qE 'NEEDED +libcurl'; then
        echo "❌ $(basename "$f") est lié à libcurl, qu'aucun module n'appelle." >&2
        ECHEC=1
    fi
    if [ -n "${VAULTAIRE_GLIBC_MAX:-}" ] && [ "$requise" != "?" ] \
        && version_superieure "$requise" "$VAULTAIRE_GLIBC_MAX"; then
        echo "❌ $(basename "$f") exige glibc $requise, au-delà de $VAULTAIRE_GLIBC_MAX :" >&2
        echo "   il ne se chargerait pas sur les postes les plus anciens de sa famille." >&2
        ECHEC=1
    else
        echo "   $(basename "$f") : glibc $requise au moins"
    fi
done
exit "$ECHEC"
