#!/bin/sh
# Phase 2 — compilation, installation et verification de la politique SELinux.
#
#   sudo ./install.sh              installe et verifie
#   sudo ./install.sh --remove     desinstalle et retire les etiquettes
#
# A executer APRES collect.sh, sur la machine cliente.
#
# ============================================================================
# CE QUE FAIT CE SCRIPT
# ============================================================================
#
# 1. compile vaultaire.te + vaultaire.fc contre la politique de reference de
#    CETTE distribution — c'est pourquoi la compilation se fait ici et pas au
#    moment du build : les interfaces de la politique de reference different
#    entre Rocky, Debian et leurs versions ;
# 2. installe le module et etiquette les fichiers ;
# 3. remet SELinux en enforcing ;
# 4. VERIFIE qu'aucun refus ne subsiste — sans quoi on ne saurait pas si la
#    politique fonctionne ou si l'on a simplement cesse de regarder.
set -eu

VERT=""; ROUGE=""; JAUNE=""; NEUTRE=""
if [ -t 1 ]; then
    VERT="$(printf '\033[32m')"; ROUGE="$(printf '\033[31m')"
    JAUNE="$(printf '\033[33m')"; NEUTRE="$(printf '\033[0m')"
fi
titre() { printf "\n%s=== %s ===%s\n" "$JAUNE" "$1" "$NEUTRE"; }
ok()    { printf "  %s[ OK ]%s %s\n" "$VERT" "$NEUTRE" "$1"; }
ko()    { printf "  %s[FAIL]%s %s\n" "$ROUGE" "$NEUTRE" "$1"; }
info()  { printf "         %s\n" "$1"; }

ICI="$(cd "$(dirname "$0")" && pwd)"
[ "$(id -u)" -eq 0 ] || { echo "Ce script doit tourner en root."; exit 1; }

# ---------------------------------------------------------------------------
if [ "${1:-}" = "--remove" ]; then
    titre "Desinstallation"
    semodule -r vaultaire 2>/dev/null && ok "module retire" || info "module deja absent"
    for chemin in '/etc/vaultaire(/.*)?' '/run/vaultaire(/.*)?' \
                  '/var/run/vaultaire(/.*)?' '/var/log/vaultaire(/.*)?'; do
        semanage fcontext -d "$chemin" 2>/dev/null || true
    done
    restorecon -RF /etc/vaultaire /var/log/vaultaire 2>/dev/null || true
    ok "etiquettes retirees"
    info "Les fichiers reprennent les types par defaut de la distribution."
    exit 0
fi

# ---------------------------------------------------------------------------
titre "1. Prerequis"
# ---------------------------------------------------------------------------
MANQUANTS=""
for outil in checkmodule semodule_package semodule semanage restorecon; do
    command -v "$outil" >/dev/null 2>&1 || MANQUANTS="$MANQUANTS $outil"
done
if [ -n "$MANQUANTS" ]; then
    ko "outils manquants :$MANQUANTS"
    info "Rocky / RHEL : dnf install policycoreutils-devel selinux-policy-devel"
    info "Debian       : apt install selinux-policy-dev policycoreutils-python-utils"
    exit 1
fi
ok "outils presents"

MAKEFILE=/usr/share/selinux/devel/Makefile
if [ ! -f "$MAKEFILE" ]; then
    ko "politique de reference absente : $MAKEFILE"
    info "Rocky / RHEL : dnf install selinux-policy-devel"
    exit 1
fi
ok "politique de reference disponible"

# ---------------------------------------------------------------------------
titre "2. Compilation"
# ---------------------------------------------------------------------------
#
# Dans un repertoire temporaire : le Makefile de la politique de reference
# genere quantite de fichiers intermediaires qu'on ne veut pas voir arriver
# dans le depot.
BUILD="$(mktemp -d)"
trap 'rm -rf "$BUILD"' EXIT
cp "$ICI/vaultaire.te" "$ICI/vaultaire.fc" "$BUILD/"

if make -f "$MAKEFILE" -C "$BUILD" vaultaire.pp >"$BUILD/build.log" 2>&1; then
    ok "vaultaire.pp compile"
else
    ko "compilation echouee"
    sed 's/^/         /' "$BUILD/build.log" | tail -25
    info ""
    info "Les erreurs les plus frequentes :"
    info "  « unknown type X »       le type n'existe pas sur cette distribution"
    info "  « unknown attribute »    nsswitch_domain absent : politique trop ancienne"
    info "  « unknown class perm »   la permission n'existe pas dans cette version"
    info ""
    info "Dans chaque cas, adaptez vaultaire.te en vous appuyant sur"
    info "  sesearch --allow -s sshd_t -c sock_file"
    exit 1
fi

# ---------------------------------------------------------------------------
titre "3. Installation du module"
# ---------------------------------------------------------------------------
if semodule -i "$BUILD/vaultaire.pp"; then
    ok "module vaultaire installe"
else
    ko "installation echouee"
    exit 1
fi

# ---------------------------------------------------------------------------
titre "4. Etiquetage des fichiers"
# ---------------------------------------------------------------------------
#
# Le module declare les types ; semanage/restorecon les POSENT sur les fichiers
# existants. Sans cette etape, la politique est en place mais aucun fichier ne
# porte les types qu'elle protege — et rien ne change.
for repertoire in /etc/vaultaire /var/log/vaultaire /run/vaultaire; do
    [ -d "$repertoire" ] || continue
    if restorecon -RF "$repertoire" 2>/dev/null; then
        ok "$repertoire etiquete"
    else
        ko "$repertoire : etiquetage echoue"
    fi
done

# Reparation des repertoires personnels deja crees.
#
# L'agent et les modules PAM creaient /home/<user>, .ssh et authorized_keys sans
# poser de contexte : la chaine heritait de /home, donc home_root_t, au lieu de
# user_home_dir_t puis ssh_home_t. sshd refusait alors de lire les cles.
#
# Le code corrige applique desormais restorecon a la creation, mais les comptes
# deja provisionnes gardent leur mauvais etiquetage : on les repare ici.
NB_HOMES=0
for home in /home/*@*; do
    [ -d "$home" ] || continue
    restorecon -RF "$home" 2>/dev/null && NB_HOMES=$((NB_HOMES+1))
done
if [ "$NB_HOMES" -gt 0 ]; then
    ok "$NB_HOMES repertoire(s) personnel(s) re-etiquete(s)"
    info "Ils portaient home_root_t hérité de /home au lieu de ssh_home_t,"
    info "ce qui empechait sshd de lire authorized_keys."
fi

# /run est un tmpfs : les etiquettes n'y survivent pas au redemarrage. Elles
# sont reappliquees a la creation des fichiers d'apres vaultaire.fc — donc
# automatiquement, tant que le module reste installe.
info "/run est volatil : ses etiquettes se reappliquent seules au demarrage"

# ---------------------------------------------------------------------------
titre "5. Retour en enforcing et verification"
# ---------------------------------------------------------------------------
setenforce 1 2>/dev/null && ok "SELinux en enforcing"

# Redemarrage de l'agent : il doit recreer ses sockets, qui prendront cette
# fois les bonnes etiquettes.
if systemctl is-active vaultaire_client >/dev/null 2>&1; then
    systemctl restart vaultaire_client && ok "agent redemarre"
    sleep 2
fi

DEBUT="$(date '+%m/%d/%Y %H:%M:%S')"
sleep 1

# --- Le test qui compte ----------------------------------------------------
#
# runcon fait tourner getent dans le contexte de sshd. C'est la seule facon de
# reproduire ce que vit sshd sans ouvrir une vraie connexion — et c'est
# exactement le test qui manquait au diagnostic precedent, lequel s'executait
# depuis un shell non confine et validait donc un chemin que sshd n'emprunte
# pas.
UTILISATEUR="${1:-verif-$$@$(hostname -d 2>/dev/null || echo vaultaire.fr)}"

if command -v runcon >/dev/null 2>&1; then
    if runcon -t sshd_t getent passwd "$UTILISATEUR" >/dev/null 2>&1; then
        ok "resolution dans le contexte sshd_t : REPOND"
    else
        ko "resolution dans le contexte sshd_t : ECHOUE ENCORE"
        info "La politique ne couvre pas tout. Relancez collect.sh, puis"
        info "comparez les nouveaux refus avec vaultaire.te."
    fi
else
    info "runcon absent : verification dans le contexte sshd_t impossible"
fi

# --- Refus residuels -------------------------------------------------------
sleep 1
RESIDUS=0
if command -v ausearch >/dev/null 2>&1; then
    RESIDUS="$(ausearch -m avc -ts $DEBUT 2>/dev/null | grep -ci 'vaultaire' || echo 0)"
fi
if [ "$RESIDUS" -eq 0 ]; then
    ok "aucun refus residuel concernant Vaultaire"
else
    ko "$RESIDUS refus subsistent"
    ausearch -m avc -ts $DEBUT 2>/dev/null | grep -i vaultaire | sed 's/^/         /' | head -10
fi

printf "\n"
titre "Etat final"
info "SELinux        : $(getenforce)"
info "Module installe: $(semodule -l 2>/dev/null | grep -c '^vaultaire') "
info ""
info "Testez maintenant une VRAIE connexion SSH depuis un autre poste."
info "En cas de probleme : sudo ./install.sh --remove, puis setenforce 0."
