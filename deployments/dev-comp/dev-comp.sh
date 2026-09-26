#!/usr/bin/env bash
# ====================================================================
# dev-comp.sh — compiler le dépôt local, puis démarrer la pile de test
# ====================================================================
#
# Usage (depuis n'importe où dans le dépôt) :
#
#   ./deployments/dev-comp/dev-comp.sh                 compile, puis (re)démarre la pile
#   ./deployments/dev-comp/dev-comp.sh --version 2.2.3 impose la version injectée
#   ./deployments/dev-comp/dev-comp.sh --local         compile sur l'hôte (auto-compil.sh), sans conteneur
#   ./deployments/dev-comp/dev-comp.sh --no-build      redémarre sans recompiler
#   ./deployments/dev-comp/dev-comp.sh --proxy         démarre aussi un proxy (relais Ducky)
#   ./deployments/dev-comp/dev-comp.sh --nexus         démarre aussi un Nexus (dépôt de paquets)
#   ./deployments/dev-comp/dev-comp.sh --down          arrête la pile (garde la base)
#   ./deployments/dev-comp/dev-comp.sh --reset         arrête et EFFACE la base, l'identité du proxy et les données Nexus
#   ./deployments/dev-comp/dev-comp.sh --logs          suit les journaux du core
#   ./deployments/dev-comp/dev-comp.sh --status        état des conteneurs et version compilée
#
# « Monter une version » : sans --version, la version injectée est la
# PROCHAINE release de la série en cours — VERSION (2.2) et le plus grand tag
# v2.2.N connu localement donnent 2.2.(N+1), ou 2.2.0 sans tag. Le commit et
# « -dirty » s'y ajoutent : « 2.2.1+g1a2b3c4-dirty (2026-09-22) ». Un binaire de
# dev-comp se reconnaît donc au premier coup d'œil dans `vlt cluster list` et
# `vlt version`, sans se faire passer pour une release.
#
# Les IMAGES du core, du proxy et du Nexus sont (re)construites à chaque
# lancement, que leurs conteneurs démarrent ou non. Une image qu'on ne construit
# qu'au moment d'en avoir besoin casse au pire moment — et ces trois-là sont
# justement celles qu'on démarre en urgence pour reproduire quelque chose.

set -euo pipefail

ICI="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)"
RACINE="$(cd "$ICI/../.." && pwd -P)"
BUILD="$ICI/build"
cd "$ICI"

info() { echo -e "\033[1;34m[dev-comp]\033[0m $*"; }
erreur() { echo -e "\033[1;31m[dev-comp]\033[0m $*" >&2; exit 1; }

command -v docker >/dev/null || erreur "docker introuvable"
docker compose version >/dev/null 2>&1 || erreur "« docker compose » (v2) introuvable"

COMPILER=1
LOCAL=0
PROXY=0
NEXUS=0
VERSION_IMPOSEE=""
ACTION="up"

while [ $# -gt 0 ]; do
    case "$1" in
        --version)  VERSION_IMPOSEE="${2:-}"; shift ;;
        --local)    LOCAL=1 ;;
        --no-build) COMPILER=0 ;;
        --proxy)    PROXY=1 ;;
        --nexus)    NEXUS=1 ;;
        --down)     ACTION="down" ;;
        --reset)    ACTION="reset" ;;
        --logs)     ACTION="logs" ;;
        --status)   ACTION="status" ;;
        -h|--help)  sed -n '2,29p' "$0"; exit 0 ;;
        *) erreur "option inconnue : $1 (voir --help)" ;;
    esac
    shift
done

# Profils des CONTENEURS à démarrer. Les IMAGES, elles, sont toutes
# construites : voir TOUS plus bas.
PROFILS=()
[ "$PROXY" = 1 ] && PROFILS+=(--profile proxy)
[ "$NEXUS" = 1 ] && PROFILS+=(--profile nexus)

# TOUS : tous les profils, pour les opérations qui doivent voir la pile entière
# (arrêt, état, construction des images) quels que soient les conteneurs
# demandés aujourd'hui. Sans cela, « --down » laisserait tourner un proxy
# démarré la veille.
TOUS=(--profile proxy --profile nexus)

case "$ACTION" in
    down)   docker compose "${TOUS[@]}" down; exit 0 ;;
    reset)  docker compose "${TOUS[@]}" down -v; rm -rf "$BUILD"; info "pile, base et binaires effacés"; exit 0 ;;
    logs)   docker compose logs -f vaultaire-ad; exit 0 ;;
    status)
        docker compose "${TOUS[@]}" ps
        if [ -x "$BUILD/vaultaire_server/vaultaire_serveur" ]; then
            info "binaires compilés le $(date -r "$BUILD/vaultaire_server/vaultaire_serveur" '+%d/%m/%Y %H:%M')"
        else
            info "aucun binaire compilé ($BUILD)"
        fi
        exit 0 ;;
esac

# --- version à injecter ---------------------------------------------
prochaine_version() {
    local serie dernier
    serie="$(tr -d '[:space:]' < "$RACINE/VERSION")"
    [[ "$serie" =~ ^[0-9]+\.[0-9]+$ ]] || erreur "VERSION illisible : « $serie » (attendu X.Y)"
    dernier="$(git -C "$RACINE" tag --list "v${serie}.*" 2>/dev/null \
        | sed -nE "s/^v${serie//./\\.}\.([0-9]+)$/\1/p" | sort -n | tail -1)"
    if [ -z "$dernier" ]; then
        echo "${serie}.0"
    else
        echo "${serie}.$((dernier + 1))"
    fi
}

if [ "$COMPILER" = 1 ]; then
    VERSION_DEV="${VERSION_IMPOSEE:-$(prochaine_version)}"
    [[ "$VERSION_DEV" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]] || erreur "--version doit être de la forme X.Y.Z (reçu : $VERSION_DEV)"
    info "compilation de la version $VERSION_DEV depuis $RACINE"
    mkdir -p "$BUILD"

    if [ "$LOCAL" = 1 ]; then
        # Sur l'hôte : plus rapide, mais les binaires suivent la glibc de
        # l'hôte. À réserver à un hôte Rocky 9 / RHEL 9.
        VAULTAIRE_ROOT="$RACINE" VAULTAIRE_BUILD_DIR="$BUILD" VAULTAIRE_VERSION="$VERSION_DEV" \
            "$RACINE/auto-compil.sh"
    else
        # Dans le conteneur Rocky 9 : même recette que la CI de release.
        HOST_UID="$(id -u)" HOST_GID="$(id -g)" VAULTAIRE_VERSION="$VERSION_DEV" \
            docker compose --profile build run --rm --build builder
    fi
fi

# --- contrôle de ce qui va être monté ------------------------------------
for f in vaultaire_server/vaultaire_serveur vaultaire_server/vaultaire_cli vaultaire_client/vaultaire_client vaultaire_ctl/vaultaire_ctl; do
    [ -x "$BUILD/$f" ] || erreur "$BUILD/$f absent : lancez sans --no-build"
done
# Le binaire du Nexus n'est exigé que si son conteneur démarre : son IMAGE, elle,
# se construit sans lui (elle ne contient aucun binaire).
if [ "$NEXUS" = 1 ]; then
    [ -x "$BUILD/vaultaire_nexus/vaultaire_nexus" ] || erreur "binaire du Nexus absent : lancez sans --no-build"
fi
if [ "$PROXY" = 1 ]; then
    [ -x "$BUILD/vaultaire_proxy/vaultaire_proxy" ] || erreur "binaire du proxy absent : lancez sans --no-build"
    if ! docker volume inspect dev-comp_devcomp_proxy_keys >/dev/null 2>&1 && [ -z "${DEVCOMP_PROXY_ENROLL_KEY:-$(grep -s '^DEVCOMP_PROXY_ENROLL_KEY=' .env | cut -d= -f2-)}" ]; then
        erreur "premier démarrage du proxy : il lui faut une clé d'enrôlement.
  Démarrez d'abord le core (sans --proxy), puis :
    docker exec vlt-dev-ad /opt/vaultaire/bin/vaultaire_cli enroll create --type vaultaire_proxy
  et mettez la clé dans deployments/dev-comp/.env : DEVCOMP_PROXY_ENROLL_KEY=VLT-ENR-…"
    fi
fi

# --- images ----------------------------------------------------------------
# Les TROIS images sont construites, même si seul le core démarre : une image
# qui n'existe pas se découvre au moment où l'on veut s'en servir. Elles ne
# contiennent aucun binaire (tout est monté), donc c'est rapide et le cache
# Docker fait le reste.
info "construction des images (core, proxy, nexus)"
docker compose "${TOUS[@]}" build vaultaire-ad vlt-proxy vaultaire-nexus

# --- démarrage -------------------------------------------------------------
# Les binaires étant montés, un redémarrage suffit à prendre en compte une
# recompilation.
docker compose "${PROFILS[@]}" up -d
A_REDEMARRER=(vaultaire-ad)
[ "$PROXY" = 1 ] && A_REDEMARRER+=(vlt-proxy)
[ "$NEXUS" = 1 ] && A_REDEMARRER+=(vaultaire-nexus)
docker compose "${PROFILS[@]}" restart "${A_REDEMARRER[@]}" >/dev/null

info "pile démarrée :"
# Le mot de passe d'amorçage n'est plus « admin123 » : le core refuse de
# démarrer sur les valeurs du dépôt (TO-DO 99). Il vient de l'environnement, et
# il est PROVISOIRE — le portail demandera de le changer à la première
# connexion, ce qui est le comportement à éprouver ici aussi.
info "  portail    https://localhost:${DEVCOMP_PORT_WEB:-4443}/login   (admin / ${VAULTAIRE_ADMIN_PASSWORD:-correcte agrafe batterie})"
info "             ce mot de passe est PROVISOIRE : le portail en demandera un autre."
info "  CLI        docker exec -it vlt-dev-ad /opt/vaultaire/bin/vaultaire_cli"
info "  agent      $BUILD/vaultaire_client/  (servi aux machines par « create -c … -join »)"
[ "$NEXUS" = 1 ] && info "  nexus      https://localhost:${DEVCOMP_PORT_NEXUS:-8843}/   (admin ; mot de passe initial : docker exec vlt-dev-nexus cat /var/lib/vaultaire_nexus/admin.initial)"
info "  journaux   ./deployments/dev-comp/dev-comp.sh --logs"
