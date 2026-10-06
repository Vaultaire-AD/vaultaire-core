#!/usr/bin/env bash
# ====================================================================
# Mise à jour pre-prod — depuis une RELEASE GitHub
# ====================================================================
#
# Les binaires ne sont plus compilés ni versionnés : la CI les publie à chaque
# fusion preprod → main (.github/workflows/release.yaml). Ce script, lancé SUR
# L'HÔTE pre-prod :
#
#   1. choisit une release — la dernière, ou celle de --version ;
#   2. place le dépôt sur le tag de cette release (git checkout --detach), pour
#      que templates, compose et configuration correspondent aux binaires ;
#   3. télécharge les archives, vérifie leurs SHA-256, les installe dans cmd/ ;
#   4. redémarre le conteneur — et ne reconstruit l'image que si le Dockerfile,
#      l'entrypoint ou le compose ont changé entre les deux versions.
#
# Usage, depuis la racine du dépôt :
#     ./deployments/pre-prod/docker-update.sh                    # dernière release
#     ./deployments/pre-prod/docker-update.sh --version 2.1.3    # version précise (ou v2.1.3)
#     ./deployments/pre-prod/docker-update.sh --list             # releases disponibles
#     ./deployments/pre-prod/docker-update.sh --build            # force la reconstruction
#     ./deployments/pre-prod/docker-update.sh --force            # réinstalle même si déjà à jour
#     ./deployments/pre-prod/docker-update.sh --no-download      # redémarrage seul
#
# Variables d'environnement :
#     VAULTAIRE_REPO   dépôt GitHub          (défaut : Vaultaire-AD/vaultaire-core)
#     GITHUB_TOKEN     jeton, facultatif      (dépôt privé, ou limite de l'API atteinte)
#
# Revenir en arrière = --version <ancienne>. Seules les 5 dernières releases
# sont conservées sur GitHub.

set -euo pipefail

# --- Le script se remplace lui-même ---------------------------------
# L'étape 2 réécrit ce fichier (checkout du tag). Bash lit un script au fil de
# l'exécution : le modifier pendant qu'il tourne fait exécuter un mélange des
# deux versions. On s'exécute donc depuis une copie.
if [ -z "${VAULTAIRE_UPDATE_COPY:-}" ]; then
    COPIE="$(mktemp -t vaultaire-update.XXXXXX)"
    cp "$0" "$COPIE"
    chmod 700 "$COPIE"
    REPO_ROOT="$(cd "$(dirname "$0")/../.." && pwd)" \
    VAULTAIRE_UPDATE_COPY="$COPIE" exec bash "$COPIE" "$@"
fi
trap 'rm -f "$VAULTAIRE_UPDATE_COPY"' EXIT
cd "$REPO_ROOT"

REPO="${VAULTAIRE_REPO:-Vaultaire-AD/vaultaire-core}"
# Les deux URL se surchargent pour un miroir interne ou pour les tests.
API="${VAULTAIRE_API_URL:-https://api.github.com/repos/$REPO}"
DL="${VAULTAIRE_DL_URL:-https://github.com/$REPO/releases/download}"

COMPOSE_FILE="deployments/pre-prod/docker-compose.yml"
PROXY_COMPOSE_FILE="deployments/pre-prod/vlt-proxy/docker-compose.yml"
DOCKERFILE="deployments/pre-prod/Dockerfile"
ENTRYPOINT="deployments/pre-prod/entrypoint.sh"
MARQUEUR="cmd/.release"

# Archive publiée -> répertoire de cmd/ monté par les compose.
COMPOSANTS="vaultaire_server vaultaire_client vaultaire_ctl vaultaire_proxy"

VERSION=""
FORCE_BUILD=0
FORCE=0
DO_DOWNLOAD=1
DO_LIST=0
while [ $# -gt 0 ]; do
    case "$1" in
        --version)      VERSION="${2:-}"; shift
                        [ -n "$VERSION" ] || { echo "--version attend une valeur (ex. 2.1.3)" >&2; exit 1; } ;;
        --version=*)    VERSION="${1#*=}" ;;
        --build)        FORCE_BUILD=1 ;;
        --force)        FORCE=1 ;;
        --no-download|--no-pull) DO_DOWNLOAD=0 ;;
        --list)         DO_LIST=1 ;;
        -h|--help)      sed -n '2,31p' "$VAULTAIRE_UPDATE_COPY" | sed 's/^# \{0,1\}//'; exit 0 ;;
        *) echo "Option inconnue : $1 (voir --help)" >&2; exit 1 ;;
    esac
    shift
done

for outil in curl tar sha256sum git; do
    command -v "$outil" >/dev/null 2>&1 || { echo "ERREUR : $outil introuvable sur cet hôte." >&2; exit 1; }
done

CURL=(curl -fsSL --retry 3 --connect-timeout 10)
[ -n "${GITHUB_TOKEN:-}" ] && CURL+=(-H "Authorization: Bearer $GITHUB_TOKEN")

# Lecture de tag_name sans jq, absent de la plupart des hôtes.
# Découpage sur les virgules : la réponse peut tenir sur une seule ligne.
tags_de() { tr ',' '\n' | sed -nE 's/.*"tag_name"[[:space:]]*:[[:space:]]*"([^"]+)".*/\1/p'; }

# --- --list ----------------------------------------------------------
if [ "$DO_LIST" -eq 1 ]; then
    echo "Releases disponibles sur $REPO :"
    "${CURL[@]}" "$API/releases?per_page=20" | tags_de | sed 's/^/  /'
    [ -f "$MARQUEUR" ] && echo "Installée ici : $(cat "$MARQUEUR")"
    exit 0
fi

# docker ou podman-compose selon ce qui est disponible sur l'hôte.
if command -v docker >/dev/null 2>&1; then
    COMPOSE_BIN="docker compose"
elif command -v podman-compose >/dev/null 2>&1; then
    COMPOSE_BIN="podman-compose"
else
    echo "Ni docker ni podman-compose trouvé sur cette machine." >&2
    exit 1
fi
COMPOSE="$COMPOSE_BIN -f $COMPOSE_FILE"

BEFORE="$(git rev-parse HEAD)"
NEED_BUILD=$FORCE_BUILD

if [ "$DO_DOWNLOAD" -eq 1 ]; then
    # --- 1. Quelle release ? -----------------------------------------
    if [ -n "$VERSION" ]; then
        TAG="v${VERSION#v}"
        if ! [[ "$TAG" =~ ^v[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
            echo "ERREUR : version invalide « $VERSION » — attendu X.Y.Z" >&2
            exit 1
        fi
    else
        TAG="$("${CURL[@]}" "$API/releases/latest" | tags_de | head -1)"
        [ -n "$TAG" ] || { echo "ERREUR : aucune release publiée sur $REPO." >&2; exit 1; }
    fi

    if [ "$FORCE" -eq 0 ] && [ -f "$MARQUEUR" ] && [ "$(cat "$MARQUEUR")" = "$TAG" ] \
       && [ "$(git rev-parse HEAD)" = "$(git rev-parse -q --verify "$TAG^{commit}" 2>/dev/null || true)" ]; then
        echo "==> Déjà en $TAG — rien à faire (--force pour réinstaller, --build pour reconstruire)."
        [ "$FORCE_BUILD" -eq 1 ] || exit 0
    else
        echo "==> Release cible : $TAG"

        # --- 2. Le code suit la release ------------------------------
        # Des modifications locales seraient écrasées sans bruit, ou
        # bloqueraient le checkout au milieu : on refuse avant de commencer.
        #
        # cmd/ et les .so compilés sont exclus du contrôle : sur un hôte encore
        # alimenté par l'ancien deploy.sh (rsync), ces fichiers étaient suivis
        # par git ET réécrits — ils apparaissent donc modifiés. Ils sont
        # remplacés par la release juste après, d'où le --force du checkout.
        HORS_BINAIRES=(-- . ':!cmd' ':!src/vaultaire_client/pam_module/*.so' ':!src/vaultaire_client/pam_module/*.so.*')
        if [ -n "$(git status --porcelain --untracked-files=no "${HORS_BINAIRES[@]}")" ]; then
            echo "ERREUR : le dépôt de l'hôte a des modifications locales :" >&2
            git status --short --untracked-files=no "${HORS_BINAIRES[@]}" >&2
            echo "         Committez-les ailleurs ou « git stash », puis relancez." >&2
            exit 1
        fi

        # --prune-tags : les tags des releases supprimées disparaissent aussi.
        git fetch --quiet --force --tags --prune --prune-tags origin
        if ! git rev-parse -q --verify "refs/tags/$TAG" >/dev/null; then
            echo "ERREUR : le tag $TAG n'existe pas. Releases disponibles : --list" >&2
            exit 1
        fi

        # --- 3. Téléchargement et vérification -----------------------
        # AVANT le checkout : une release incomplète ne doit pas laisser l'hôte
        # sur un code dont il n'a pas les binaires.
        TMP="$(mktemp -d -t vaultaire-release.XXXXXX)"
        trap 'rm -rf "$TMP"; rm -f "$VAULTAIRE_UPDATE_COPY"' EXIT

        echo "==> Téléchargement depuis $DL/$TAG"
        "${CURL[@]}" -o "$TMP/SHA256SUMS" "$DL/$TAG/SHA256SUMS" \
            || { echo "ERREUR : release $TAG introuvable ou incomplète." >&2; exit 1; }
        # La release peut contenir plus d'archives que la pré-prod n'en installe
        # (vaultaire_nexus, par exemple). On ne vérifie donc que les lignes des
        # archives téléchargées — mais CHACUNE doit y figurer : une archive
        # absente de SHA256SUMS n'est pas vérifiée, donc pas installée.
        : > "$TMP/SHA256SUMS.pre-prod"
        for c in $COMPOSANTS; do
            f="${c}-${TAG}-linux-amd64.tar.gz"
            "${CURL[@]}" -o "$TMP/$f" "$DL/$TAG/$f"
            grep -E "^[0-9a-f]{64}[[:space:]]+\*?${f}\$" "$TMP/SHA256SUMS" >> "$TMP/SHA256SUMS.pre-prod" \
                || { echo "ERREUR : $f absent de SHA256SUMS — rien n'a été installé." >&2; exit 1; }
        done
        (cd "$TMP" && sha256sum --quiet -c SHA256SUMS.pre-prod) \
            || { echo "ERREUR : somme de contrôle invalide — rien n'a été installé." >&2; exit 1; }

        echo "==> git checkout $TAG"
        git -c advice.detachedHead=false checkout --quiet --force --detach "$TAG"

        # --- 4. Installation dans cmd/ -------------------------------
        # Les fichiers sont remplacés DANS le répertoire existant, pas le
        # répertoire lui-même : les compose le montent en volume.
        for c in $COMPOSANTS; do
            tar -C "$TMP" -xzf "$TMP/${c}-${TAG}-linux-amd64.tar.gz"
            mkdir -p "cmd/$c"
            find "cmd/$c" -mindepth 1 -maxdepth 1 -exec rm -rf {} +
            cp -a "$TMP/$c/." "cmd/$c/"
            # Le proxy tourne en utilisateur non privilégié : 0755 obligatoire.
            find "cmd/$c" -type f ! -name '*.yaml' ! -name VERSION -exec chmod 755 {} +
        done
        echo "$TAG" > "$MARQUEUR"
        echo "==> Binaires $TAG installés dans cmd/"

        if [ "$NEED_BUILD" -eq 0 ] && git diff --name-only "$BEFORE" HEAD -- \
            "$DOCKERFILE" "$ENTRYPOINT" "$COMPOSE_FILE" | grep -q .; then
            echo "==> Dockerfile, entrypoint ou compose modifié : reconstruction nécessaire"
            NEED_BUILD=1
        fi
    fi
fi

# --- Contrôle des binaires ------------------------------------------
SERVER_BIN="cmd/vaultaire_server/vaultaire_serveur"
if [ ! -x "$SERVER_BIN" ]; then
    echo "ERREUR : $SERVER_BIN absent ou non exécutable." >&2
    echo "         Relancez sans --no-download pour installer une release." >&2
    exit 1
fi
echo "==> Version installée : $(cat "$MARQUEUR" 2>/dev/null || echo inconnue)"

# Image absente : premier déploiement sur cette machine.
if ! $COMPOSE images 2>/dev/null | grep -q "vaultaire-preprod"; then
    echo "==> Image absente, construction initiale"
    NEED_BUILD=1
fi

# --- Application -----------------------------------------------------
if [ "$NEED_BUILD" -eq 1 ]; then
    # Sans --no-cache : les couches système sont réutilisées.
    echo "==> Reconstruction de l'image"
    $COMPOSE build
    $COMPOSE up -d
else
    echo "==> Redémarrage du conteneur (aucune reconstruction)"
    $COMPOSE restart vaultaire-ad
fi

# Le proxy partage cmd/ : s'il tourne sur cet hôte, il doit repartir sur le
# nouveau binaire lui aussi.
if [ -f "$PROXY_COMPOSE_FILE" ] && \
   [ -n "$($COMPOSE_BIN -f "$PROXY_COMPOSE_FILE" ps -q vlt-proxy 2>/dev/null || true)" ]; then
    echo "==> Redémarrage de vlt-proxy"
    $COMPOSE_BIN -f "$PROXY_COMPOSE_FILE" restart vlt-proxy
fi

echo "==> État :"
$COMPOSE ps

echo
echo "Terminé. Logs : $COMPOSE logs -f vaultaire-ad"
