#!/bin/bash
# set -euo pipefail

# Variables

ROOT_DIR="/mnt/c/Users/loren/Documents/git/vaultaire-core"
#ROOT_DIR="/workspaces/vaultaire-core"
BUILD_DIR="$ROOT_DIR/cmd"
SERVER_BIN="$BUILD_DIR/vaultaire_server/vaultaire_serveur"
CLI_BIN="$BUILD_DIR/vaultaire_server/vaultaire_cli"
CLIENT_BIN="$BUILD_DIR/vaultaire_client/vaultaire_client"
CTL_BIN="$BUILD_DIR/vaultaire_ctl/vaultaire_ctl"
PROXY_BIN="$BUILD_DIR/vaultaire_proxy/vaultaire_proxy"

# Créer les dossiers de sortie si nécessaire.
#
# `go build -o chemin/binaire` n'invente pas le répertoire parent : il échoue.
# Sur un dépôt fraîchement cloné, où cmd/ n'existe pas encore, chaque cible
# échouerait donc sur la même erreur.
mkdir -p "$BUILD_DIR" \
         "$BUILD_DIR/vaultaire_server" \
         "$BUILD_DIR/vaultaire_client" \
         "$BUILD_DIR/vaultaire_ctl" \
         "$BUILD_DIR/vaultaire_proxy"

cd "$ROOT_DIR"
#git pull

# -------------------------
# Contrôle des directives go des go.mod
# -------------------------
# Le Go local n'a PAS besoin d'être aussi récent que les modules : avec
# GOTOOLCHAIN=auto (le défaut), un go1.22 télécharge tout seul le toolchain
# réclamé par go.mod. C'est ce qui fait tourner ce script aujourd'hui.
#
# En revanche le nom du toolchain doit EXISTER, et il s'écrit toujours avec un
# numéro de correctif : go1.25.0, go1.25.1… Une directive « go 1.23 » sans
# correctif fait construire à Go le nom « go1.23 », qui n'est publié nulle part :
#
#     go: downloading go1.23 (linux/amd64)
#     go: download go1.23 for linux/amd64: toolchain not available
#
# Le message parle de téléchargement et de version : rien n'y suggère qu'il
# manque un « .0 ». D'où ce contrôle, qui coûte une seconde et évite une heure.
#
# Deux détails rendent ce contrôle moins évident qu'il n'y paraît :
#
#   - les go.mod du dépôt sont en CRLF (édités sous Windows). Un motif ancré sur
#     « $ » ne matche jamais, et le contrôle passerait tout sans rien dire —
#     pire que pas de contrôle. D'où le tr -d '\r'.
#   - la bascule de toolchain n'existe que depuis Go 1.21. Une directive
#     « go 1.19 » est donc parfaitement saine, et la signaler ferait modifier un
#     module qui marche.
echo "🐹 Go $(go env GOVERSION 2>/dev/null || echo introuvable) ($(command -v go))"
GOMOD_FAUTIFS=""
for gomod in "$ROOT_DIR"/src/*/go.mod; do
    [ -f "$gomod" ] || continue
    directive="$(grep -m1 '^go ' "$gomod" | tr -d '\r' | awk '{print $2}')"
    case "$directive" in
        *.*.*) continue ;;                    # a un correctif : rien à dire
        "")    continue ;;
    esac
    majeure="${directive%%.*}"; mineure="${directive#*.}"
    if [ "$majeure" -eq 1 ] && [ "$mineure" -ge 21 ] 2>/dev/null; then
        GOMOD_FAUTIFS="$GOMOD_FAUTIFS   $gomod  (go $directive)
"
    fi
done
if [ -n "$GOMOD_FAUTIFS" ]; then
    echo "❌ Directive go sans numéro de correctif — écrire 1.25.0, pas 1.25 :"
    printf '%s' "$GOMOD_FAUTIFS"
    echo "   Go en déduirait le toolchain « go$directive », qui n'est publié nulle part."
    exit 1
fi

# build_go compile une cible et ARRÊTE le script si elle échoue.
#
# Sans cela, un `go build` en échec laissait le script continuer et afficher
# « ✅ Build et déploiement terminés. » alors qu'aucun binaire n'avait été
# produit — le pire des retours, puisqu'il faut alors découvrir la panne au
# déploiement.
#
# Le quatrième argument, facultatif, porte des variables d'environnement à
# passer au compilateur (voir le proxy et CGO_ENABLED=0).
build_go() {
    local libelle="$1" repertoire="$2" sortie="$3" env_build="${4:-}"
    echo "🛠 Build $libelle..."
    mkdir -p "$(dirname "$sortie")"
    if ! (cd "$repertoire" && env $env_build go build -buildvcs=false -o "$sortie"); then
        echo "❌ Build $libelle échoué — arrêt."
        exit 1
    fi
    # 0755 et non le mode par défaut.
    #
    # Sous WSL sur un montage /mnt/c, l'umask hérité produit des binaires en
    # 0700 appartenant au compte qui compile. Montés dans un conteneur qui
    # tourne en utilisateur NON privilégié — c'est le cas du proxy —, ils ne
    # sont ni lisibles ni exécutables, et Docker répond :
    #
    #     exec: "/opt/vaultaire/bin/vaultaire_proxy": permission denied
    #
    # Un message du runtime, qui ne dit ni pourquoi ni sur quelle machine agir.
    chmod 755 "$sortie"
}

# -------------------------
# Build serveur
# -------------------------
build_go "du serveur" "$ROOT_DIR/src/vaultaire_serveur/main" "$SERVER_BIN"

# Copier web_packet
cp -r "$ROOT_DIR/web_packet" "$BUILD_DIR/"

build_go "du CLI"    "$ROOT_DIR/src/vaultaire_cli"    "$CLI_BIN"
build_go "du client" "$ROOT_DIR/src/vaultaire_client" "$CLIENT_BIN"
build_go "du ctl"    "$ROOT_DIR/src/vaultaire_ctl"    "$CTL_BIN"

# -------------------------
# Build proxy
# -------------------------


# CGO_ENABLED=0 : binaire statique.
#
# Le proxy n'utilise ni cgo ni résolution NSS, mais `go build` active cgo par
# défaut dès qu'un gcc traîne, et lie alors le binaire à la glibc de la machine
# de compilation. Il refuse ensuite de démarrer dans un conteneur dont la glibc
# est plus ancienne — avec un « no such file or directory » qui désigne le
# binaire et non la bibliothèque manquante, une des erreurs les plus trompeuses
# de Linux.
#
# Statique, le même binaire tourne partout : debian, alpine, ou à même l'hôte.
build_go "du proxy" "$ROOT_DIR/src/vaultaire_proxy" "$PROXY_BIN" "CGO_ENABLED=0"

# La configuration d'exemple accompagne le binaire : un proxy déployé sans
# fichier de configuration ne démarre pas, et le modèle n'est utile que là où on
# récupère le binaire.
cp "$ROOT_DIR/src/vaultaire_proxy/config.example.yaml" "$BUILD_DIR/vaultaire_proxy/"

# -------------------------
# Build modules PAM
# -------------------------
echo "🛠 Build modules PAM..."
cd "$ROOT_DIR/src/vaultaire_client/pam_module"

gcc -fPIC -shared -o pam_login_custom_module.so pam_login_custom_module.c pam_common.c -lcurl -lpam -lcrypt
gcc -fPIC -shared -o pam_logout_custom_module.so pam_logout_custom_module.c pam_common.c -lcurl -lpam -lcrypt
gcc -fPIC -shared -o pam_ssh_auth_module.so pam_ssh_auth_module.c pam_common.c -lcurl -lpam -lcrypt
gcc -fPIC -shared -o libnss_vaultaire.so.2 nss_vaultaire.c

cp ./pam*.so "$BUILD_DIR/vaultaire_client/"
cp ./libnss_vaultaire.so.2 "$BUILD_DIR/vaultaire_client/"
# -------------------------
# Copier les binaires dans release Vaultaire_AD-ppd
# -------------------------
RELEASE_DIR="$ROOT_DIR/Vaultaire_AD-ppd"


echo "✅ Build et déploiement terminés."

