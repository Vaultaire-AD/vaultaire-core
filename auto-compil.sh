#!/bin/bash
set -euo pipefail

# Variables
ROOT_DIR="/srv/nfs/vaultaire-core"
BUILD_DIR="$ROOT_DIR/cmd"
SERVER_BIN="$BUILD_DIR/vaultaire_server/vaultaire_serveur"
CLI_BIN="$BUILD_DIR/vaultaire_server/vaultaire_cli"
CLIENT_BIN="$BUILD_DIR/vaultaire_client/vaultaire_client"
CTL_BIN="$BUILD_DIR/vaultaire_ctl/vaultaire_ctl"

# Créer le dossier build si nécessaire
mkdir -p "$BUILD_DIR"

echo "�� Pull des dernières modifications..."
cd "$ROOT_DIR"
git pull

# -------------------------
# Build serveur
# -------------------------
echo "🛠 Build du serveur..."
cd "$ROOT_DIR/src/vaultaire_serveur/main"
go build -buildvcs=false -o "$SERVER_BIN"

# Copier web_packet
cp -r "$ROOT_DIR/web_packet" "$BUILD_DIR/"

# -------------------------
# Build CLI
# -------------------------
echo "🛠 Build du CLI..."
cd "$ROOT_DIR/src/vaultaire_cli"
go build -buildvcs=false -o "$CLI_BIN"

# -------------------------
# Build client
# -------------------------
echo "🛠 Build du client..."
cd "$ROOT_DIR/src/vaultaire_client"
go build -buildvcs=false -o "$CLIENT_BIN"

# ------------------------
# Build CTL
# ------------------------
echo "🛠  Build du ctl..."
cd "$ROOT_DIR/src/vaultaire_ctl"
go build -buildvcs=false -o "$CTL_BIN"

# -------------------------
# Build modules PAM
# -------------------------
echo "🛠 Build modules PAM..."
cd "$ROOT_DIR/src/vaultaire_client/pam_module"
gcc -fPIC -shared -o pam_login_custom_module.so pam_login_custom_module.c -lcurl -lpam
gcc -fPIC -shared -o pam_logout_custom_module.so pam_logout_custom_module.c -lcurl -lpam
gcc -fPIC -shared -o pam_ssh_auth_module.so pam_ssh_auth_module.c -lcurl -lpam
cp ./pam*.so "$BUILD_DIR/"

# -------------------------
# Copier les binaires dans release Vaultaire_AD-ppd
# -------------------------
RELEASE_DIR="$ROOT_DIR/Vaultaire_AD-ppd"
# mkdir -p "$RELEASE_DIR"
mkdir -p /srv/nfs/serveur
cp $SERVER_BIN /srv/nfs/serveur/
cp $CLIENT_BIN /srv/nfs/serveur/
cp $CLI_BIN /srv/nfs/serveur/
cp $CTL_BIN /srv/nfs/serveur/

mkdir -p /srv/nfs/client
cp -rf $CLIENT_BIN /srv/nfs/client/
mkdir -p /srv/nfs/vaultaire_cli
cp -rf $CLI_BIN /srv/nfs/vaultaire_cli/
mkdir -p /srv/nfs/vaultaire_ctl
cp -rf $CTL_BIN /srv/nfs/vaultaire_ctl

echo "✅ Build et déploiement terminés."

