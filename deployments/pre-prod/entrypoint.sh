#!/usr/bin/env bash
# ====================================================================
# Entrypoint pre-prod — vérifie les volumes puis lance le serveur
# ====================================================================
#
# Les binaires et les fichiers statiques sont montés en volume, pas embarqués
# dans l'image. Ce script vérifie leur présence AVANT de démarrer, pour qu'un
# volume oublié se traduise par un message clair plutôt que par un conteneur qui
# redémarre en boucle avec « exec format error » ou « no such file ».

set -euo pipefail

VAULTAIRE_HOME="/opt/vaultaire"
SERVER_BIN="${VAULTAIRE_HOME}/bin/vaultaire_serveur"

cd "$VAULTAIRE_HOME"

fail() {
    echo "[entrypoint] ERREUR : $*" >&2
    echo "[entrypoint] Verifiez les volumes du service vaultaire-ad dans deployments/pre-prod/docker-compose.yml" >&2
    exit 1
}

# --- Binaire serveur -------------------------------------------------
[ -f "$SERVER_BIN" ] || fail "binaire serveur absent ($SERVER_BIN). Compilez d'abord avec ./auto-compil.sh"

# Le volume est monte en lecture seule : chmod +x echouerait. On verifie donc le
# bit d'execution au lieu de tenter de le poser, et on explique quoi faire.
[ -x "$SERVER_BIN" ] || fail "binaire serveur non executable. Sur l'hote : chmod +x cmd/vaultaire_server/vaultaire_serveur"

# --- Ressources web --------------------------------------------------
# Le serveur lit ./web_packet/sso_WEB_page/templates relativement a son
# repertoire de travail : sans ce volume, l'interface repondrait « Template
# manquant » sur chaque page, sans que la cause soit evidente.
[ -d "${VAULTAIRE_HOME}/web_packet/sso_WEB_page/templates" ] \
    || fail "web_packet absent ou incomplet : l'interface d'administration ne fonctionnerait pas"

# --- Configuration ---------------------------------------------------
[ -f "${VAULTAIRE_HOME}/serveur_conf.yaml" ] \
    || fail "serveur_conf.yaml absent de l'image"

echo "[entrypoint] Binaire     : $(ls -l "$SERVER_BIN" | awk '{print $5" octets, "$6" "$7" "$8}')"
echo "[entrypoint] web_packet  : present"
echo "[entrypoint] Demarrage du serveur Vaultaire..."

exec "$SERVER_BIN" "$@"
