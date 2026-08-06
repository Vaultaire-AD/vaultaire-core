#!/bin/sh
# Point d'entrée du proxy.
#
# Son seul rôle est de transformer trois pannes muettes en messages qui disent
# quoi faire. Sans lui, un binaire non exécutable donne :
#
#     OCI runtime create failed: ... exec: "/opt/vaultaire/bin/vaultaire_proxy":
#     permission denied
#
# — un message du runtime, qui ne dit ni pourquoi ni sur quelle machine agir.
set -e

BIN="/opt/vaultaire/bin/vaultaire_proxy"
CONFIG="${VAULTAIRE_CONFIG:-/etc/vaultaire_proxy/config.yaml}"
KEYS="${VAULTAIRE_KEYS:-/var/lib/vaultaire_proxy/keys}"

fail() {
    echo "vlt-proxy: $1" >&2
    exit 1
}

[ -f "$BIN" ] || fail "binaire absent de $BIN.
  Le binaire vient de cmd/vaultaire_proxy/, produit par ./auto-compil.sh.
  Lancez-le sur l'hôte, puis: docker compose up -d"

# Le conteneur tourne en utilisateur NON PRIVILÉGIÉ. auto-compil.sh produit un
# binaire en 0700 appartenant à celui qui a compilé : le compte du conteneur ne
# peut alors ni le lire ni l'exécuter.
#
# Le volume est monté en lecture seule, donc un chmod ici échouerait de toute
# façon. On vérifie et on explique.
[ -x "$BIN" ] || fail "binaire non exécutable par le compte du conteneur.
  Sur l'hôte : chmod 755 cmd/vaultaire_proxy/vaultaire_proxy"

[ -f "$CONFIG" ] || fail "configuration absente de $CONFIG.
  Sur l'hôte : cp deployments/pre-prod/vlt-proxy/config.example.yaml \\
                  deployments/pre-prod/vlt-proxy/config.yaml
  puis renseignez servers et enrollment.key"

# Le répertoire des clés porte l'identité du proxy et doit être inscriptible :
# l'enrôlement y écrit client_software.yaml et la paire de clés.
[ -w "$KEYS" ] || fail "répertoire des clés $KEYS non inscriptible.
  Le volume vlt_proxy_keys doit appartenir au compte du conteneur."

exec "$BIN" --config "$CONFIG" --keys "$KEYS" "$@"
