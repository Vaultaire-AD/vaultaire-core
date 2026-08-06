#!/bin/sh
# Point d'entrée du proxy.
#
# Son seul rôle est de transformer des pannes muettes en messages qui disent quoi
# faire. Sans lui, un binaire non exécutable donne :
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
  Il vient de cmd/vaultaire_proxy/, produit par ./auto-compil.sh sur l'hôte."

# Le conteneur tourne en utilisateur NON PRIVILÉGIÉ (UID 10001). Un binaire en
# 0600 ou 0700 appartenant à un autre compte lui est inaccessible.
#
# Le volume est monté en lecture seule, donc un chmod ici échouerait de toute
# façon. On vérifie et on explique.
[ -x "$BIN" ] || fail "binaire non exécutable par le compte du conteneur.
  Sur l'hôte : chmod 755 cmd/vaultaire_proxy/vaultaire_proxy
  Durablement : git update-index --chmod=+x cmd/vaultaire_proxy/vaultaire_proxy"

# La configuration est FACULTATIVE : deux variables suffisent.
#
# Exiger un fichier pour porter une adresse et une clé, c'est imposer un montage
# et un fichier à tenir hors du dépôt, pour rien. On ne réclame donc que l'un
# des deux chemins.
if [ ! -f "$CONFIG" ] && [ -z "$VAULTAIRE_IP_CORE" ]; then
    fail "aucune configuration.
  Le proxy n'a besoin que de deux choses :

    VAULTAIRE_IP_CORE=10.0.0.1:6666      adresse du core (port 6666 par défaut)
    VAULTAIRE_ENROLL_KEY=<clé>           clé créée sur le core :
                                           vlt enroll create --type vaultaire_proxy

  Renseignez-les dans le docker-compose.yml, ou montez un config.yaml
  sur $CONFIG."
fi

# Le répertoire des clés porte l'identité du proxy et doit être inscriptible :
# l'enrôlement y écrit client_software.yaml et la paire de clés.
[ -w "$KEYS" ] || fail "répertoire des clés $KEYS non inscriptible.
  Le volume vlt_proxy_keys doit appartenir à l'UID 10001."

exec "$BIN" --config "$CONFIG" --keys "$KEYS" "$@"
