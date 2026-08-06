#!/bin/sh
# Point d'entrée du proxy.
#
# Deux rôles :
#
#   1. transformer des pannes muettes en messages qui disent quoi faire ;
#   2. approprier le volume d'identité, puis ABANDONNER les privilèges.
#
# Sans le point 2, la propriété du volume dépendrait de l'UID qu'avait l'image le
# jour où Docker l'a créé. Changer l'image — ne serait-ce qu'en réordonnant un
# useradd — rendrait le volume inaccessible à son successeur, et la seule issue
# serait de le détruire, donc de réenrôler et de consommer un jeton.
set -e

BIN="/opt/vaultaire/bin/vaultaire_proxy"
CONFIG="${VAULTAIRE_CONFIG:-/etc/vaultaire_proxy/config.yaml}"
KEYS="${VAULTAIRE_KEYS:-/var/lib/vaultaire_proxy/keys}"
LOGS="/var/log/vaultaire"
RUN_UID=10001
RUN_GID=10001

fail() {
    echo "vlt-proxy: $1" >&2
    exit 1
}

[ -f "$BIN" ] || fail "binaire absent de $BIN.
  Il vient de cmd/vaultaire_proxy/, produit par ./auto-compil.sh sur l'hôte."

# Le proxy tournera en utilisateur NON PRIVILÉGIÉ. Un binaire en 0600 ou 0700
# appartenant à un autre compte lui serait inaccessible.
#
# Le volume du binaire est monté en lecture seule : un chmod ici échouerait de
# toute façon. On vérifie et on explique.
[ -r "$BIN" ] && [ -x "$BIN" ] || fail "binaire non exécutable par le compte du conteneur.
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

if [ "$(id -u)" = "0" ]; then
    # Docker crée un volume nommé avec la propriété qu'avait le répertoire dans
    # l'image au moment de la création — et ne la remet jamais à jour ensuite.
    # Un volume plus ancien que l'image courante appartient donc à un autre UID.
    #
    # On le reprend ici, une fois, au démarrage. C'est ce qui rend le conteneur
    # remplaçable sans toucher au volume : l'identité du proxy survit aux
    # reconstructions d'image, donc aucun jeton d'enrôlement n'est gaspillé.
    mkdir -p "$KEYS" "$LOGS"
    chown -R "$RUN_UID:$RUN_GID" "$KEYS" "$LOGS"
    chmod 700 "$KEYS"

    # setpriv plutôt que USER dans le Dockerfile : il faut être root pour le
    # chown ci-dessus, et l'abandon des privilèges doit se faire APRÈS. Le
    # processus final tourne donc bien en 10001 — le proxy n'ouvre que des
    # connexions sortantes et n'écrit que dans son répertoire de clés, root ne
    # lui apporterait qu'un pouvoir dont il ne fait rien.
    #
    # --clear-groups : sans lui, le processus garderait les groupes
    # supplémentaires de root, ce qui annulerait une partie du bénéfice.
    exec setpriv --reuid="$RUN_UID" --regid="$RUN_GID" --clear-groups \
        "$BIN" --config "$CONFIG" --keys "$KEYS" "$@"
fi

# Démarrage déjà non privilégié (docker run --user, par exemple) : on ne peut
# rien approprier, on se contente de vérifier.
[ -w "$KEYS" ] || fail "répertoire des clés $KEYS non inscriptible par l'UID $(id -u).
  Ce conteneur reprend normalement le volume au démarrage, ce qui demande de
  partir en root. Retirez le « user: » du docker-compose.yml, ou recréez le
  volume : docker compose down -v && docker compose up -d"

exec "$BIN" --config "$CONFIG" --keys "$KEYS" "$@"
