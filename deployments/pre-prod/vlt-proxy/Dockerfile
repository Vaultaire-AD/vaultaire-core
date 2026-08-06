# ====================================================================
# vlt-proxy — image d'exécution pre-prod
# ====================================================================
#
# Cette image ne contient AUCUN binaire et ne compile rien. Le binaire vient de
# cmd/vaultaire_proxy/, monté en volume par docker-compose — même principe que
# l'image du serveur.
#
# Une mise à jour se réduit donc à :
#
#     ./auto-compil.sh && docker compose restart vlt-proxy
#
# L'image ne se reconstruit que lorsque ce fichier change.
#
# Points de montage attendus (voir docker-compose.yml) :
#   /opt/vaultaire/bin        <- cmd/vaultaire_proxy   (binaire, lecture seule)
#   /etc/vaultaire_proxy      <- ./config.yaml         (lecture seule)
#   /var/lib/vaultaire_proxy/keys  <- volume nommé     (identité, écriture)

FROM debian:12-slim

LABEL maintainer="adm-lviguie"
LABEL description="Vaultaire proxy - client de service du cluster (binaire monte en volume)"
LABEL env="preprod"

# debian-slim et non alpine : auto-compil.sh compile le proxy en CGO_ENABLED=0,
# donc un binaire statique tournerait sur les deux. Mais si quelqu'un le
# recompile un jour sans ce réglage, le binaire sera lié à la glibc et refusera
# de démarrer sur la musl d'alpine — avec un « no such file or directory » qui
# désigne le binaire et non la bibliothèque manquante. Debian évite ce piège.
#
# L'UID est FIXÉ à 10001, et util-linux fournit setpriv.
#
# Un UID attribué automatiquement changerait au gré des paquets installés dans
# l'image. L'entrypoint reprend le volume au démarrage, donc ce n'est plus
# bloquant — mais un UID stable garde les fichiers lisibles d'une version à
# l'autre sans réécriture inutile de tout le volume.
RUN groupadd --system --gid 10001 vaultaire \
    && useradd --system --uid 10001 --gid 10001 \
               --home-dir /var/lib/vaultaire_proxy --shell /usr/sbin/nologin vaultaire \
    && mkdir -p /opt/vaultaire/bin /etc/vaultaire_proxy /var/lib/vaultaire_proxy/keys \
    && mkdir -p /var/log/vaultaire \
    && chown -R vaultaire:vaultaire /var/lib/vaultaire_proxy /var/log/vaultaire \
    && chmod 700 /var/lib/vaultaire_proxy/keys \
    && apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates tzdata util-linux \
    && rm -rf /var/lib/apt/lists/*

COPY entrypoint.sh /usr/local/bin/entrypoint.sh
RUN chmod 755 /usr/local/bin/entrypoint.sh

WORKDIR /var/lib/vaultaire_proxy

# /var/log/vaultaire appartient au compte du conteneur.
#
# Le paquet Ducky y écrit son journal en plus de la sortie standard. Sans ce
# répertoire — ou sans les droits dessus — chaque ligne journalisée produit deux
# messages d'erreur non horodatés sur stderr, et le vrai contenu se perd dedans.
# Docker collecte stdout de toute façon : le fichier est redondant, mais le
# laisser échouer coûte la lisibilité de tout le reste.

# PAS de « USER vaultaire » ici, et c'est délibéré.
#
# L'entrypoint démarre en root pour reprendre la propriété du volume d'identité,
# puis abandonne les privilèges avec setpriv avant d'exécuter le proxy. Le
# processus final tourne donc en 10001.
#
# Poser USER ici priverait l'entrypoint du chown, et un volume créé par une image
# antérieure resterait inaccessible — sans autre issue que de le détruire, donc
# de réenrôler et de consommer un jeton d'enrôlement.
#
# Le binaire monté doit rester lisible et exécutable par 10001 : auto-compil.sh
# le produit en 0755, et le mode est enregistré dans git.

# 389 et 8443 pour la répartition de charge à venir. Cette version n'écoute rien :
# elle ne fait que se connecter au core.
EXPOSE 389 8443

ENTRYPOINT ["/usr/local/bin/entrypoint.sh"]
