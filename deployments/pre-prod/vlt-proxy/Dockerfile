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
# L'UID est FIXÉ à 10001.
#
# Le volume des clés est créé par Docker avec la propriété du compte qui y écrit
# en premier. Un UID attribué automatiquement changerait au gré des paquets
# installés dans l'image, et un conteneur reconstruit ne pourrait plus écrire
# dans le volume de son prédécesseur — donc réenrôlement, donc jeton consommé.
RUN groupadd --system --gid 10001 vaultaire \
    && useradd --system --uid 10001 --gid 10001 \
               --home-dir /var/lib/vaultaire_proxy --shell /usr/sbin/nologin vaultaire \
    && mkdir -p /opt/vaultaire/bin /etc/vaultaire_proxy /var/lib/vaultaire_proxy/keys \
    && chown -R vaultaire:vaultaire /var/lib/vaultaire_proxy \
    && chmod 700 /var/lib/vaultaire_proxy/keys \
    && apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates tzdata \
    && rm -rf /var/lib/apt/lists/*

COPY entrypoint.sh /usr/local/bin/entrypoint.sh
RUN chmod 755 /usr/local/bin/entrypoint.sh

WORKDIR /var/lib/vaultaire_proxy

# Le proxy n'a besoin d'aucun privilège : il ouvre une connexion SORTANTE vers le
# core et n'écrit que dans son répertoire de clés. Tourner en root lui donnerait
# un pouvoir dont il ne fait rien.
#
# Conséquence à connaître : le binaire monté doit être lisible et exécutable par
# cet utilisateur. auto-compil.sh le produit en 0755 pour cette raison.
USER vaultaire

# 389 et 8443 pour la répartition de charge à venir. Cette version n'écoute rien :
# elle ne fait que se connecter au core.
EXPOSE 389 8443

ENTRYPOINT ["/usr/local/bin/entrypoint.sh"]
