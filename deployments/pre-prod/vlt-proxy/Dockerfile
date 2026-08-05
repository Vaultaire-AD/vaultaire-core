# ====================================================================
# vlt-proxy — image d'exécution pre-prod
# ====================================================================
#
# Cette image ne contient AUCUN binaire et ne compile rien. Le binaire vient de
# cmd/vaultaire_proxy/, monté en volume par docker-compose — même principe que
# l'image du serveur.
#
# Pourquoi : recompiler ici rejouerait un étage Go complet à chaque itération
# pour produire un binaire qu'auto-compil.sh vient déjà de fabriquer. Une mise à
# jour se réduit à :
#
#     ./auto-compil.sh && docker compose restart vlt-proxy
#
# L'image ne se reconstruit que lorsque ce fichier change.
#
# Point de montage attendu :
#   /opt/vaultaire/bin   <- cmd/vaultaire_proxy   (binaire + config d'exemple)

FROM debian:12-slim

LABEL maintainer="adm-lviguie"
LABEL description="Vaultaire proxy - client de service du cluster (binaire monte en volume)"
LABEL env="preprod"

# debian-slim et non alpine : auto-compil.sh compile le proxy en CGO_ENABLED=0,
# donc un binaire statique tournerait sur les deux. Mais si quelqu'un le
# recompile un jour sans ce réglage, le binaire sera lié à la glibc et refusera
# de démarrer sur la musl d'alpine, avec un « not found » qui désigne le
# binaire lui-même et non la bibliothèque manquante. Debian évite ce piège.
RUN useradd --system --create-home --home-dir /var/lib/vaultaire_proxy \
            --shell /usr/sbin/nologin vaultaire \
    && mkdir -p /opt/vaultaire/bin /etc/vaultaire_proxy /var/lib/vaultaire_proxy/keys \
    && chown -R vaultaire:vaultaire /var/lib/vaultaire_proxy \
    && chmod 700 /var/lib/vaultaire_proxy/keys \
    && apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates tzdata \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /var/lib/vaultaire_proxy

# Le proxy n'a besoin d'aucun privilège : il ouvre une connexion SORTANTE vers le
# core et n'écrit que dans son répertoire de clés.
USER vaultaire

# 389 et 8443 pour la répartition de charge à venir. La v1 n'écoute rien.
EXPOSE 389 8443

ENTRYPOINT ["/opt/vaultaire/bin/vaultaire_proxy"]
