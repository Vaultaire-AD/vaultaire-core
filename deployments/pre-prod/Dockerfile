# ====================================================================
# Vaultaire Server - image d'exécution pre-prod
# ====================================================================
#
# Cette image ne contient AUCUN binaire applicatif et ne compile rien : les
# binaires et les fichiers statiques sont montés en volume par docker-compose,
# depuis cmd/ et web_packet/ du dépôt.
#
# Pourquoi : la boucle de test consistait à supprimer l'image puis à la
# reconstruire avec --no-cache, uniquement pour y recopier 14 Mo de binaires
# déjà compilés. La couche dnf, qui ne change jamais, était rejouée à chaque
# itération. Avec le montage, une mise à jour se réduit à un redémarrage du
# conteneur — l'image ne se reconstruit que lorsque ce fichier change.
#
# C'est un choix assumé pour un environnement de test : l'image n'est plus
# autoportante, elle dépend de ce qui est monté. Pour une image de release
# reproductible, réactiver les étages de compilation en fin de fichier.
#
# Points de montage attendus (voir docker-compose.yml) :
#   /opt/vaultaire/bin            <- cmd/vaultaire_server   (serveur + cli)
#   /opt/vaultaire/vaultaire_client <- cmd/vaultaire_client (binaire client + .so PAM)
#   /opt/vaultaire/web_packet     <- web_packet             (templates et statiques)

FROM rockylinux:9

LABEL maintainer="adm-lviguie"
LABEL description="Vaultaire AD server - pre-prod/test (binaires montes en volume)"
LABEL env="preprod"

# Couches stables, mises en cache : elles ne dépendent d'aucun fichier du dépôt
# et ne sont donc jamais réexécutées tant que ce Dockerfile ne change pas.
RUN useradd -m -d /opt/vaultaire -s /bin/bash vaultaire \
    && mkdir -p /var/log/vaultaire /opt/vaultaire/bin \
    && chown -R vaultaire:vaultaire /opt/vaultaire /var/log/vaultaire \
    && chmod 770 /opt/vaultaire /var/log/vaultaire \
    && dnf install -y sudo openssh-server openssh-clients \
    && dnf clean all

WORKDIR /opt/vaultaire

# Seul élément embarqué : la configuration, qui bouge rarement et doit exister
# même si aucun volume n'est monté.
COPY --chown=vaultaire:vaultaire deployments/configs/serveur_conf.yaml ./serveur_conf.yaml

# Le déploiement automatisé n'est pas monté : il fait partie de l'image.
COPY --chown=vaultaire:vaultaire automatisation/auto_deployements ./automatisation

# Le serveur cherche ./web_packet et ./vaultaire_client relativement à son
# répertoire de travail : l'entrypoint le place donc dans /opt/vaultaire, où les
# volumes sont montés, et lance le binaire depuis bin/.
COPY --chown=vaultaire:vaultaire deployments/pre-prod/entrypoint.sh /usr/local/bin/entrypoint.sh
RUN chmod +x /usr/local/bin/entrypoint.sh

EXPOSE 666 443 389 636 22 53/udp

USER root

ENTRYPOINT ["/usr/local/bin/entrypoint.sh"]

# ====================================================================
# Image de release (désactivée)
# ====================================================================
# Pour produire une image autoportante, compilée et reproductible — sans
# dépendre de binaires construits sur le poste de développement — décommenter
# les étages ci-dessous, retirer les volumes du docker-compose, et remettre les
# COPY des binaires depuis les étages de build.
#
# Le cache Go rend les reconstructions incrémentales rapides ; sans lui, chaque
# build repart de zéro et l'étage de compilation devient le nouveau goulot.
#
# # syntax=docker/dockerfile:1.4
# FROM golang:1.23-alpine AS server-builder
# WORKDIR /build
# COPY src/vaultaire_serveur/ ./
# RUN --mount=type=cache,target=/root/.cache/go-build \
#     --mount=type=cache,target=/go/pkg/mod \
#     CGO_ENABLED=0 GOOS=linux go build -ldflags="-s -w" -o vaultaire_serveur ./main
#
# FROM golang:1.23-alpine AS cli-builder
# WORKDIR /build
# COPY src/vaultaire_cli/ ./
# RUN --mount=type=cache,target=/root/.cache/go-build \
#     --mount=type=cache,target=/go/pkg/mod \
#     CGO_ENABLED=0 GOOS=linux go build -ldflags="-s -w" -o vaultaire_cli .
#
# COPY --from=server-builder --chown=vaultaire:vaultaire /build/vaultaire_serveur ./bin/vaultaire_serveur
# COPY --from=cli-builder    --chown=vaultaire:vaultaire /build/vaultaire_cli     ./bin/vaultaire_cli
