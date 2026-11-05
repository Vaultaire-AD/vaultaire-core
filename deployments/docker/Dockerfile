# syntax=docker/dockerfile:1.7
# ====================================================================
# Vaultaire — image du core (serveur), rootless et minimale
# ====================================================================
#
# Construite depuis la racine du dépôt :
#
#   docker build -f deployments/docker/Dockerfile \
#     --build-arg VAULTAIRE_VERSION=2.3.0 \
#     --build-arg VCS_COMMIT=$(git rev-parse --short HEAD) \
#     -t ghcr.io/vaultaire-ad/vaultaire-server:2.3.0 .
#
# Ce qu'elle garantit (voir deployments/docker/README.md) :
#
#   - AUCUN shell, aucun gestionnaire de paquets, aucun binaire système : la
#     base est distroless « static », qui ne porte que les certificats CA, les
#     fuseaux horaires et /etc/passwd. Le core et son CLI sont des binaires Go
#     statiques (CGO_ENABLED=0) ; il ne lance plus aucun programme externe
#     (le « -join » parle SSH lui-même depuis la 2.3).
#   - Compte NON root, UID/GID 65532, numérique : runAsNonRoot se vérifie sans
#     lire /etc/passwd.
#   - Ports au-dessus de 1024 : aucune capacité n'est nécessaire, même pas
#     NET_BIND_SERVICE. LDAP 3389, LDAPS 3636, DNS 5353/udp ; le Service
#     Kubernetes (ou « -p 389:3389 ») republie les ports standard.
#   - Compatible système de fichiers en lecture seule : le core n'écrit que
#     dans /var/lib/vaultaire, /var/log/vaultaire et /run/vaultaire.
#   - Images de base épinglées par empreinte : un tag qui bouge ne change pas
#     l'image en silence. Renovate/Dependabot mettent les empreintes à jour.
#   - Construite depuis les sources, sans rien télécharger d'autre que les
#     modules Go (go.sum) et les paquets de compilation des étages jetés.
#
# Le paquet d'agent (binaire + modules PAM/NSS des familles Rocky et Debian)
# est embarqué : c'est lui que « vlt create -c … -join » copie sur un poste.

ARG GO_IMAGE=golang:1.26.5-bookworm@sha256:53eeac89074db483fdf0ab3be1df32bf6e47562263d2d0d6baa7f26acb4957dd
ARG ROCKY_IMAGE=rockylinux/rockylinux:9@sha256:8101994123cf3d0a8fee517bee7f39e555c7d92bd2d9eb3303cc988a0eeed00f
ARG UBUNTU_IMAGE=ubuntu:22.04@sha256:076e7bf82319619f28dd0aa9c02ab34b055ad37100395b4f49a2ffba04fb5e11
ARG RUNTIME_IMAGE=gcr.io/distroless/static-debian12:nonroot@sha256:afa5c872c891853ca7fcf1f12c3edb23f7eeef36189728842dd51042ff57f7ab

# --------------------------------------------------------------------
# 1. Core et CLI — Go statique
# --------------------------------------------------------------------
FROM ${GO_IMAGE} AS go
ARG VAULTAIRE_VERSION=dev
ARG VCS_COMMIT=dev
ARG VCS_DATE=unknown
ENV CGO_ENABLED=0 GOTOOLCHAIN=local GOFLAGS=-trimpath
WORKDIR /src

COPY src/vaultaire_serveur/go.mod src/vaultaire_serveur/go.sum ./vaultaire_serveur/
RUN --mount=type=cache,target=/go/pkg/mod cd vaultaire_serveur && go mod download
COPY src/vaultaire_cli/ ./vaultaire_cli/
COPY src/vaultaire_serveur/ ./vaultaire_serveur/

RUN --mount=type=cache,target=/go/pkg/mod --mount=type=cache,target=/root/.cache/go-build \
    set -eu; \
    V="-X vaultaire/core/version.Commit=${VCS_COMMIT} -X vaultaire/core/version.Date=${VCS_DATE}"; \
    [ "${VAULTAIRE_VERSION}" = dev ] || V="$V -X vaultaire/core/version.Version=${VAULTAIRE_VERSION}"; \
    mkdir -p /out/bin; \
    cd /src/vaultaire_serveur/main && go build -buildvcs=false -ldflags "-s -w $V" -o /out/bin/vaultaire_serveur; \
    cd /src/vaultaire_cli && go build -buildvcs=false -ldflags "-s -w" -o /out/bin/vaultaire_cli; \
    # Un binaire qui chargerait la libc ne démarrerait pas sur distroless static.
    ! (go version -m /out/bin/vaultaire_serveur | grep -q 'CGO_ENABLED=1')

# --------------------------------------------------------------------
# 2a. Agent + modules natifs de la famille Rocky (glibc 2.34)
# --------------------------------------------------------------------
FROM ${GO_IMAGE} AS gotoolchain

FROM ${ROCKY_IMAGE} AS agent-rocky
ARG VAULTAIRE_VERSION=dev
ARG VCS_COMMIT=dev
ARG VCS_DATE=unknown
RUN dnf install -y --setopt=install_weak_deps=False gcc binutils pam-devel libxcrypt-devel \
    && dnf clean all
COPY --from=gotoolchain /usr/local/go /usr/local/go
ENV PATH=/usr/local/go/bin:$PATH GOTOOLCHAIN=local GOFLAGS=-trimpath GOPATH=/go
WORKDIR /src
COPY src/ducky-network-sdk-service/ ./ducky-network-sdk-service/
COPY src/vaultaire_client/ ./vaultaire_client/
RUN --mount=type=cache,target=/go/pkg/mod --mount=type=cache,target=/root/.cache/go-build \
    set -eu; \
    a() { printf -- '-X %s.Commit=%s -X %s.Date=%s' "$1" "$VCS_COMMIT" "$1" "$VCS_DATE"; }; \
    V="$(a vaultaire_client/version) $(a duckynetworkclient/V1/duckynetwork/version)"; \
    [ "${VAULTAIRE_VERSION}" = dev ] || V="$V -X vaultaire_client/version.Version=${VAULTAIRE_VERSION}"; \
    mkdir -p /out/vaultaire_client/rocky; \
    cd /src/vaultaire_client && go build -buildvcs=false -ldflags "$V" -o /out/vaultaire_client/vaultaire_client; \
    VAULTAIRE_GLIBC_MAX=2.34 bash /src/vaultaire_client/pam_module/auto_compil.sh /out/vaultaire_client/rocky; \
    chmod 0755 /out/vaultaire_client/vaultaire_client /out/vaultaire_client/rocky/*

# --------------------------------------------------------------------
# 2b. Modules natifs de la famille Debian (Ubuntu 22.04, glibc 2.35)
# --------------------------------------------------------------------
FROM ${UBUNTU_IMAGE} AS modules-debian
RUN apt-get update -q \
    && DEBIAN_FRONTEND=noninteractive apt-get install -y -q --no-install-recommends \
       gcc libc6-dev libpam0g-dev libcrypt-dev binutils \
    && rm -rf /var/lib/apt/lists/*
COPY src/vaultaire_client/pam_module/ /src/pam_module/
RUN VAULTAIRE_GLIBC_MAX=2.35 bash /src/pam_module/auto_compil.sh /out/debian \
    && chmod 0755 /out/debian/*

# --------------------------------------------------------------------
# 3. Arborescence finale, assemblée là où un shell existe encore
# --------------------------------------------------------------------
FROM ${GO_IMAGE} AS rootfs
COPY --from=go /out/bin/ /rootfs/opt/vaultaire/bin/
COPY --from=agent-rocky /out/vaultaire_client/ /rootfs/opt/vaultaire/vaultaire_client/
COPY --from=modules-debian /out/debian/ /rootfs/opt/vaultaire/vaultaire_client/debian/
COPY web_packet/ /rootfs/opt/vaultaire/web_packet/
COPY automatisation/auto_deployements/ /rootfs/opt/vaultaire/automatisation/
COPY deployments/docker/serveur_conf.yaml /rootfs/etc/vaultaire/serveur_conf.yaml
RUN set -eu; \
    for f in pam_login_custom_module.so pam_logout_custom_module.so pam_ssh_auth_module.so libnss_vaultaire.so.2; do \
      test -s /rootfs/opt/vaultaire/vaultaire_client/rocky/$f; \
      test -s /rootfs/opt/vaultaire/vaultaire_client/debian/$f; \
    done; \
    mkdir -p /rootfs/var/lib/vaultaire /rootfs/var/log/vaultaire /rootfs/run/vaultaire; \
    # Le code et les ressources appartiennent à root et ne s'écrivent pas : le
    # compte du core (65532) ne peut pas modifier ce qu'il exécute.
    chown -R 0:0 /rootfs/opt /rootfs/etc; \
    find /rootfs/opt /rootfs/etc -type d -exec chmod 0755 {} +; \
    find /rootfs/opt/vaultaire/web_packet /rootfs/opt/vaultaire/automatisation /rootfs/etc -type f -exec chmod 0644 {} +; \
    chmod 0755 /rootfs/opt/vaultaire/bin/* ; \
    # Seuls ces trois répertoires sont au core.
    chown -R 65532:65532 /rootfs/var/lib/vaultaire /rootfs/var/log/vaultaire /rootfs/run/vaultaire; \
    chmod 0700 /rootfs/var/lib/vaultaire /rootfs/var/log/vaultaire /rootfs/run/vaultaire

# --------------------------------------------------------------------
# 4. Image d'exécution
# --------------------------------------------------------------------
FROM ${RUNTIME_IMAGE}
ARG VAULTAIRE_VERSION=dev
ARG VCS_COMMIT=dev
ARG VCS_DATE=unknown

LABEL org.opencontainers.image.title="vaultaire-server" \
      org.opencontainers.image.description="Vaultaire core : annuaire LDAP/LDAPS, authentification centralisée des postes Linux, GPO" \
      org.opencontainers.image.source="https://github.com/Vaultaire-AD/vaultaire-core" \
      org.opencontainers.image.vendor="Vaultaire" \
      org.opencontainers.image.version="${VAULTAIRE_VERSION}" \
      org.opencontainers.image.revision="${VCS_COMMIT}" \
      org.opencontainers.image.created="${VCS_DATE}"

COPY --from=rootfs /rootfs/ /

# Le core lit sa configuration ici (VAULTAIRE_CONFIG l'emporte). Chaque clé
# peut être remplacée par une variable VAULTAIRE_* ; les secrets aussi par
# VAULTAIRE_*_FILE. Liste : docs/Installation/Variables_environnement.md
ENV VAULTAIRE_CONFIG=/etc/vaultaire/serveur_conf.yaml \
    VAULTAIRE_SOCKET=/run/vaultaire/vaultaire.sock \
    VAULTAIRE_WEB_PACKET=/opt/vaultaire/web_packet/sso_WEB_page \
    VAULTAIRE_LOG_FORMAT=json \
    TZ=UTC

WORKDIR /opt/vaultaire
USER 65532:65532

#      ducky   web   api   ldap  ldaps  dns
EXPOSE 6666/tcp 4443/tcp 6643/tcp 3389/tcp 3636/tcp 5353/udp

# Pas de shell pour un HEALTHCHECK classique : le CLI interroge le core par
# son socket — c'est la preuve qu'il a démarré ET qu'il répond.
HEALTHCHECK --interval=30s --timeout=5s --start-period=60s --retries=3 \
    CMD ["/opt/vaultaire/bin/vaultaire_cli", "version"]

ENTRYPOINT ["/opt/vaultaire/bin/vaultaire_serveur"]
