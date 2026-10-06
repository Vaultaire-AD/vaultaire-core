# ====================================================================
# vaultaire_nexus — image autonome (compile et exécute)
# ====================================================================
#
# Contexte de construction : src/  (le module consomme le SDK Ducky par
# « replace ../ducky-network-sdk-service »).
#
#   docker build -f src/vaultaire_nexus/deploy/Dockerfile -t vaultaire/nexus src/
#
# ou, plus simple : docker compose -f src/vaultaire_nexus/deploy/docker-compose.yml up -d --build
#
# Volumes :
#   /var/lib/vaultaire_nexus     tout l'état (blobs, catalogue, comptes, suivi)
#   /etc/vaultaire_nexus         configuration (lecture seule)

# Images de base substituables : un parc sans accès à Docker Hub peut les
# tirer de son propre Nexus (--build-arg BUILD_IMAGE=nexus:8843/docker/golang:…).
ARG GO_VERSION=1.26.5
ARG BUILD_IMAGE=golang:${GO_VERSION}-bookworm
ARG RUNTIME_IMAGE=debian:12-slim

FROM ${BUILD_IMAGE} AS build
WORKDIR /src
# Dépendances d'abord : la couche reste en cache tant que go.mod ne change pas.
COPY ducky-network-sdk-service/ ducky-network-sdk-service/
COPY vaultaire_nexus/go.mod vaultaire_nexus/go.sum vaultaire_nexus/
RUN cd vaultaire_nexus && go mod download
COPY vaultaire_nexus/ vaultaire_nexus/
ARG VERSION=""
ARG COMMIT=dev
ARG DATE=inconnue
# CGO_ENABLED=0 : binaire statique (même raison que le proxy).
RUN cd vaultaire_nexus \
 && LDFLAGS="-s -w -X vaultaire_nexus/version.Commit=${COMMIT} -X vaultaire_nexus/version.Date=${DATE}" \
 && if [ -n "$VERSION" ]; then LDFLAGS="$LDFLAGS -X vaultaire_nexus/version.Version=${VERSION}"; fi \
 && CGO_ENABLED=0 GOTOOLCHAIN=local go build -trimpath -buildvcs=false -ldflags "$LDFLAGS" -o /out/vaultaire_nexus . \
 && /out/vaultaire_nexus -version

FROM ${RUNTIME_IMAGE}
LABEL description="Vaultaire Nexus - dépôt de paquets, images et releases"

# gnupg : signature facultative des index APT/YUM (signing.enable).
# UID fixe 10001, comme les autres images du dépôt.
RUN groupadd --system --gid 10001 vaultaire \
 && useradd --system --uid 10001 --gid 10001 \
            --home-dir /var/lib/vaultaire_nexus --shell /usr/sbin/nologin vaultaire \
 && apt-get update \
 && apt-get install -y --no-install-recommends ca-certificates tzdata gnupg curl \
 && rm -rf /var/lib/apt/lists/* \
 && mkdir -p /var/lib/vaultaire_nexus /etc/vaultaire_nexus /var/log/vaultaire \
 && chown -R vaultaire:vaultaire /var/lib/vaultaire_nexus /var/log/vaultaire

COPY --from=build /out/vaultaire_nexus /usr/local/bin/vaultaire_nexus
COPY vaultaire_nexus/config.example.yaml /etc/vaultaire_nexus/config.example.yaml
# Configuration minimale : mode local, dépôts à créer depuis l'interface.
# Remplacée par un montage de fichier en production.
RUN printf 'listen: ":8843"\ndata_dir: /var/lib/vaultaire_nexus\nlog_path: /var/log/vaultaire/\n' \
      > /etc/vaultaire_nexus/config.yaml

USER 10001:10001
WORKDIR /var/lib/vaultaire_nexus
EXPOSE 8843
VOLUME ["/var/lib/vaultaire_nexus"]

HEALTHCHECK --interval=30s --timeout=5s --start-period=20s \
  CMD curl -fsk "https://127.0.0.1:8843/healthz" || curl -fs "http://127.0.0.1:8843/healthz" || exit 1

# Sans fichier monté : défauts (compte local, dépôts à créer depuis l'interface).
ENTRYPOINT ["/usr/local/bin/vaultaire_nexus"]
CMD ["-config", "/etc/vaultaire_nexus/config.yaml"]
