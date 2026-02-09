# ====================================================================
# Vaultaire Server - Multi-stage: build then runtime
# ====================================================================

# --------------------------------------------------------------------
# Stage 0: Build server binary
# --------------------------------------------------------------------
FROM golang:1.23-alpine AS server-builder
WORKDIR /build
RUN apk add --no-cache git ca-certificates

COPY src/vaultaire_serveur/ ./
RUN go mod download
RUN CGO_ENABLED=0 GOOS=linux go build -ldflags="-s -w" -o vaultaire_serveur ./main

# --------------------------------------------------------------------
# Stage 0b: Build CLI binary (separate module)
# --------------------------------------------------------------------
FROM golang:1.23-alpine AS cli-builder
WORKDIR /build
RUN apk add --no-cache git ca-certificates

COPY src/vaultaire_cli/ ./
RUN go mod download
RUN CGO_ENABLED=0 GOOS=linux go build -ldflags="-s -w" -o vaultaire_cli .

# --------------------------------------------------------------------
# Stage 1: Runtime
# --------------------------------------------------------------------
FROM rockylinux:9

LABEL maintainer="adm-lviguie"
LABEL description="Vaultaire AD server - pre-prod/test deployment (compiled)"
LABEL env="preprod"

RUN useradd -m -d /opt/vaultaire -s /bin/bash vaultaire
RUN mkdir -p /var/log/vaultaire
RUN chown -R vaultaire:vaultaire /opt/vaultaire /var/log/vaultaire
RUN chmod 770 /opt/vaultaire /var/log/vaultaire
RUN dnf install -y sudo openssh-server && dnf clean all

WORKDIR /opt/vaultaire

# Binaries from builders
COPY --from=server-builder /build/vaultaire_serveur ./vaultaire_serveur
COPY --from=cli-builder /build/vaultaire_cli ./vaultaire_cli

# Static assets and config (from build context = repo root)
COPY --chown=vaultaire:vaultaire cmd/vaultaire_client/ ./vaultaire_client/
COPY --chown=vaultaire:vaultaire web_packet ./web_packet
COPY --chown=vaultaire:vaultaire automatisation ./automatisation
COPY --chown=vaultaire:vaultaire deployments/configs/serveur_conf.yaml ./serveur_conf.yaml
COPY --chown=vaultaire:vaultaire deployments/pre-prod/dockerautocreate.sh ./dockerautocreate.sh

RUN chmod +x ./vaultaire_serveur ./vaultaire_cli ./dockerautocreate.sh

EXPOSE 666 443 389 636 22 53/udp

USER root

ENTRYPOINT ["./vaultaire_serveur"]
