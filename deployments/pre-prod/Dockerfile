# ====================================================================
# Vaultaire Server - Minimal Alpine Dockerfile
# ====================================================================
FROM rockylinux:9

LABEL maintainer="adm-lviguie"
LABEL description="Vaultaire AD server container (Alpine Linux based)"

# --------------------------------------------------------------------
# Mise à jour et installation SSH + utilitaires minimal
# --------------------------------------------------------------------

# --------------------------------------------------------------------
# Création utilisateur applicatif (non-root)
# --------------------------------------------------------------------
RUN useradd -m -d /opt/vaultaire -s /bin/bash vaultaire
RUN mkdir -p /var/log/vaultaire
RUN chown -R vaultaire:vaultaire /opt/vaultaire /var/log/vaultaire
RUN chmod 770 /opt/vaultaire /var/log/vaultaire
RUN dnf install -y sudo openssh-server


# --------------------------------------------------------------------
# Copier le code applicatif
# --------------------------------------------------------------------
WORKDIR /opt/vaultaire
COPY --chown=vaultaire:vaultaire cmd/vaultaire_server/vaultaire_serveur ./vaultaire_serveur
COPY --chown=vaultaire:vaultaire cmd/vaultaire_client/ ./vaultaire_client/
COPY --chown=vaultaire:vaultaire web_packet ./web_packet
COPY --chown=vaultaire:vaultaire automatisation ./automatisation
COPY --chown=vaultaire:vaultaire deployments/configs/serveur_conf.yaml ./serveur_conf.yaml
COPY --chown=vaultaire:vaultaire deployments/pre-prod/dockerautocreate.sh ./dockerautocreate.sh

# --------------------------------------------------------------------
# Permissions
# --------------------------------------------------------------------
RUN chmod +x ./vaultaire_serveur ./dockerautocreate.sh

# --------------------------------------------------------------------
# Ports exposés
# --------------------------------------------------------------------
EXPOSE 666 443 389 636 22 53/udp

# --------------------------------------------------------------------
# Définition de l’utilisateur non-root
# --------------------------------------------------------------------
USER root

# --------------------------------------------------------------------
# Entrypoint
# --------------------------------------------------------------------
ENTRYPOINT ["./vaultaire_serveur"]
