# ====================================================================
#  Vaultaire Server - Secure Dockerfile
# ====================================================================

# Base solide : Rocky Linux 9
FROM rockylinux:9

LABEL maintainer="adm-lviguie"
LABEL description="Vaultaire AD server container (Rocky Linux 9 based)"

# Sécurisation de base + outils utiles
RUN dnf -y update && \
    dnf -y install \
        openssh-clients \
        openssh-server \
        iputils \
        bind-utils \
        vim \
        net-tools \
        curl \
        wget \
        mariadb \
        nmap \
        procps-ng \
        sudo && \
    dnf clean all

# --------------------------------------------------------------------
# Création utilisateur applicatif (non-root)
# --------------------------------------------------------------------
RUN useradd -m -s /bin/bash vaultaire && \
    echo "vaultaire ALL=(ALL) NOPASSWD:ALL" >> /etc/sudoers.d/vaultaire && \
    mkdir -p /opt/vaultaire && \
    chown -R vaultaire:vaultaire /opt/vaultaire

# --------------------------------------------------------------------
# Copie du code applicatif
# (on part du répertoire racine du repo)
# --------------------------------------------------------------------
WORKDIR /opt/vaultaire
COPY cmd/vaultaire_server/vaultaire_serveur ./vaultaire_serveur
COPY cmd/vaultaire_server/vaultaire_cli ./vaultaire_cli
COPY cmd/vaultaire_client/vaultaire_client ./vaultaire_client
COPY web_packet ./web_packet
COPY automatisation ./automatisation
COPY deployements/configs/serveur_conf.yaml ./serveur_conf.yaml
COPY deployements/prod/dockerautocreate.sh ./dockerautocreate.sh

# --------------------------------------------------------------------
# Sécurisation des permissions
# --------------------------------------------------------------------
RUN chmod +x ./vaultaire_serveur ./vaultaire_cli ./vaultaire_client ./dockerautocreate.sh && \
    chown -R vaultaire:vaultaire /opt/vaultaire

# --------------------------------------------------------------------
# Ports exposés (LDAP, LDAPS, WebUI, DNS interne, etc.)
# --------------------------------------------------------------------
EXPOSE 666 443 389 636 53/udp

# --------------------------------------------------------------------
# Définition de l’utilisateur non-root
# --------------------------------------------------------------------
USER vaultaire

# --------------------------------------------------------------------
# Commande de démarrage
# --------------------------------------------------------------------
ENTRYPOINT ["bash", "-c", "/opt/vaultaire/dockerautocreate.sh && /opt/vaultaire/vaultaire_serveur"]
