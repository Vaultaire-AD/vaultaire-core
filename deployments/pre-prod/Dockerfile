# ====================================================================
#  Vaultaire Server - Secure Dockerfile
# ====================================================================

# Base solide : Rocky Linux 9
FROM rockylinux:9

LABEL maintainer="adm-lviguie"
LABEL description="Vaultaire AD server container (Rocky Linux 9 based)"

# --------------------------------------------------------------------
# Sécurisation de base + outils utiles
# --------------------------------------------------------------------
RUN dnf -y update && \
    dnf -y install \
        openssh-clients \
        openssh-server \
        iputils \
        bind-utils \
        vim \
        mariadb \
        sudo && \
    dnf clean all

# --------------------------------------------------------------------
# Création utilisateur applicatif (non-root)
# --------------------------------------------------------------------
RUN useradd -m -s /bin/bash vaultaire && \
    echo "vaultaire ALL=(ALL) NOPASSWD:ALL" >> /etc/sudoers.d/vaultaire && \
    mkdir -p /opt/vaultaire /var/log/vaultaire && \
    chown -R root:root /opt/vaultaire /var/log/vaultaire && \
    chmod 770 /opt/vaultaire /var/log/vaultaire

# --------------------------------------------------------------------
# Copie du code applicatif
# (on part du répertoire racine du repo)
# --------------------------------------------------------------------
WORKDIR /opt/vaultaire

# ⚠️ Ne pas créer manuellement le socket — le serveur le crée lui-même
COPY cmd/vaultaire_server/vaultaire_serveur ./vaultaire_serveur
COPY cmd/vaultaire_server/vaultaire_cli ./vaultaire_cli
COPY cmd/vaultaire_client/ /opt/vaultaire/vaultaire_client/
COPY web_packet ./web_packet
COPY automatisation ./automatisation
COPY deployments/configs/serveur_conf.yaml ./serveur_conf.yaml
COPY deployments/pre-prod/dockerautocreate.sh ./dockerautocreate.sh

# --------------------------------------------------------------------
# Sécurisation des permissions et capabilities
# --------------------------------------------------------------------
RUN chmod +x ./vaultaire_serveur ./vaultaire_cli ./dockerautocreate.sh && \
    chown -R root:root /opt/vaultaire && \
    # Autorise l'exécution sur ports <1024 (389, 53, etc.) sans root
    dnf clean all

# --------------------------------------------------------------------
# Ports exposés (LDAP, LDAPS, WebUI, DNS interne, etc.)
# --------------------------------------------------------------------
EXPOSE 666 443 389 636 53/udp

# --------------------------------------------------------------------
# Définition de l’utilisateur non-root
# --------------------------------------------------------------------
USER root

# --------------------------------------------------------------------
# Commande de démarrage
# --------------------------------------------------------------------
ENTRYPOINT ["bash", "-c", "/opt/vaultaire/vaultaire_serveur"]
