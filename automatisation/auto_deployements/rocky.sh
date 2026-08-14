#!/usr/bin/env bash

# ==============================================================================
# 🔧 Script d'installation du client Vaultaire (Optimisé & Idempotent)
# ==============================================================================

set -euo pipefail

# Couleurs pour les logs
C_RESET='\033[0m'
C_INFO='\033[1;34m[INFO]\033[0m'
C_SUCCESS='\033[1;32m[SUCCÈS]\033[0m'
C_WARN='\033[1;33m[ATTENTION]\033[0m'

log_info() { echo -e "${C_INFO} $1"; }
log_success() { echo -e "${C_SUCCESS} $1"; }
log_warn() { echo -e "${C_WARN} $1"; }

# Vérification des privilèges root
if [[ $EUID -ne 0 ]]; then
   echo -e "\033[1;31m[ERREUR]\033[0m Ce script doit être exécuté en tant que root." >&2
   exit 1
fi

log_info "Début du déploiement de Vaultaire Client..."

# 1. Installation des dépendances
log_info "Installation des prérequis système..."
dnf install -y -q libxcrypt-compat

# 2. Déplacement et préparation des fichiers
log_info "Mise en place des binaires, bibliothèques et configurations..."
mkdir -p /opt/vaultaire/vaultaire_client \
         /etc/vaultaire_client/.ssh \
         /var/log/vaultaire \
         /usr/lib64/security \
         /lib64

chmod 700 /var/log/vaultaire

# Déplacement sécurisé (si les fichiers source existent)
[[ -f /opt/vaultaire/vaultaire_client/pam_login_custom_module.so ]] && mv -f /opt/vaultaire/vaultaire_client/pam*.so /usr/lib64/security/
[[ -f /opt/vaultaire/vaultaire_client/vaultaire_client ]] && mv -f /opt/vaultaire/vaultaire_client/vaultaire_client /usr/bin/
[[ -f /opt/vaultaire/client_software.yaml ]] && mv -f /opt/vaultaire/client_software.yaml /etc/vaultaire_client/.ssh/
[[ -f /opt/vaultaire/vaultaire_client/libnss_vaultaire.so.2 ]] && mv -f /opt/vaultaire/vaultaire_client/libnss_vaultaire.so.2 /lib64/
compgen -G "/opt/vaultaire/*.pem" > /dev/null && mv -f /opt/vaultaire/*.pem /etc/vaultaire_client/.ssh/

# Empreinte de la clé publique du core.
#
# Elle arrive par ce canal — SCP au-dessus de SSH — et non par le réseau
# Ducky : c'est tout l'intérêt. L'agent compare la clé qu'il recevra plus tard
# par la trame « askkey » à cette empreinte, et refuse si elles diffèrent.
#
# Sans ce fichier, l'agent accepte la première clé venue, en le signalant dans
# son journal. Le déploiement reste donc possible sans, mais moins sûr.
[[ -f /opt/vaultaire/core_key_fingerprint ]] && mv -f /opt/vaultaire/core_key_fingerprint /etc/vaultaire_client/.ssh/

# Clé du core héritée d'une installation précédente.
#
# Ce script n'efface pas /etc/vaultaire_client/.ssh : une réinstallation sur une
# machine déjà enrôlée y retrouve donc le serveurpublickey.pem d'avant. Si le
# core a été réinstallé entre-temps — base recréée, donc nouvelle paire de clés —
# ce fichier est périmé.
#
# Une clé périmée ne produit pas d'erreur claire : l'agent chiffre sa poignée de
# main avec, le core ne sait pas la déchiffrer, ne répond pas, et l'agent finit
# par signaler « Erreur lors de la lecture du header : EOF ». Rien n'y désigne la
# clé, et le diagnostic peut prendre des heures.
#
# On la supprime donc quand une empreinte vient d'être déposée. L'agent la
# redemandera au core au premier contact, et la comparera à cette empreinte :
# la reprise est sûre, puisqu'une clé qui ne correspond pas sera refusée.
#
# Sans empreinte déposée, on ne touche à rien : on n'aurait alors rien pour
# valider la clé de remplacement.
if [[ -f /etc/vaultaire_client/.ssh/core_key_fingerprint ]]; then
    rm -f /etc/vaultaire_client/.ssh/serveurpublickey.pem
    log_info "Clé du core éventuellement héritée supprimée : elle sera redemandée puis vérifiée contre l'empreinte."
fi

# Application stricte des permissions
chmod 755 /lib64/libnss_vaultaire.so.2
chmod 750 /usr/bin/vaultaire_client
chmod 700 -R /etc/vaultaire_client/
find /etc/vaultaire_client/.ssh/ -type f -exec chmod 400 {} +

for mod in pam_login_custom_module.so pam_logout_custom_module.so pam_ssh_auth_module.so; do
    if [[ -f /usr/lib64/security/$mod ]]; then
        chmod 755 /usr/lib64/security/$mod
        chown root:root /usr/lib64/security/$mod
    fi
done

# 3. Service Systemd
log_info "Création du service Systemd..."
cat > /etc/systemd/system/vaultaire_client.service <<'EOF'
[Unit]
Description=Vaultaire Client Service
After=network.target

[Service]
User=root
Group=root
ExecStart=/usr/bin/vaultaire_client
WorkingDirectory=/etc/vaultaire_client
Environment=USER=root
LimitNOFILE=4096
Restart=on-failure

[Install]
WantedBy=multi-user.target
EOF

# 4. Configuration JSON du client
log_info "Écriture du fichier de configuration client..."
cat > /etc/vaultaire_client/client_conf.json <<'EOF'
{
  "servers": [
    {
      "ip": "192.168.30.3",
      "port": 6666
    }
  ]
}
EOF

# 4bis. Rotation du journal
#
# Sans ce fichier, /var/log/vaultaire/vaultaire_client.log grossit
# indéfiniment. Sur une machine isolée on s'en apercevrait ; sur un parc,
# personne ne voit grossir un fichier — jusqu'au jour où /var est plein sur des
# dizaines de postes à la fois.
#
# Aucune ligne de code de rotation n'est nécessaire : l'agent rouvre son journal
# PAR SON CHEMIN à chaque ligne, donc le renommage que fait logrotate est suivi
# tout seul. Pas de copytruncate, pas de signal, pas de redémarrage du service.
#
# ⚠ COPIE. L'original est deployments/logrotate/vaultaire-client, avec les
# commentaires complets. Ce script est autonome — il tourne sur une machine qui
# n'a pas le dépôt — d'où la duplication, comme pour l'unité systemd ci-dessus.
log_info "Installation de la rotation des journaux..."
cat > /etc/logrotate.d/vaultaire-client <<'EOF'
/var/log/vaultaire/vaultaire_client.log {
    daily
    rotate 30
    compress
    delaycompress
    maxsize 20M
    missingok
    notifempty
    create 0600 root root
    sharedscripts
}
EOF
chmod 644 /etc/logrotate.d/vaultaire-client

# Un ancien répertoire, écrit en dur par une version antérieure du socle et
# couvert par aucune rotation. Retiré s'il est vide ; signalé sinon, plutôt que
# supprimé — il peut contenir la trace d'un incident qu'on cherche encore.
if [[ -d /var/log/vaultaire_client ]]; then
    if rmdir /var/log/vaultaire_client 2>/dev/null; then
        log_info "Ancien répertoire /var/log/vaultaire_client retiré (vide)."
    else
        log_info "ATTENTION : /var/log/vaultaire_client contient des fichiers d'une"
        log_info "            version antérieure. Aucune rotation ne les couvre."
    fi
fi

# 5. Configuration NSS (Idempotente)
log_info "Configuration de NSS..."
for db in passwd group; do
    if ! grep -qE "^${db}:.*\\bvaultaire\\b" /etc/nsswitch.conf; then
        sed -i "/^${db}:/ s/$/ vaultaire/" /etc/nsswitch.conf
    fi
done

# 6. Configuration SSHD propre et anti-doublons
log_info "Configuration sécurisée de SSHD..."
SSHD_CONF="/etc/ssh/sshd_config"

# Nettoyage des directives existantes pour éviter les conflits
for directive in UsePAM KbdInteractiveAuthentication ChallengeResponseAuthentication AuthenticationMethods PubkeyAuthentication Include AuthorizedKeysCommand AuthorizedKeysCommandUser; do
    sed -i "/^${directive}/d" "$SSHD_CONF"
done

# Ré-injection propre
cat >> "$SSHD_CONF" <<'EOF'
UsePAM yes
PubkeyAuthentication yes
KbdInteractiveAuthentication yes
ChallengeResponseAuthentication yes
AuthenticationMethods publickey,keyboard-interactive
AuthorizedKeysCommand /usr/bin/vaultaire_client --fetch-key %u
AuthorizedKeysCommandUser root
Include /etc/ssh/sshd_config.d/*.conf
EOF

# Désactivation propre dans les fichiers d'inclusion (.conf)
if [ -d /etc/ssh/sshd_config.d/ ]; then
    sed -i 's/^\(KbdInteractiveAuthentication\|PasswordAuthentication\).*/#\0 disabled_by_vaultaire/' /etc/ssh/sshd_config.d/*.conf 2>/dev/null || true
fi

# 7. Configuration PAM (Login)
log_info "Mise en place de la pile PAM (login)..."
cat > /etc/pam.d/login <<'EOF'
#%PAM-1.0
auth        [success=done ignore=ignore default=die]    pam_login_custom_module.so
auth        substack       system-auth
auth        include        postlogin

account     required       pam_nologin.so
account     include        system-auth

password    include        system-auth

session     required       pam_selinux.so close
session     required       pam_loginuid.so
session     required       pam_selinux.so open
session     required       pam_logout_custom_module.so
session     required       pam_namespace.so
session     optional       pam_keyinit.so force revoke
session     include        system-auth
session     include        postlogin
-session    optional       pam_ck_connector.so
EOF

# 8. Configuration PAM (GDM / Graphique) si présent
if [ -f /etc/pam.d/gdm-password ]; then
    log_info "Configuration de GDM (Interface graphique)..."
    cat > /etc/pam.d/gdm-password <<'EOF'
#%PAM-1.0
auth        [success=done ignore=ignore default=bad]    pam_login_custom_module.so
auth        [success=done ignore=ignore default=bad]    pam_selinux_permit.so
auth        substack       password-auth
auth        optional       pam_gnome_keyring.so
auth        include        postlogin

account     required       pam_nologin.so
account     include        password-auth

password    substack       password-auth
-password   optional       pam_gnome_keyring.so use_authtok

session     required       pam_selinux.so close
session     required       pam_loginuid.so
session     optional       pam_console.so
-session    optional       pam_ck_connector.so
session     required       pam_selinux.so open
session     required       pam_logout_custom_module.so
session     optional       pam_keyinit.so force revoke
session     required       pam_namespace.so
session     include        password-auth
session     optional       pam_gnome_keyring.so auto_start
session     include        postlogin
EOF

    mkdir -p /etc/dconf/db/gdm.d
    cat > /etc/dconf/db/gdm.d/10-vaultaire-userlist <<'EOF'
[org/gnome/login-screen]
disable-user-list=true
EOF
    dconf update 2>/dev/null || true
    log_success "PAM GDM configuré avec succès."
else
    log_info "GDM absent, pile PAM graphique ignorée."
fi

# 9. Configuration PAM (SSHD)
log_info "Mise en place de la pile PAM (sshd)..."
cat > /etc/pam.d/sshd <<'EOF'
#%PAM-1.0
auth        [success=done ignore=ignore default=die]    pam_ssh_auth_module.so
auth        substack       password-auth
auth        include        postlogin

account     required       pam_nologin.so
account     include        password-auth

session     required       pam_selinux.so close
session     required       pam_loginuid.so
session     required       pam_selinux.so open env_params
session     required       pam_namespace.so
session     optional       pam_keyinit.so force revoke
session     optional       pam_motd.so
session     include        password-auth
session     include        postlogin
EOF

# Sécurisation des permissions PAM
chmod 644 /etc/pam.d/*

# 10. Nettoyage des sources d'installation temporaires
log_info "Nettoyage des fichiers temporaires..."
rm -rf /opt/vaultaire

# 11. Activation et redémarrage des services
log_info "Activation du service systemd et rechargement de SSHD..."
systemctl daemon-reload
systemctl enable --now vaultaire_client.service
systemctl reload sshd

log_success "Installation de Vaultaire Client terminée avec succès !"