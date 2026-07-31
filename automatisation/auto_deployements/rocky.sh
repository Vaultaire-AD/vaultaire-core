#!/bin/bash

set -euo pipefail

echo "🔧 Déploiement Vaultaire Client..."

# Déplacement des fichiers
mv -f /opt/vaultaire/vaultaire_client/pam*.so /usr/lib64/security/
mkdir -p /etc/vaultaire_client/.ssh

# Dossier de logs des modules PAM (pam_common.c écrit dans
# /var/log/vaultaire/vaultaire_pam.log). Sans ça, fopen() échoue en
# silence et les modules tournent sans jamais rien logger nulle part —
# ça ressemble à un module qui ne se charge pas alors qu'il tourne bien.
mkdir -p /var/log/vaultaire
chmod 700 /var/log/vaultaire
mv /opt/vaultaire/vaultaire_client/vaultaire_client /usr/bin/
mv /opt/vaultaire/client_software.yaml /etc/vaultaire_client/.ssh/client_software.yaml
mv /opt/vaultaire/*.pem /etc/vaultaire_client/.ssh/

mv /opt/vaultaire/vaultaire_client/libnss_vaultaire.so.2 /lib64/
chmod 755 /lib64/libnss_vaultaire.so.2
chmod 750 /usr/bin/vaultaire_client

# Permissions
chmod 700 -R /etc/vaultaire_client/
chmod 400 -R /etc/vaultaire_client/.ssh/*
chmod 755 /usr/lib64/security/pam_login_custom_module.so
chmod 755 /usr/lib64/security/pam_logout_custom_module.so
chmod 755 /usr/lib64/security/pam_ssh_auth_module.so
chown root:root /usr/lib64/security/pam_login_custom_module.so
chown root:root /usr/lib64/security/pam_logout_custom_module.so
chown root:root /usr/lib64/security/pam_ssh_auth_module.so

# Service systemd
cat > /etc/systemd/system/vaultaire_client.service <<'EOF'
[Unit]
Description=Vaultaire_Client Service
After=network.target

[Service]
User=root
Group=root
ExecStart=/usr/bin/vaultaire_client
WorkingDirectory=/etc/vaultaire_client
Environment=USER=root
LimitNOFILE=4096

[Install]
WantedBy=multi-user.target
EOF

# Configuration client
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


echo "🔗 Configuration NSS..."
sed -i '/^passwd:/ s/$/ vaultaire/' /etc/nsswitch.conf
sed -i '/^group:/ s/$/ vaultaire/' /etc/nsswitch.conf
# On s'assure de supprimer les doublons si le script est lancé deux fois
sed -i 's/vaultaire vaultaire/vaultaire/g' /etc/nsswitch.conf

# 5. Configuration SSHD (Nettoyage agressif des doublons et conflits)
echo "Configure SSHD MFA..."

# On utilise un fichier temporaire pour reconstruire une config propre sans doublons
SSHD_CONF="/etc/ssh/sshd_config"

# Désactiver les paramètres conflictuels dans TOUS les fichiers d'inclusion (.conf)
# Désactiver les paramètres conflictuels proprement
[ -d /etc/ssh/sshd_config.d/ ] && sed -i 's/^\(KbdInteractiveAuthentication\|PasswordAuthentication\).*/#\0 disabled_by_vaultaire/' /etc/ssh/sshd_config.d/*.conf 2>/dev/null || true

# Ajout du Fetch Dynamique de clés
sed -i '/^AuthorizedKeysCommand/d' "/etc/ssh/sshd_config"
sed -i '/^AuthorizedKeysCommandUser/d' "/etc/ssh/sshd_config"
echo "AuthorizedKeysCommand /usr/bin/vaultaire_client --fetch-key %u" >> "/etc/ssh/sshd_config"
echo "AuthorizedKeysCommandUser root" >> "/etc/ssh/sshd_config"

# Nettoyage du fichier principal pour éviter les doublons
sed -i '/^UsePAM/d' "/etc/ssh/sshd_config"
sed -i '/^KbdInteractiveAuthentication/d' "/etc/ssh/sshd_config"
sed -i '/^ChallengeResponseAuthentication/d' "/etc/ssh/sshd_config"
sed -i '/^AuthenticationMethods/d' "/etc/ssh/sshd_config"
sed -i '/^PubkeyAuthentication/d' "/etc/ssh/sshd_config"
sed -i '/^Include/d' "/etc/ssh/sshd_config"
# Ré-injection propre
echo "UsePAM yes" >> "/etc/ssh/sshd_config"
echo "PubkeyAuthentication yes" >> "/etc/ssh/sshd_config"
echo "KbdInteractiveAuthentication yes" >> "/etc/ssh/sshd_config"
echo "ChallengeResponseAuthentication yes" >> "/etc/ssh/sshd_config"
echo "AuthenticationMethods publickey,keyboard-interactive" >> "/etc/ssh/sshd_config"
echo "Include /etc/ssh/sshd_config.d/*.conf/d" >> "/etc/ssh/sshd_config"

# PAM login
cat > /etc/pam.d/login <<'EOF'
#%PAM-1.0
#auth       substack     system-auth
#auth       include      postlogin
auth       required     pam_login_custom_module.so
account    required     pam_nologin.so
account    include      system-auth
password   include      system-auth
# pam_selinux.so close should be the first session rule
session    required     pam_selinux.so close
session    required     pam_loginuid.so
# pam_selinux.so open should only be followed by sessions to be executed in the user context
session    required     pam_selinux.so open
session    required     pam_logout_custom_module.so
session    required     pam_namespace.so
session    optional     pam_keyinit.so force revoke
session    include      system-auth
session    include      postlogin
-session   optional     pam_ck_connector.so
EOF

# PAM sudo
# cat > /etc/pam.d/sudo <<'EOF'
# #%PAM-1.0
# #auth       include      system-auth
# #account    include      system-auth
# #password   include      system-auth
# #session    include      system-auth
# auth       required      pam_env.so
# auth       sufficient    pam_unix.so try_first_pass nullok
# auth       required      pam_deny.so

# account    required      pam_unix.so

# password   sufficient    pam_unix.so try_first_pass use_authtok nullok sha512 shadow
# password   required      pam_deny.so

# session    optional      pam_keyinit.so revoke
# session    required      pam_limits.so
# -session   optional      pam_systemd.so
# EOF

cat > /etc/pam.d/sshd <<'EOF'
#%PAM-1.0
# --- AUTHENTICATION ---


auth       [success=done ignore=ignore default=die]   pam_ssh_auth_module.so

# Ces lignes ne seront lues QUE si le module échoue (ex: mauvais mdp MFA)
auth       substack     password-auth
auth       include      postlogin

# --- ACCOUNT ---
account    required     pam_nologin.so
account    include      password-auth

# --- SESSION ---
session    required     pam_selinux.so close
session    required     pam_loginuid.so
session    required     pam_selinux.so open env_params
session    required     pam_namespace.so
session    optional     pam_keyinit.so force revoke
session    optional     pam_motd.so
session    include      password-auth
session    include      postlogin
EOF

# Permissions PAM
chmod 644 /etc/pam.d/*

# Nettoyage
rm -rf /opt/vaultaire

# Activation du service
systemctl daemon-reload
systemctl enable vaultaire_client.service
systemctl start vaultaire_client.service
echo "✅ Installation terminée."
systemctl reload sshd

