#!/bin/bash

set -euo pipefail

echo "🔧 Déploiement Vaultaire Client..."

# Déplacement des fichiers
mv -f /opt/vaultaire/vaultaire_client/pam*.so /usr/lib64/security/
mkdir -p /opt/vaultaire_client/.ssh
mv /opt/vaultaire/vaultaire_client/vaultaire_client /opt/vaultaire_client/
mv /opt/vaultaire/client_software.yaml /opt/vaultaire_client/.ssh/client_software.yaml
mv /opt/vaultaire/*.pem /opt/vaultaire_client/.ssh/

# Permissions
chmod 700 -R /opt/vaultaire_client/
chmod 400 -R /opt/vaultaire_client/.ssh/*
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
ExecStart=/opt/vaultaire_client/vaultaire_client
WorkingDirectory=/opt/vaultaire_client
Environment=USER=root
LimitNOFILE=4096
PrivateTmp=false
ProtectSystem=full
ReadOnlyPaths=/etc /usr /lib /bin
ReadWritePaths=/tmp

[Install]
WantedBy=multi-user.target
EOF

# Configuration client
cat > /opt/vaultaire_client/client_conf.yaml <<'EOF'
serveurlistenport: 6666
serveur_ip: vaultaire-ad1.vaultaire.local
EOF

# Force le MFA : Clé SSH + Mot de passe (via PAM)
# On utilise sed pour modifier les lignes existantes ou on les ajoute à la fin
sed -i 's/^#\(UsePAM\) .*/\1 yes/' /etc/ssh/sshd_config
sed -i 's/^\(UsePAM\) .*/\1 yes/' /etc/ssh/sshd_config

sed -i 's/^#\(KbdInteractiveAuthentication\) .*/\1 yes/' /etc/ssh/sshd_config
sed -i 's/^\(KbdInteractiveAuthentication\) .*/\1 yes/' /etc/ssh/sshd_config

# Ajout des méthodes d'authentification combinées (MFA)
if ! grep -q "AuthenticationMethods" /etc/ssh/sshd_config; then
    echo "AuthenticationMethods publickey,keyboard-interactive" >> /etc/ssh/sshd_config
else
    sed -i 's/^.*AuthenticationMethods.*/AuthenticationMethods publickey,keyboard-interactive/' /etc/ssh/sshd_config
fi


# PAM system-auth
# cat > /etc/pam.d/system-auth <<'EOF'
# #%PAM-1.0
# # This file is auto-generated.
# # User changes will be destroyed the next time authselect is run.
# #auth        required      pam_env.so
# #auth        sufficient    pam_unix.so try_first_pass nullok
# #auth        required      pam_deny.so
# auth        required      pam_login_custom_module.so
# account     required      pam_unix.so

# password    requisite     pam_pwquality.so try_first_pass local_users_only retry=3 authtok_type=
# password    sufficient    pam_unix.so try_first_pass use_authtok nullok sha512 shadow
# password    required      pam_deny.so

# session     optional      pam_keyinit.so revoke
# session     required      pam_limits.so
# -session     optional      pam_systemd.so
# session     [success=1 default=ignore] pam_succeed_if.so service in crond quiet use_uid
# session     required      pam_unix.so
# EOF

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
# TON MODULE SSH CUSTOM (exécuté AVANT l'auth par clé)
auth     required    pam_ssh_auth_module.so
auth       substack     password-auth
auth       include      postlogin
account    required     pam_sepermit.so
account    required     pam_nologin.so
account    include      password-auth
password   include      password-auth
# pam_selinux.so close should be the first session rule
session    required     pam_selinux.so close
session    required     pam_loginuid.so
# pam_selinux.so open should only be followed by sessions to be executed in the user context
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

