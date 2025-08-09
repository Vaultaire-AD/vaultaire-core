#!/bin/bash

set -euo pipefail

echo "🔧 Déploiement Vaultaire Client..."

# Déplacement des fichiers
mv -f /opt/vaultaire/vaultaire_client/pam*.so /lib/x86_64-linux-gnu/security/
mkdir -p /opt/vaultaire_client/.ssh
mv /opt/vaultaire/vaultaire_client/vaultaire_client /opt/vaultaire_client/
mv /opt/vaultaire/client_software.yaml /opt/vaultaire_client/.ssh/client_software.yaml
mv /opt/vaultaire/*.pem /opt/vaultaire_client/.ssh/

# Permissions
chmod 700 -R /opt/vaultaire_client/
chmod 400 -R /opt/vaultaire_client/.ssh/*
chmod 644 /lib/x86_64-linux-gnu/security/pam_login_custom_module.so
chmod 644 /lib/x86_64-linux-gnu/security/pam_logout_custom_module.so
chown root:root /lib/x86_64-linux-gnu/security/pam_login_custom_module.so
chown root:root /lib/x86_64-linux-gnu/security/pam_logout_custom_module.so

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
serveurlistenport: 666
serveur_ip: 192.168.10.57
EOF

# PAM system-auth
cat > /etc/pam.d/login <<'EOF'
auth       optional   pam_faildelay.so delay=3000000
auth       required   pam_login_custom_module.so
auth       requisite  pam_nologin.so
session    [success=ok ignore=ignore module_unknown=ignore default=bad] pam_selinux.so close
session    required   pam_loginuid.so
session    optional   pam_motd.so motd=/run/motd.dynamic
session    optional   pam_motd.so noupdate
session    required   pam_env.so readenv=1
session    required   pam_env.so readenv=1 envfile=/etc/default/locale
session    required   pam_logout_custom_module.so
@include common-auth
auth       optional   pam_group.so
session    required   pam_limits.so
session    optional   pam_lastlog.so
session    optional   pam_mail.so standard
session    optional   pam_keyinit.so force revoke
@include common-account
@include common-session
@include common-passwordls
EOF

# PAM login
cat > /etc/pam.d/common-auth <<'EOF'
auth       required   pam_login_custom_module.so
auth       [success=2 default=ignore]   pam_unix.so nullok
auth       [success=1 default=ignore]   pam_sss.so use_first_pass
auth    requisite   pam_deny.so
auth    required    pam_permit.so
auth    optional    pam_cap.so
EOF

# PAM sudo
cat > /etc/pam.d/sudo <<'EOF'
#%PAM-1.0

auth       [success=2 default=ignore]   pam_unix.so nullok
auth       [success=1 default=ignore]   pam_sss.so use_first_pass
auth    requisite   pam_deny.so
auth    required    pam_permit.so
auth    optional    pam_cap.so

account required    pam_unix.so
account sufficient  pam_succeed_if.so user != root quiet
account required    pam_sss.so

session required pam_limits.so
session required pam_env.so readenv=1 user_readenv=0
session required pam_env.so envfile=/etc/default/locale user_readenv=0
session required pam_unix.so
session optional    pam_sss.so
session optional    pam_systemd.so
EOF

# Permissions PAM
chmod 644 /etc/pam.d/*

# Activation du service
systemctl daemon-reload
systemctl enable vaultaire_client.service
systemctl start vaultaire_client.service

# Nettoyage
rm -rf /opt/vaultaire

echo "✅ Installation terminée."
