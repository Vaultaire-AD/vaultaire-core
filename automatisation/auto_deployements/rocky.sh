#!/bin/bash

set -euo pipefail

echo "🔧 Déploiement Vaultaire Client..."


dnf install -y libxcrypt-compat
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
echo "Include /etc/ssh/sshd_config.d/*.conf" >> "/etc/ssh/sshd_config"

# ---------------------------------------------------------------------------
# PAM login — connexion sur console/tty (programme /bin/login)
# ---------------------------------------------------------------------------
#
# Drapeau de contrôle : [success=done ignore=ignore default=die], le même que
# pour sshd, et NON « required ».
#
#   success=done  utilisateur Vaultaire authentifié  -> on s'arrête, succès
#   ignore=ignore utilisateur local (le module rend PAM_IGNORE) -> on continue
#                 vers system-auth, qui authentifie les comptes locaux
#   default=die   utilisateur Vaultaire refusé       -> on s'arrête, échec
#
# La version précédente utilisait « required » avec system-auth commenté :
# un compte local, root compris, ne pouvait alors plus se connecter en console,
# puisque le seul module de la pile rendait PAM_IGNORE et qu'aucun autre ne
# prenait le relais. C'est un risque de verrouillage sur une machine sans SSH.
cat > /etc/pam.d/login <<'EOF'
#%PAM-1.0
# --- AUTHENTICATION ---
auth       [success=done ignore=ignore default=die]   pam_login_custom_module.so
auth       substack     system-auth
auth       include      postlogin

# --- ACCOUNT ---
account    required     pam_nologin.so
account    include      system-auth

# --- PASSWORD ---
password   include      system-auth

# --- SESSION ---
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

# ---------------------------------------------------------------------------
# PAM gdm-password — connexion graphique GNOME
# ---------------------------------------------------------------------------
#
# GDM n'utilise PAS /etc/pam.d/login : la connexion graphique a sa propre pile.
# Sans ce fichier, le module Vaultaire n'est jamais appelé depuis l'interface
# graphique — aucune requête n'arrive au daemon, ce qui donne exactement
# l'impression d'un module qui ne se charge pas.
#
# Le fichier n'est écrit que si GDM est présent : l'installer sur une machine
# sans environnement graphique créerait une pile PAM pour un service inexistant.
if [ -f /etc/pam.d/gdm-password ]; then

cat > /etc/pam.d/gdm-password <<'EOF'
#%PAM-1.0
# --- AUTHENTICATION ---
# pam_selinux_permit doit rester en tête : il autorise la connexion en mode
# permissif après un échec de relabel SELinux, avant toute autre décision.
auth       [success=done ignore=ignore default=bad]   pam_login_custom_module.so
auth       [success=done ignore=ignore default=bad]   pam_selinux_permit.so
auth       substack     password-auth
auth       optional     pam_gnome_keyring.so
auth       include      postlogin

# --- ACCOUNT ---
account    required     pam_nologin.so
account    include      password-auth

# --- PASSWORD ---
password   substack     password-auth
-password  optional     pam_gnome_keyring.so use_authtok

# --- SESSION ---
session    required     pam_selinux.so close
session    required     pam_loginuid.so
session    optional     pam_console.so
-session   optional     pam_ck_connector.so
session    required     pam_selinux.so open
session    required     pam_logout_custom_module.so
session    optional     pam_keyinit.so force revoke
session    required     pam_namespace.so
session    include      password-auth
session    optional     pam_gnome_keyring.so auto_start
session    include      postlogin
EOF

    # GDM n'affiche que les comptes locaux existants. Un utilisateur Vaultaire
    # qui ne s'est jamais connecté sur cette machine n'apparaît donc dans aucune
    # liste : il faut « Non répertorié ? » pour saisir son identifiant. Sans
    # cette option, l'utilisateur conclut que son compte n'existe pas.
mkdir -p /etc/dconf/db/gdm.d
cat > /etc/dconf/db/gdm.d/10-vaultaire-userlist <<'EOF'
# Genere par Vaultaire.
# Masque la liste des comptes locaux : les comptes Vaultaire n'y figurent pas
# tant qu'ils ne se sont pas connectes au moins une fois sur cette machine.
[org/gnome/login-screen]
disable-user-list=true
EOF
    dconf update 2>/dev/null || true

    echo "✅ PAM GDM configuré (connexion graphique)"
else
    echo "ℹ️  GDM absent, pile PAM graphique non configurée"
fi

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

