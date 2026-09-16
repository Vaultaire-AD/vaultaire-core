#!/bin/bash
# Installe et teste le module PAM "login" (pam_login_custom_module.so) dans le
# conteneur rocky-ssh-dev, via pamtester, sans passer par un vrai login
# interactif (console/getty). À lancer DANS le conteneur rocky-ssh-dev :
#
#   docker compose -f deployments/dev/docker-compose.yml exec rocky-ssh bash /tmp/test-pam-login.sh <username>
#
# Prérequis : le service rocky-ssh du docker-compose doit monter
# cmd/vaultaire_client (qui contient les .so déjà compilés par auto_compil.sh)
# sur /tmp, et ce script doit lui aussi être accessible dans /tmp (copie-le
# à côté, ou monte tout le dossier deployments/dev).
set -euo pipefail

USERNAME="${1:-root}"
SERVICE=vaultairelogin   # service PAM dédié au test, ne touche pas /etc/pam.d/login

echo "🔧 Installation du module dans /usr/lib64/security/ ..."
cp -f /tmp/pam_login_custom_module.so /usr/lib64/security/
chmod 755 /usr/lib64/security/pam_login_custom_module.so

echo "📁 Création du dossier de logs (bug historique : sans ce dossier, le module tourne mais ne log jamais nulle part) ..."
mkdir -p /var/log/vaultaire
chmod 755 /var/log/vaultaire

echo "🧩 Écriture du service PAM de test /etc/pam.d/${SERVICE} ..."
cat > /etc/pam.d/${SERVICE} <<EOF
#%PAM-1.0
auth       required     pam_login_custom_module.so
account    required     pam_permit.so
EOF

echo "🚀 Test via pamtester (service=${SERVICE}, user=${USERNAME}) ..."
echo "   -> Le mot de passe demandé est celui envoyé au daemon vaultaire_client (socket ${VAULTAIRE_SOCKET_PATH:-/tmp/vaultaire_client.sock})."
pamtester -v ${SERVICE} "${USERNAME}" authenticate || true

echo
echo "📜 Dernières lignes de /var/log/vaultaire/vaultaire_pam.log :"
tail -n 20 /var/log/vaultaire/vaultaire_pam.log 2>/dev/null || echo "   (toujours vide/absent -> le module n'a pas écrit du tout, regarder pam_sm_authenticate / dlopen)"
