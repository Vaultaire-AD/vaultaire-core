#!/bin/bash
# Compte base dédié à l'interface web (src/vaultaire_web).
#
# POURQUOI UN COMPTE SÉPARÉ. Le web est sorti du serveur central : il n'a plus
# accès à l'annuaire qu'à travers des commandes, sauf pour le chemin
# d'authentification. Tant que cette frontière n'est qu'une règle de code, la
# compromission du web donne l'écriture directe sur toute la base. Avec ce
# compte, la frontière est imposée par le moteur.
#
# POURQUOI PAS « READ ONLY ». L'enrôlement du second facteur écrit :
# StartMFAEnrollment pose le secret, ActivateMFA lève le drapeau, et
# ConsumeMFACounter avance le compteur anti-rejeu à chaque connexion. Un compte
# en lecture pure rendrait le MFA inutilisable. Le périmètre juste est donc
# « lecture sur quatre tables, écriture sur quatre colonnes nommées d'une seule ».
#
# POURQUOI UN .sh ET PAS UN .sql. docker-entrypoint-initdb.d exécute aussi les
# scripts shell, ce qui permet de lire le mot de passe depuis l'environnement.
# Un .sql versionné obligerait à figer le mot de passe dans le dépôt — ce que
# fait init-db.sql pour Keycloak, acceptable en développement, à ne pas
# reproduire pour un compte qui lit des empreintes de mots de passe.
#
# ⚠️ CE SCRIPT NE S'EXÉCUTE QU'À L'INITIALISATION D'UN VOLUME VIDE.
# vaultaire_db_data est un volume nommé persistant : une installation déjà en
# service ne verra jamais ce fichier. Les mêmes instructions sont rappelées en
# fin de script pour être passées à la main sur une base existante.

set -euo pipefail

DB_NAME="${MARIADB_DATABASE:-vaultaire}"
WEB_USER="${VAULTAIRE_WEB_DB_USER:-web-vaultaire}"
WEB_PASSWORD="${VAULTAIRE_WEB_DB_PASSWORD:-}"

if [ -z "$WEB_PASSWORD" ]; then
    echo "init-web-user: VAULTAIRE_WEB_DB_PASSWORD non défini — compte web non créé." >&2
    echo "init-web-user: l'interface web ne pourra pas se connecter à la base." >&2
    # On sort en succès : une base sans interface web reste une base utilisable,
    # et faire échouer l'initialisation entière pour un service optionnel
    # empêcherait le serveur central de démarrer.
    exit 0
fi

mysql --protocol=socket -uroot -p"${MARIADB_ROOT_PASSWORD}" <<SQL
CREATE USER IF NOT EXISTS '${WEB_USER}'@'%' IDENTIFIED BY '${WEB_PASSWORD}';

-- Lecture : exactement les tables du chemin d'authentification.
--   users           sel et empreinte du mot de passe, colonnes MFA
--   groups          mfa_required
--   users_group     appartenance, pour résoudre mfa_required d'un compte
--   server_settings politique d'expiration des mots de passe
GRANT SELECT ON \`${DB_NAME}\`.users           TO '${WEB_USER}'@'%';
GRANT SELECT ON \`${DB_NAME}\`.groups          TO '${WEB_USER}'@'%';
GRANT SELECT ON \`${DB_NAME}\`.users_group     TO '${WEB_USER}'@'%';
GRANT SELECT ON \`${DB_NAME}\`.server_settings TO '${WEB_USER}'@'%';

-- Écriture : les quatre colonnes du second facteur, et rien d'autre.
-- Le changement de mot de passe passe par une commande (07), pas par ici.
GRANT UPDATE (mfa_secret, mfa_enabled, mfa_enrolled_at, mfa_last_counter)
      ON \`${DB_NAME}\`.users TO '${WEB_USER}'@'%';

FLUSH PRIVILEGES;
SQL

echo "init-web-user: compte '${WEB_USER}' créé sur '${DB_NAME}'."

# ---------------------------------------------------------------------------
# BASE DÉJÀ EN SERVICE — à passer à la main, en root :
#
#   CREATE USER IF NOT EXISTS 'web-vaultaire'@'%' IDENTIFIED BY '<mot de passe>';
#   GRANT SELECT ON vaultaire.users           TO 'web-vaultaire'@'%';
#   GRANT SELECT ON vaultaire.groups          TO 'web-vaultaire'@'%';
#   GRANT SELECT ON vaultaire.users_group     TO 'web-vaultaire'@'%';
#   GRANT SELECT ON vaultaire.server_settings TO 'web-vaultaire'@'%';
#   GRANT UPDATE (mfa_secret, mfa_enabled, mfa_enrolled_at, mfa_last_counter)
#         ON vaultaire.users TO 'web-vaultaire'@'%';
#   FLUSH PRIVILEGES;
#
# Vérification du périmètre obtenu :
#   SHOW GRANTS FOR 'web-vaultaire'@'%';
# ---------------------------------------------------------------------------
