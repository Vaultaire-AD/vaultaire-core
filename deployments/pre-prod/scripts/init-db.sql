-- Création de la base de données pour Keycloak
CREATE DATABASE IF NOT EXISTS keycloak;

-- Création de l'utilisateur avec le mot de passe de ton docker-compose
CREATE USER IF NOT EXISTS 'keycloak'@'%' IDENTIFIED BY 'root';

-- Attribution des droits
GRANT ALL PRIVILEGES ON keycloak.* TO 'keycloak'@'%';

FLUSH PRIVILEGES;
