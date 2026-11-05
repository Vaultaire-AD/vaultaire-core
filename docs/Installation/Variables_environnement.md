[⌂ Accueil du dépôt](../../README.md) · [Index de la documentation](../README.md) · [Kubernetes](./Kubernetes.md)

# Configuration du core par variables d'environnement

*(2.3.)* Toute clé utile en conteneur de `serveur_conf.yaml` peut être donnée par
une variable `VAULTAIRE_*`. **La variable l'emporte sur le fichier.** C'est ce qui
permet de versionner la configuration (une ConfigMap dans un dépôt GitOps) et de
garder les secrets dans le gestionnaire de secrets de la plateforme.

## Les règles

- Une variable **absente** laisse le fichier décider.
- Une variable **posée mais vide** est une **erreur** et arrête le démarrage, en la
  nommant. C'est presque toujours une clé de Secret mal nommée : la laisser passer
  ferait tourner le core sur la valeur du fichier sans que personne ne le voie.
- Une valeur invalide (port hors de 1–65535, booléen illisible) arrête le
  démarrage, en nommant la variable.
- **Secrets** : chaque variable marquée 🔒 accepte la variante `NOM_FILE`, qui
  désigne un fichier dont le contenu est la valeur (la fin de ligne est retirée).
  C'est la convention des images officielles (MariaDB, Postgres) et des Secrets
  montés en volume : la valeur n'apparaît ni dans `docker inspect` ni dans
  `/proc/<pid>/environ`. Poser `NOM` **et** `NOM_FILE` est refusé.
- Les listes s'écrivent séparées par des virgules : `a.acme.lan, b.acme.lan`.
- Le core **refuse de démarrer** tant que les mots de passe de la base et du
  compte d'amorçage valent `CHANGEZ_MOI`, comme avec le fichier seul (TO-DO 99).

## Les variables

| Variable | Remplace | Exemple |
|---|---|---|
| `VAULTAIRE_CONFIG` | le chemin du fichier lui-même | `/etc/vaultaire/serveur_conf.yaml` |
| **Base de données** | | |
| `VAULTAIRE_DB_HOST` | `database.ip_database` | `mariadb.vaultaire.svc` |
| `VAULTAIRE_DB_PORT` | `database.port_database` | `3306` |
| `VAULTAIRE_DB_NAME` | `database.databaseName` | `vaultaire` |
| `VAULTAIRE_DB_USERNAME` 🔒 | `database.username` | `vaultaire` |
| `VAULTAIRE_DB_PASSWORD` 🔒 | `database.password` | — |
| **Compte d'amorçage** | | |
| `VAULTAIRE_ADMIN_USERNAME` 🔒 | `administrateur.username` | `admin` |
| `VAULTAIRE_ADMIN_PASSWORD` 🔒 | `administrateur.password` | — |
| `VAULTAIRE_ADMIN_PUBLIC_KEY` 🔒 | `administrateur.public_key` | `ssh-ed25519 AAAA…` |
| **Ports d'écoute** | | |
| `VAULTAIRE_DUCKY_PORT` | `serveurlistenport` | `6666` |
| `VAULTAIRE_LDAP_PORT` | `ldap.ldap_port` | `3389` |
| `VAULTAIRE_LDAPS_PORT` | `ldap.ldaps_port` | `3636` |
| `VAULTAIRE_WEB_PORT` | `website.website_port` | `4443` |
| `VAULTAIRE_API_PORT` | `api.api_port` | `6643` |
| `VAULTAIRE_DNS_PORT` | `dns.dns_port` (nouveau) | `5353` |
| `VAULTAIRE_DNS_ENABLE` | `dns.dns_enable` | `false` |
| **Certificats** | | |
| `VAULTAIRE_LDAPS_TLS_DNS_NAMES` | `ldap.ldaps_tls_dns_names` | `ldap.acme.lan,vaultaire` |
| `VAULTAIRE_LDAPS_TLS_IP_ADDRESSES` | `ldap.ldaps_tls_ip_addresses` | `10.0.0.10` |
| `VAULTAIRE_WEB_TLS_DNS_NAMES` | `website.web_tls_dns_names` | `sso.acme.lan` |
| `VAULTAIRE_WEB_TLS_IP_ADDRESSES` | `website.web_tls_ip_addresses` | `10.0.0.10` |
| `VAULTAIRE_WEB_TRUSTED_PROXIES` | `website.web_trusted_proxies` | `10.42.0.0/16` |
| **Répertoires** | | |
| `VAULTAIRE_DATA_DIR` | `file-path.clientconfpath` | `/var/lib/vaultaire/` |
| `VAULTAIRE_LOG_DIR` | `file-path.logpath` | `/var/log/vaultaire/` |
| `VAULTAIRE_SOCKET` | `file-path.socketpath` (lu aussi par `vaultaire_cli`) | `/run/vaultaire/vaultaire.sock` |
| `VAULTAIRE_SCRIPTS_DIR` | `automatisation.sh_folder_path` | `/opt/vaultaire/automatisation/` |
| `VAULTAIRE_AGENT_PACKAGE_DIR` | `automatisation.agent_package_path` (nouveau) | `/opt/vaultaire/vaultaire_client/` |
| `VAULTAIRE_WEB_PACKET` | racine des gabarits du portail | `/opt/vaultaire/web_packet/sso_WEB_page` |
| **Journal** | | |
| `VAULTAIRE_DEBUG` | `debug.debug` | `false` |
| `VAULTAIRE_LOG_FORMAT` | format de la sortie standard | `json` |

Les réglages plus fins (bornes LDAP, `mfa_bypass`, détail du journal par
sous-système…) restent dans le fichier : ce ne sont pas des secrets, et une
ConfigMap les porte très bien.

> ⚠️ **Kubernetes et les variables injectées.** Kubernetes injecte dans chaque pod
> `<SERVICE>_PORT`, `<SERVICE>_SERVICE_HOST`… pour chaque Service du namespace.
> Un Service nommé `vaultaire-ldap` produirait `VAULTAIRE_LDAP_PORT=tcp://…`, que le
> core refuserait. La chart pose `enableServiceLinks: false` ; faites de même dans
> un manifeste écrit à la main.

## Exemple — `docker run`

```bash
docker run -d --name vaultaire \
  --read-only --cap-drop ALL --security-opt no-new-privileges \
  --tmpfs /run/vaultaire:uid=65532,gid=65532,mode=0700 \
  --tmpfs /var/log/vaultaire:uid=65532,gid=65532,mode=0700 \
  -v vaultaire-data:/var/lib/vaultaire \
  -e VAULTAIRE_DB_HOST=db.acme.lan \
  -e VAULTAIRE_DB_PASSWORD_FILE=/run/secrets/db-password \
  -e VAULTAIRE_ADMIN_PASSWORD_FILE=/run/secrets/admin-password \
  -v ./secrets:/run/secrets:ro \
  -p 389:3389 -p 636:3636 -p 6666:6666 -p 443:4443 -p 6643:6643 \
  ghcr.io/vaultaire-ad/vaultaire-server:2.3.0
```
