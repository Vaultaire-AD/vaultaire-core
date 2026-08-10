# Déploiement conteneurisé

Deux piles Compose sont fournies. **Il n'y a pas de manifeste Kubernetes** dans
le dépôt aujourd'hui.

---

## Développement

Le code source est **monté** dans le conteneur : l'image ne contient pas
l'application, et un changement de code ne demande qu'un redémarrage.

```bash
./deployments/dev/up.sh
```

| | |
| --- | --- |
| Fichier | [`deployments/dev/docker-compose.yml`](../../deployments/dev/docker-compose.yml) |
| Services | `vaultaire-dev`, `vaultaire-db` (MariaDB), `vaultaire-keycloak` |
| Après un changement de code | `docker compose -f deployments/dev/docker-compose.yml restart vaultaire-dev` |
| Lancer la suite de tests | `docker compose -f deployments/dev/docker-compose.yml run --rm vaultaire-dev go run ./main --test` |

Un conteneur Rocky avec `sshd`, pour éprouver le chemin PAM de bout en bout,
est présent mais commenté dans le Compose — voir `Dockerfile.rocky-ssh` et
`test-pam-login.sh`.

---

## Préproduction

**Environnement de test, pas de production.** Les binaires sont compilés sur le
poste de développement, transférés par `rsync` et montés en volume : l'image ne
contient aucun binaire applicatif et ne se reconstruit que si le `Dockerfile`
change.

```bash
# Depuis le poste de développement, à la racine du dépôt
PREPROD_HOST=root@192.168.30.3 ./deployments/pre-prod/deploy.sh
```

Ou localement :

```bash
./deployments/pre-prod/docker-build-and-up.sh
# depuis PowerShell
.\deployments\pre-prod\docker-build-and-up.ps1
```

| | |
| --- | --- |
| Fichier | [`deployments/pre-prod/docker-compose.yml`](../../deployments/pre-prod/docker-compose.yml) |
| Services | `vaultaire-ad`, `vaultaire-db`, `vaultaire-keycloak` |
| Proxy | pile séparée, [`deployments/pre-prod/vlt-proxy/`](../../deployments/pre-prod/vlt-proxy/) |
| Détail | [`deployments/pre-prod/README.md`](../../deployments/pre-prod/README.md) |

### Ports publiés

| Port | Service |
| --- | --- |
| 6666 | Ducky Network |
| 4443 | Portail web (HTTPS) |
| 6643 | API REST (HTTPS) |
| 389 / 636 | LDAP / LDAPS |
| 3306 | MariaDB |
| 8080 | Keycloak (optionnel) |

---

## Points d'attention

> ⚠️ **Un changement de gabarit ou de fichier statique n'est visible qu'après
> `auto-compil.sh`.** Le script recopie `web_packet/` dans `cmd/web_packet/`, et
> c'est cette copie que sert le binaire déployé.

> ⚠️ **Les images de base sont épinglées sur `latest`** (`mariadb:latest`,
> `keycloak:latest`). Deux déploiements à deux dates peuvent donc ne pas donner
> la même pile.

> ⚠️ La configuration de référence
> [`deployments/configs/serveur_conf.yaml`](../../deployments/configs/serveur_conf.yaml)
> contient des identifiants de démonstration (`root`/`root`, `admin`/`admin123`).
> Ils doivent être changés avant toute exposition, y compris en préproduction.

---

## Kubernetes

Non fourni. Les éléments nécessaires existent — image sans état, configuration
par fichier YAML et variables d'environnement, sondes possibles sur les ports
HTTP — mais aucun manifeste, chart ou opérateur n'est maintenu ici.
