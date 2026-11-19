[⌂ Accueil du dépôt](../../README.md) · [Index de la documentation](../../docs/README.md) · [Kubernetes](../../docs/Installation/Kubernetes.md) · [Variables d'environnement](../../docs/Installation/Variables_environnement.md)

# Déployer Vaultaire avec Docker *(2.3.2)*

Un core en production sur **un hôte Docker**, avec l'image publiée sur GHCR :
rootless, sans shell, système de fichiers en lecture seule, secrets par
fichiers. Pour un cluster, voir [`Kubernetes.md`](../../docs/Installation/Kubernetes.md) ; les piles
de `deployments/dev`, `dev-comp` et `pre-prod` sont des environnements de
**test**, pas ce qui suit.

> Procédure éprouvée le 17/11/2026 sur Ubuntu, Docker 29 et Compose 2.40.

---

## 1. Prérequis

- Docker ≥ 24 avec le plugin Compose (`docker compose version`).
- Les ports **443, 389, 636, 6643, 6666** libres sur l'hôte.
- Une adresse IP fixe (et si possible des noms DNS) pour le core : les postes
  et `vlt` s'y connectent, et les certificats la portent.

## 2. Vérifier l'image (recommandé)

L'image est signée par le workflow de release ; la signature se vérifie sans
clé :

```bash
docker run --rm gcr.io/projectsigstore/cosign:v2.4.1 verify \
  ghcr.io/vaultaire-ad/vaultaire-server@sha256:67eae26f9633364fc8ad7abe85c926562361d426246cb857bb710164b62caecb \
  --certificate-identity-regexp '^https://github.com/Vaultaire-AD/vaultaire-core/.github/workflows/release.yaml@' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com
```

Le digest de chaque version figure dans les notes de la release GitHub.

## 3. Les fichiers

```
/opt/vaultaire-docker/
├── compose.yaml
├── .env
└── secrets/
    ├── db-password
    └── admin-password
```

### `compose.yaml`

```yaml
name: vaultaire

services:
  db:
    image: docker.io/library/mariadb:11.4
    restart: unless-stopped
    environment:
      MARIADB_DATABASE: vaultaire
      MARIADB_USER: vaultaire
      MARIADB_PASSWORD_FILE: /run/secrets/db-password
      MARIADB_RANDOM_ROOT_PASSWORD: "yes"
    secrets: [db-password]
    volumes:
      - db-data:/var/lib/mysql
    networks: [interne]
    healthcheck:
      test: ["CMD", "healthcheck.sh", "--connect", "--innodb_initialized"]
      interval: 10s
      timeout: 5s
      retries: 10

  core:
    # Épinglée par digest : le tag est lisible, le digest fait foi.
    image: ghcr.io/vaultaire-ad/vaultaire-server:2.3.2@sha256:67eae26f9633364fc8ad7abe85c926562361d426246cb857bb710164b62caecb
    restart: unless-stopped
    depends_on:
      db:
        condition: service_healthy
    read_only: true
    cap_drop: [ALL]
    security_opt: ["no-new-privileges:true"]
    tmpfs:
      - /run/vaultaire:uid=65532,gid=65532,mode=0700
      - /var/log/vaultaire:uid=65532,gid=65532,mode=0700
    volumes:
      - core-data:/var/lib/vaultaire
    environment:
      VAULTAIRE_DB_HOST: db
      VAULTAIRE_DB_PASSWORD_FILE: /run/secrets/db-password
      VAULTAIRE_ADMIN_PASSWORD_FILE: /run/secrets/admin-password
      # Noms et adresse des certificats auto-signés — lus au PREMIER démarrage.
      VAULTAIRE_WEB_TLS_DNS_NAMES: ${VAULTAIRE_FQDN_WEB}
      VAULTAIRE_WEB_TLS_IP_ADDRESSES: ${VAULTAIRE_IP}
      VAULTAIRE_LDAPS_TLS_DNS_NAMES: ${VAULTAIRE_FQDN_LDAP}
      VAULTAIRE_LDAPS_TLS_IP_ADDRESSES: ${VAULTAIRE_IP}
    secrets: [db-password, admin-password]
    networks: [interne]
    ports:
      - "6666:6666"   # Ducky : agents et proxies
      - "389:3389"    # LDAP (bind avec mot de passe en clair refusé)
      - "636:3636"    # LDAPS
      - "443:4443"    # portail
      - "6643:6643"   # API : vlt, REST

volumes:
  db-data:
  core-data:

networks:
  interne:

secrets:
  db-password:
    file: ./secrets/db-password
  admin-password:
    file: ./secrets/admin-password
```

### `.env`

```bash
VAULTAIRE_IP=192.168.10.57
VAULTAIRE_FQDN_WEB=sso.acme.lan
VAULTAIRE_FQDN_LDAP=ldap.acme.lan
```

### Les secrets

```bash
cd /opt/vaultaire-docker
install -d -m 700 secrets
openssl rand -base64 24 | tr -d '/+=' > secrets/db-password
echo 'Un-Mot-De-Passe-Provisoire-42' > secrets/admin-password   # le vôtre
chmod 644 secrets/*
```

Compose monte ces fichiers tels quels : ils doivent être lisibles par le
compte du core (UID 65532) **et** par celui de MariaDB (UID 999), d'où le
`644`. C'est le répertoire `secrets/` (`700`, à root) qui les protège sur
l'hôte. Les mots de passe ne paraissent ni dans `docker inspect` ni dans les
journaux.

## 4. Démarrer

```bash
docker compose up -d
docker compose ps          # core et db : (healthy) au bout d'une trentaine de secondes
docker compose logs core | grep empreinte
```

Au premier démarrage, le core crée ses tables, génère ses clés et ses
certificats (rangés **en base**), et crée le compte `admin` avec le mot de
passe de `secrets/admin-password`. Ce mot de passe est **provisoire** : il se
change à la première connexion au portail, `https://<VAULTAIRE_IP>/`.

L'empreinte journalisée (`keymanagement: empreinte du core SHA256:…`) est
celle que les agents vérifient : notez-la.

## 5. Administrer

**Sur l'hôte**, par le CLI de l'image :

```bash
alias vaultaire='docker compose -f /opt/vaultaire-docker/compose.yaml exec core /opt/vaultaire/bin/vaultaire_cli'
vaultaire version
vaultaire create -g infra acme.lan
```

**Depuis un poste**, avec `vlt` (archive `vaultaire_ctl` de la release) :

```bash
# 1. Sur l'hôte : la clé SSH du poste, et le certificat de l'API
vaultaire add -u admin -k poste-admin "ssh-ed25519 AAAA…"
vaultaire certificate show api | sed -n '/BEGIN/,/END/p' > api-cert.pem
```

Sur le poste, `~/.vaultaire/config.json` (avec `api-cert.pem` à côté) :

```json
{
  "server": "https://192.168.10.57:6643",
  "username": "admin",
  "private_key": "/home/moi/.ssh/id_ed25519",
  "ca_certificate": "/home/moi/.vaultaire/api-cert.pem"
}
```

```bash
vlt status
vlt api GET /api/v1/users      # l'API REST : docs/Utilisation/API_REST.md
```

Le certificat de l'API porte déjà `VAULTAIRE_IP` et `VAULTAIRE_FQDN_WEB`. Pour
une autre adresse : `vaultaire certificate regenerate api --ip <IP>` (ou
`--dns <nom>`), puis `docker compose restart core`.

## 6. Vos propres certificats *(facultatif)*

Pour servir des certificats d'une PKI plutôt que les auto-signés : montez-les
en lecture seule et nommez-les — ils sont relus à chaud.

```yaml
  core:
    volumes:
      - core-data:/var/lib/vaultaire
      - ./tls:/run/secrets/vaultaire-tls:ro
    environment:
      VAULTAIRE_WEB_TLS_CERT_FILE: /run/secrets/vaultaire-tls/web/tls.crt
      VAULTAIRE_WEB_TLS_KEY_FILE: /run/secrets/vaultaire-tls/web/tls.key
      VAULTAIRE_LDAPS_TLS_CERT_FILE: /run/secrets/vaultaire-tls/ldaps/tls.crt
      VAULTAIRE_LDAPS_TLS_KEY_FILE: /run/secrets/vaultaire-tls/ldaps/tls.key
      VAULTAIRE_API_TLS_CERT_FILE: /run/secrets/vaultaire-tls/api/tls.crt
      VAULTAIRE_API_TLS_KEY_FILE: /run/secrets/vaultaire-tls/api/tls.key
```

Les clés doivent être lisibles par l'UID 65532. Détails :
[Variables d'environnement](../../docs/Installation/Variables_environnement.md).

## 7. Sauvegarder

La base porte **tout** (comptes, groupes, GPO, clés et certificats du core).
Le volume `core-data` ne contient que des fichiers régénérables.

```bash
docker compose exec -T db sh -c \
  'mariadb-dump -u vaultaire -p"$(cat /run/secrets/db-password)" --single-transaction vaultaire' \
  | gzip > vaultaire-$(date +%F).sql.gz
```

Restauration, sur une pile arrêtée côté core :

```bash
docker compose stop core
gunzip -c vaultaire-AAAA-MM-JJ.sql.gz | docker compose exec -T db sh -c \
  'mariadb -u vaultaire -p"$(cat /run/secrets/db-password)" vaultaire'
docker compose start core
```

Gardez les sauvegardes **et** `secrets/` à l'abri : la base contient la clé
privée du core.

## 8. Mettre à jour

1. Sauvegarder la base (§ 7).
2. Lire les notes de la release (changements à appliquer, nouveau digest).
3. Remplacer la ligne `image:` du service `core` (tag **et** digest).
4. ```bash
   docker compose pull core && docker compose up -d core
   docker compose exec core /opt/vaultaire/bin/vaultaire_cli version
   ```

Le schéma de la base est mis à jour au démarrage. Revenir en arrière, c'est
remettre l'ancienne ligne `image:` **et** restaurer la sauvegarde.

## 9. Si ça ne démarre pas

```bash
docker compose logs core | tail -20
```

| Message | Cause |
|---|---|
| `… vaut CHANGEZ_MOI` | un secret manquant : vérifier `secrets/` et les `*_FILE` |
| `variable … vide` | une variable posée sans valeur (souvent `.env` incomplet) |
| `permission denied` sur `/run/secrets/…` | un secret illisible par l'UID 65532 (`chmod 644`) |
| `Impossible d'amorcer les clés du core` | base injoignable : `docker compose ps db` |
| `dial unix …vaultaire.sock` (CLI) | le core n'est pas (encore) démarré |
