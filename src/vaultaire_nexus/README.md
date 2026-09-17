# Vaultaire Nexus

Dépôt central du parc Vaultaire — l'équivalent d'un **WSUS** ou d'un **Nexus** pour Linux.

Un seul service pour stocker, versionner et distribuer :

| Type de dépôt | Ce qu'il sert | Client |
|---|---|---|
| `rpm` | paquets RPM, métadonnées `repodata/` générées | `dnf` / `yum` |
| `deb` | paquets Debian, index `dists/` générés | `apt` |
| `docker` | images et index multi-plateformes (API Registry v2) | `docker`, `podman`, `skopeo` |
| `vaultaire` | archives de release Vaultaire, API compatible GitHub | `docker-update.sh`, `curl` |
| `generic` | tout fichier versionné (scripts, outils, archives) | `curl`, `wget` |

Avec :

- une **interface web** authentifiée par les **comptes Vaultaire** (LDAP du core) ou par un **compte local** ;
- des **jetons** pour les machines et la CI ;
- le **suivi de chaque téléchargement** (qui, quoi, quelle version, d'où) ;
- des **versions immuables** et une **rétention** par paquet.

> Aucun fichier du core ni des autres services n'est modifié par ce service.
> Ce qu'il faudra changer côté core est décrit dans [CORE_CHANGEMENTS.md](CORE_CHANGEMENTS.md),
> l'authentification par le réseau Ducky (version suivante) dans [DUCKY_AUTH.md](DUCKY_AUTH.md).

---

## Sommaire

1. [Démarrage rapide](#1-démarrage-rapide)
2. [Architecture](#2-architecture)
3. [Configuration](#3-configuration)
4. [Authentification et droits](#4-authentification-et-droits)
5. [Utiliser les dépôts](#5-utiliser-les-dépôts)
6. [API REST](#6-api-rest)
7. [Suivi d'utilisation](#7-suivi-dutilisation)
8. [Exploitation](#8-exploitation)
9. [Sécurité](#9-sécurité)
10. [Développement et tests](#10-développement-et-tests)
11. [Limites connues](#11-limites-connues)

---

## 1. Démarrage rapide

```bash
cd src/vaultaire_nexus
./build.sh                                   # → ./dist/vaultaire_nexus
sudo mkdir -p /etc/vaultaire_nexus
sudo cp config.example.yaml /etc/vaultaire_nexus/config.yaml
sudo ./dist/vaultaire_nexus -config /etc/vaultaire_nexus/config.yaml
```

Ou en conteneur : `docker compose -f deploy/docker-compose.yml up -d` (voir [§ 8](#8-exploitation)).

| | Défaut |
|---|---|
| URL | `https://<hôte>:8843` |
| Compte | `admin` (compte **local**, indépendant de Vaultaire) |
| Mot de passe | **généré au premier démarrage**, écrit dans `<data_dir>/admin.initial` (0600) |
| Données | `/var/lib/vaultaire_nexus` |
| Journal | sortie standard + `/var/log/vaultaire/vaultaire_nexus.log` |
| Certificat | auto-signé, créé dans `<data_dir>/tls/` |

```bash
sudo cat /var/lib/vaultaire_nexus/admin.initial
```

Changez ce mot de passe dans **Administration** : le fichier est alors supprimé.
Pour fixer le mot de passe sans fichier (conteneur) : `NEXUS_ADMIN_PASSWORD`.

**Port** : `8843` a été choisi pour ne pas croiser ceux du parc (6666 Ducky, 4443 portail,
6643 API, 389/636 LDAP, 8443 réservé au proxy).

---

## 2. Architecture

```
src/vaultaire_nexus/
├── main.go                    démarrage, arrêt propre
├── version/                   version injectable (-ldflags -X), même contrat que le core
├── internal/
│   ├── config/                YAML strict + variables d'environnement
│   ├── store/                 blobs adressés par contenu (sha256), écritures atomiques
│   ├── catalog/               métadonnées : dépôts, paquets, images, manifestes
│   ├── vercmp/                comparaison de versions façon rpmvercmp (1.10 > 1.9, ~rc)
│   ├── rpmrepo/               lecture d'en-tête RPM, génération repodata (sans createrepo)
│   ├── debrepo/               lecture .deb (gz/xz/zst), génération Packages/Release
│   ├── signing/               signature GPG des index (binaire gpg de l'hôte)
│   ├── repos/                 publication, rétention, régénération des index, GC
│   ├── registry/              Docker Registry HTTP API v2
│   ├── files/                 releases Vaultaire (API GitHub), import depuis GitHub
│   ├── auth/                  compte local, LDAP, jetons, sessions, verrouillage
│   ├── ldapclient/            client LDAP minimal (bind + search)
│   ├── usage/                 journal d'utilisation + agrégats
│   ├── clusterlink/           raccordement au cluster (Ducky) — désactivé par défaut
│   ├── tlsutil/               certificat fourni ou auto-signé
│   └── web/                   interface, API, points de distribution
├── deploy/                    Dockerfile, compose, unité systemd
├── test/e2e.sh                test de bout en bout (dnf, apt, docker, releases…)
├── config.example.yaml
├── CORE_CHANGEMENTS.md        ce que le core doit ajouter (non appliqué)
└── DUCKY_AUTH.md              authentification par le réseau Ducky (proposition)
```

### Stockage

```
<data_dir>/
├── blobs/sha256/ab/abcdef…    tout contenu, une seule fois (paquets, couches Docker)
├── meta/repos/<dépôt>.json    catalogue du dépôt
├── index/rpm/<dépôt>/repodata/        index générés (reconstructibles)
├── index/deb/<dépôt>/dists/
├── auth/local_admin.json      empreinte PBKDF2 du compte local
├── auth/tokens.json           jetons (empreintes sha256 uniquement)
├── usage/AAAA-MM-JJ.jsonl     journal d'utilisation
├── tls/                       certificat auto-signé
└── tmp/                       envois en cours, téléversements Docker
```

- Un fichier présent dans plusieurs dépôts n'est stocké **qu'une fois**.
- Les **index** (`index/`) sont **reconstructibles** à tout moment depuis le catalogue :
  ils sont régénérés au démarrage, et 1,5 s après la dernière modification d'un dépôt
  (une CI qui pousse vingt paquets ne régénère qu'une fois).
- **Sauvegarde** : `blobs/`, `meta/` et `auth/` suffisent. `usage/` si l'historique compte.

### Versions immuables

Une version publiée ne se remplace pas : un second envoi de la même version est refusé
(`409`). Pour republier, supprimez d'abord. C'est ce qui garantit qu'un
`vaultaire_client 2.1.0` téléchargé aujourd'hui est le même que celui d'hier.

Exception assumée : les **tags Docker** sont mobiles (`latest`, `2.1`) — c'est le
fonctionnement attendu de Docker. Un manifeste, lui, est adressé par son condensat.

### Rétention

`keep_versions: N` conserve les N versions les plus récentes **par paquet et par
architecture** (comparaison façon RPM : `1.10.0 > 1.9.0`, `2.0~rc1 < 2.0`).
`0` = tout garder. Les fichiers retirés sont libérés au prochain **GC**
(Administration → Nettoyer), après un délai de grâce d'une heure.

---

## 3. Configuration

Fichier complet commenté : [config.example.yaml](config.example.yaml).

```bash
vaultaire_nexus -config /etc/vaultaire_nexus/config.yaml -check   # valider sans démarrer
vaultaire_nexus -version
```

La lecture est **stricte** : une clé inconnue (faute de frappe) empêche le démarrage.

| Variable d'environnement | Remplace |
|---|---|
| `NEXUS_ADMIN_PASSWORD` | `auth.local_admin.password` |
| `NEXUS_LDAP_BIND_PASSWORD` | `auth.ldap.bind_password` |
| `NEXUS_DATA_DIR` | `data_dir` |
| `NEXUS_LISTEN` | `listen` |
| `NEXUS_PUBLIC_URL` | `public_url` |
| `NEXUS_GITHUB_API` | URL de l'API GitHub pour l'import (défaut `https://api.github.com`) |
| `NEXUS_GITHUB_TOKEN` | jeton GitHub pour l'import (dépôts privés, quota) |

`public_url` est l'adresse que les clients utilisent : elle apparaît dans les
instructions de l'interface, l'API releases et l'enregistrement au cluster. Sans elle,
Nexus la déduit de chaque requête (`Host` et TLS de la connexion) — **renseignez-la derrière un mandataire**.

### Dépôts

Les dépôts déclarés dans `repositories:` sont créés au démarrage s'ils n'existent pas.
Ceux créés depuis l'interface vivent dans les métadonnées. Modifier la configuration
**ne modifie pas** un dépôt existant : utilisez l'interface ou l'API.

```yaml
repositories:
  - name: rocky9            # [a-z0-9._-], apparaît dans les URL
    type: rpm
    public: true            # lecture anonyme
    keep_versions: 5
  - name: debian
    type: deb
    distribution: bookworm  # défaut : stable
    component: main         # défaut : main
  - name: interne
    type: rpm
    readers: [Infra]        # groupes Vaultaire en plus du rôle global
    publishers: [CI]
```

---

## 4. Authentification et droits

### Sources d'identité

| `auth.mode` | Comptes acceptés |
|---|---|
| `local` (défaut) | le compte local seul |
| `ldap` | le compte local **et** les comptes Vaultaire, par l'annuaire LDAP du core |
| `ducky` | *pas encore disponible* — voir [DUCKY_AUTH.md](DUCKY_AUTH.md) |

**Le compte local reste actif en mode LDAP** : c'est le compte de secours quand le core
est injoignable. Son nom n'est **jamais** transmis à l'annuaire (un compte Vaultaire
`admin` ne peut pas le masquer). Il se désactive avec `local_admin.enable: false`.

#### Mode LDAP — comment ça marche

1. Nexus ouvre une connexion `ldap://` ou `ldaps://` vers le core.
2. **Bind** avec `uid=<compte>,<base_dn>` et le mot de passe saisi. C'est le core qui
   vérifie : mot de passe, expiration, et la permission **`auth`** sur le domaine du DN.
3. **Recherche** de l'entrée (`(uid=<compte>)`, attributs `memberOf` et `displayName`),
   avec la session de l'utilisateur, ou avec `bind_dn` si un compte de service est configuré.
4. Les groupes (`cn=<groupe>,ou=groups,…`) donnent le **rôle Nexus**.
5. Toutes les 5 minutes, les groupes des sessions ouvertes sont relus : un compte retiré
   d'un groupe perd ses droits sans se déconnecter.

```yaml
auth:
  mode: ldap
  ldap:
    url: ldaps://vaultaire.acme.lan:636
    base_dn: dc=acme,dc=lan
    ca_file: /etc/vaultaire_nexus/core-ca.crt
```

Un identifiant de la forme `alice@infra.acme.lan` est transmis tel quel au bind.
Les caractères spéciaux sont échappés (DN et filtre) : `*`, `(`, `)`, `\`, `,`…

### Rôles

| Rôle | Peut |
|---|---|
| `reader` | parcourir, rechercher, télécharger, `docker pull` |
| `publisher` | + publier, supprimer une version, `docker push`, régénérer un index |
| `admin` | + créer / régler / supprimer des dépôts, importer une release GitHub, voir tous les jetons et les clients, GC |

```yaml
auth:
  roles:
    admin:     [vaultaire]   # groupe protégé du core
    publisher: [CI, Infra]
    reader:    ["*"]         # « * » = tout compte authentifié
```

Un compte sans aucun rôle est **refusé**, même avec un bon mot de passe.
Les noms de groupe sont uniques dans tout l'annuaire du core (contrainte `UNIQUE` de la
table `groups`) : un domaine délégué ne peut pas créer un second `vaultaire`.

Par dépôt, `readers` et `publishers` **ajoutent** des groupes au rôle global.
Un dépôt `public` se lit sans compte ; il ne se publie jamais sans compte.

### Jetons

Pour dnf, apt, docker et la CI : **Jetons** dans l'interface, ou `POST /api/v1/tokens`.

- forme `nxs_<id>_<secret>`, affiché **une seule fois**, stocké en empreinte sha256 ;
- portée `reader` (lecture seule, même pour un admin) ou `publisher` ;
- le jeton porte les groupes de son propriétaire, rafraîchis avec eux ;
- utilisable en `Authorization: Bearer <jeton>` ou en Basic avec **n'importe quel**
  identifiant (`-u ci:<jeton>`, `docker login -u ci -p <jeton>`) ;
- expiration facultative, révocation immédiate, dernière utilisation et adresse affichées.

### Protection des sessions

- cookie `nexus_session` `HttpOnly`, `Secure`, `SameSite=Strict`, durée glissante ;
- jeton **CSRF** sur chaque formulaire et sur l'API appelée depuis une session (`X-CSRF-Token`) ;
- **verrouillage** : 5 échecs en 15 min par compte, 20 par adresse (réglable) ;
- les identifiants Basic valides sont mis en cache 2 minutes (docker s'authentifie
  à chaque couche : sans cache, un pull ferait des dizaines de binds LDAP).

---

## 5. Utiliser les dépôts

La page de chaque dépôt affiche ces instructions **pré-remplies** (adresse, nom, jeton).

### RPM — dnf / yum

```bash
sudo curl -fsSLo /etc/yum.repos.d/nexus-rocky9.repo https://nexus.acme.lan:8843/repo/rpm/rocky9/nexus.repo
sudo dnf install mon-paquet
```

Dépôt privé : ajoutez `username=ci` et `password=<jeton>` au fichier `.repo`.
Publication :

```bash
curl -fsS -u ci:$NEXUS_TOKEN -T mon-paquet-1.2.0-1.x86_64.rpm https://nexus.acme.lan:8843/api/v1/repos/rocky9/upload
```

Le nom, la version et l'architecture sont lus dans l'en-tête RPM ; le fichier est
renommé selon la convention (`nom-version-release.arch.rpm`). Les RPM **sources**
sont refusés.

### Debian — apt

```bash
echo "deb [trusted=yes] https://nexus.acme.lan:8843/repo/deb/debian bookworm main" \
  | sudo tee /etc/apt/sources.list.d/nexus-debian.list
sudo apt update
```

Avec signature activée : `[signed-by=/etc/apt/keyrings/vaultaire-nexus.asc]` et la clé
publique servie sur `/repo/keys/nexus.asc`.
Dépôt privé : identifiants dans `/etc/apt/auth.conf.d/nexus.conf` (l'interface donne
la commande).

Architectures indexées : `amd64`, `arm64`, et celles des paquets présents.
Un paquet `all` apparaît dans chacune.

### Docker

Nom d'image : `<hôte>:<port>/<dépôt nexus>/<image>:<tag>`.

```bash
docker login nexus.acme.lan:8843 -u ci -p $NEXUS_TOKEN
docker tag vaultaire/core:2.1.0 nexus.acme.lan:8843/docker/vaultaire/core:2.1.0
docker push nexus.acme.lan:8843/docker/vaultaire/core:2.1.0
docker pull nexus.acme.lan:8843/docker/vaultaire/core:2.1.0
```

Avec le certificat auto-signé, chaque hôte Docker doit l'approuver :

```bash
sudo mkdir -p /etc/docker/certs.d/nexus.acme.lan:8843
sudo curl -fsSk -o /etc/docker/certs.d/nexus.acme.lan:8843/ca.crt https://nexus.acme.lan:8843/repo/keys/nexus.crt
```

Pris en charge : envois monolithiques et par morceaux, montage inter-dépôts,
manifestes Docker v2 et OCI, **index multi-plateformes**, suppression par tag ou par
condensat, `_catalog` et `tags/list` paginés. Un manifeste qui référence une couche
absente est refusé.

### Releases Vaultaire

Le dépôt de type `vaultaire` reprend la forme des releases GitHub. `docker-update.sh`
de la pré-prod fonctionne **sans modification** :

```bash
VAULTAIRE_API_URL=https://nexus.acme.lan:8843/repo/vaultaire/releases/api \
VAULTAIRE_DL_URL=https://nexus.acme.lan:8843/repo/vaultaire/releases/download \
./deployments/pre-prod/docker-update.sh --version 2.1.0
```

| URL | Réponse |
|---|---|
| `…/api/releases` | liste, forme GitHub (`tag_name`, `assets[].browser_download_url`) |
| `…/api/releases/latest` | la plus récente (comparaison de versions, pas de dates) |
| `…/api/releases/tags/v2.1.0` | une release |
| `…/download/v2.1.0/<archive>` | une archive |
| `…/download/v2.1.0/SHA256SUMS` | sommes **calculées** sur les archives de la release |

Publication : le nom standard `composant-vX.Y.Z-os-arch.tar.gz` suffit.

```bash
curl -fsS -u ci:$NEXUS_TOKEN -T vaultaire_client-v2.1.1-linux-amd64.tar.gz \
  https://nexus.acme.lan:8843/api/v1/repos/releases/upload/
```

**Importer depuis GitHub** (parc sans Internet, sauf Nexus) : bouton sur la page du
dépôt, ou `POST /api/v1/repos/releases/import-github` avec
`{"repository":"owner/nom","tag":"latest"}`. Chaque archive est **vérifiée contre le
`SHA256SUMS` de la release** avant publication ; une release sans `SHA256SUMS` est refusée.

> `docker-update.sh` vérifie avec `sha256sum -c` : **tous** les fichiers listés doivent
> être téléchargés. Une release Nexus doit donc contenir exactement les composants que le
> script récupère (`COMPOSANTS`), comme sur GitHub.

### Fichiers génériques

```bash
curl -fsS -u ci:$NEXUS_TOKEN -T outil.tar.gz \
  'https://nexus.acme.lan:8843/api/v1/repos/outils/upload/outil.tar.gz?name=outil&version=1.4.0'
curl -fsSLO -u lecteur:$NEXUS_TOKEN https://nexus.acme.lan:8843/repo/files/outils/outil/latest/outil.tar.gz
```

`latest` désigne la plus haute version. Chaque téléchargement renvoie
`X-Checksum-Sha256` et un `ETag` ; `?download=1` force l'enregistrement.

---

## 6. API REST

Préfixe `/api/v1`. JSON en entrée et en sortie. Authentification : jeton (Bearer ou
Basic), mot de passe (Basic), ou session + `X-CSRF-Token`.

| Méthode | Chemin | Rôle | |
|---|---|---|---|
| GET | `/health`, `/version` | — | état, version |
| GET | `/whoami` | connecté | identité, groupes, rôle |
| GET | `/repos` | lecture | dépôts visibles, avec statistiques |
| POST | `/repos` | admin | créer (`name`, `type`, `public`, `keep_versions`…) |
| GET / PATCH | `/repos/{repo}` | lecture / admin | détail / réglages |
| DELETE | `/repos/{repo}?confirm={repo}` | admin | supprimer le dépôt |
| GET | `/repos/{repo}/packages[?name=]` | lecture | paquets et versions |
| GET / DELETE | `/repos/{repo}/packages/{id}` | lecture / publication | une version |
| PUT / POST | `/repos/{repo}/upload[/{fichier}]` | publication | corps brut ou multipart (`file`) ; `?name&version&arch&summary` |
| GET | `/repos/{repo}/images` | lecture | images Docker, tags, manifestes |
| POST | `/repos/{repo}/reindex` | publication | régénérer les index |
| POST | `/repos/{repo}/import-github` | admin | importer une release |
| GET | `/search?q=` | lecture | paquets et images des dépôts visibles |
| GET | `/usage[?days&repo&name]` | connecté | statistiques (clients : admin) |
| GET | `/usage/export` | admin | journal brut (JSONL) |
| GET / POST | `/tokens` | connecté | ses jetons / en créer un (`label`, `scope`, `expires_days`) |
| DELETE | `/tokens/{id}` | connecté | révoquer |
| POST | `/admin/gc[?dry_run=1]` | admin | libérer les fichiers orphelins |

Codes : `401` sans identité, `403` droit insuffisant, `404` inconnu, `409` version
existante, `413` trop gros (`max_upload_mb`), `422` fichier refusé.

Points de distribution (hors API) : `/repo/rpm/…`, `/repo/deb/…`, `/repo/files/…`,
`/repo/vaultaire/…`, `/repo/keys/nexus.asc`, `/v2/…`, `/healthz`.

---

## 7. Suivi d'utilisation

Chaque accès est journalisé : **téléchargement**, **pull**, **publication**, **push**,
**suppression**, et les **refus** (401/403).

```json
{"t":"2026-09-17T06:27:07Z","a":"download","r":"releases","rt":"vaultaire","n":"vaultaire_client","v":"2.1.0",
 "f":"vaultaire_client-v2.1.0-linux-amd64.tar.gz","u":"ci","ip":"10.0.4.12","ua":"curl/8.5.0","b":14032211,"s":200,"ms":41}
```

- un fichier JSONL par jour dans `<data_dir>/usage/`, conservé `usage.retention_days` (90) ;
- l'interface **Utilisation** : téléchargements par jour, paquets les plus demandés,
  répartition par version, comptes, **machines clientes** (admin), derniers accès ;
- chaque page de paquet et d'image montre ses propres chiffres ;
- `usage.anonymize_ip: true` tronque les adresses (/24, /48) ;
- les téléchargements partiels (`Range`) ne comptent qu'une fois, les index jamais ;
- un **pull Docker** compte une fois par client et par image par minute (Docker relit
  plusieurs manifestes par pull). Un `docker pull` d'une image déjà à jour ne fait qu'un
  `HEAD` : il n'est pas compté ;
- l'enregistrement ne ralentit jamais une réponse : en cas d'engorgement, les
  évènements sont abandonnés et **comptés** (visible dans Administration).

---

## 8. Exploitation

### Conteneur

```bash
cd src/vaultaire_nexus
docker compose -f deploy/docker-compose.yml up -d --build
docker compose -f deploy/docker-compose.yml exec nexus cat /var/lib/vaultaire_nexus/admin.initial
```

L'image compile le service (multi-étapes) et tourne en utilisateur `10001`.
Le volume `nexus-data` porte tout l'état. Sans fichier monté, l'image embarque une
configuration minimale (mode local, dépôts à créer depuis l'interface).

Parc sans accès à Docker Hub : les images de base sont des arguments.

```bash
docker build -f src/vaultaire_nexus/deploy/Dockerfile \
  --build-arg BUILD_IMAGE=nexus.acme.lan:8843/docker/golang:1.26.5-bookworm \
  --build-arg RUNTIME_IMAGE=nexus.acme.lan:8843/docker/debian:12-slim \
  --build-arg VERSION=2.1.0 -t vaultaire/nexus:2.1.0 src/
```

### systemd

```bash
sudo install -m 0755 dist/vaultaire_nexus /usr/local/bin/
sudo useradd --system --home /var/lib/vaultaire_nexus --shell /usr/sbin/nologin vaultaire-nexus
sudo install -m 0644 deploy/vaultaire_nexus.service /etc/systemd/system/
sudo systemctl daemon-reload && sudo systemctl enable --now vaultaire_nexus
```

### Derrière un mandataire TLS

`tls.enable: false`, `public_url` renseigné, et l'adresse du mandataire dans
`trusted_proxies` (sinon `X-Forwarded-For` est ignoré et le suivi montre le mandataire).
Renseignez aussi `public_url`. Pour Docker : pas de limite de taille de corps, pas de mise en tampon
(`client_max_body_size 0; proxy_request_buffering off;` sous nginx).

### Signature des dépôts

```yaml
signing:
  enable: true
  gpg_home: /var/lib/vaultaire_nexus/gnupg
  key_id: nexus@acme.lan
```

Clé **sans phrase de passe** (le service signe seul). APT reçoit `InRelease` et
`Release.gpg`, YUM `repomd.xml.asc`. Clé publique : `/repo/keys/nexus.asc`.
Les paquets eux-mêmes ne sont pas re-signés : signez-les à la construction.

### Raccordement au cluster

`ducky.enable: true` fait enrôler Nexus comme **client service** du core et
l'enregistre dans `cluster_nodes` (trames 04_09 / 04_12 / 04_14). **Nécessite les
changements du core** ([CORE_CHANGEMENTS.md](CORE_CHANGEMENTS.md) § 1) : sans eux,
l'enrôlement est refusé, Nexus le journalise, l'affiche dans Administration et
continue de fonctionner seul.

### Mise à jour, sauvegarde

- arrêter, remplacer le binaire, redémarrer : les index sont régénérés au démarrage
  depuis le catalogue ;
- sauvegarder `blobs/`, `meta/`, `auth/` (à chaud possible : les écritures sont atomiques,
  un blob n'est référencé qu'après avoir été écrit).

---

## 9. Sécurité

- **TLS** par défaut ; TLS 1.2 minimum.
- Mots de passe : **PBKDF2-SHA256, 600 000 itérations**. Jetons et mot de passe initial :
  aléatoire cryptographique.
- **Aucune** donnée d'identification dans les journaux.
- Envois : taille bornée, contenu **vérifié** (un `.rpm` doit être un RPM, un `.deb` un
  paquet Debian), noms de fichier validés, empreinte sha256 contrôlée pour Docker.
- Aucune traversée de répertoire : les fichiers servis sont résolus depuis le catalogue,
  jamais depuis le chemin demandé.
- En-têtes : `Content-Security-Policy`, `X-Frame-Options: DENY`,
  `X-Content-Type-Options: nosniff`, `Referrer-Policy`.
- Un dépôt privé répond `401` (et non `404`) : dnf et apt présentent alors leurs identifiants.

---

## 10. Développement et tests

```bash
cd src/vaultaire_nexus
go test ./...            # rpm/deb nécessitent rpmbuild, dnf, dpkg-deb, apt-get (sinon ignorés)
go vet ./...
./build.sh               # version injectée depuis VERSION à la racine
test/e2e.sh              # démarre un Nexus jetable et le passe à dnf, apt, docker, curl
```

Ce qui est vérifié par les tests :

| | |
|---|---|
| `vercmp` | ordre des versions (tilde, époques, suffixes) |
| `rpmrepo` | lecture de vrais RPM construits par `rpmbuild` ; **dnf** lit l'index généré |
| `debrepo` | `.deb` gzip / xz / zstd / non compressé ; **apt** lit l'index généré |
| `auth` | mots de passe, rôles, compte local, verrouillage, jetons, **LDAP** contre un faux annuaire qui imite celui du core |
| `ldapclient` | filtres et échappements |
| `registry` | envoi par morceaux et monolithique, condensat faux, manifeste incomplet, tags, pagination, montage, suppression, droits |
| `test/e2e.sh` | dnf public et privé (jeton), apt, docker push/pull, API releases + `sha256sum -c`, fichiers `latest`, interface, CSRF |

Le module suit les règles du dépôt : un `go.mod` propre, le SDK Ducky en `replace`
local, pas de `go.work`.

---

## 11. Limites connues

- **Pas de mandataire vers l'extérieur** (proxy cache de dépôts publics) : Nexus sert ce
  qu'on y publie. L'import GitHub couvre les releases Vaultaire.
- **Pas de réplication** entre deux Nexus : un seul nœud, stockage local.
- **RPM** : pas de métadonnées `updateinfo` / `modules`. **APT** : pas de sources.
- **LDAP** : les groupes sont lus par leur nom (`cn`) ; le core n'expose pas le domaine
  d'un groupe dans `memberOf` au-delà des deux derniers niveaux. Sans conséquence tant
  que les noms de groupe restent uniques (c'est le cas aujourd'hui).
- **LDAP et MFA** : si le core active `RefuseBindWhenMFARequired`, les comptes soumis au
  second facteur ne peuvent plus se connecter à Nexus par LDAP. L'authentification par
  le réseau Ducky ([DUCKY_AUTH.md](DUCKY_AUTH.md)) lève cette limite.
- Le **mode `ducky`** et le **rôle RBAC natif** attendent les changements du core.
