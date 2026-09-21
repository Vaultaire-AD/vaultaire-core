# Vaultaire Core

Annuaire et contrôleur de domaine pour parcs Linux : authentification centralisée,
RBAC multi-domaines, LDAP(S), DNS, GPO, portail web et API REST.

Ce dépôt contient **le code source, la documentation et les outils de déploiement**.
Pour découvrir Vaultaire pas à pas, commencez par la
**[formation](./docs/training/README.md)**.

---

## 🔗 Points d'entrée de la documentation

| Sujet | Fichier |
| --- | --- |
| Index de la documentation | [`docs/README.md`](./docs/README.md) |
| **Formation pas à pas** | [`docs/training/README.md`](./docs/training/README.md) |
| Installation & configuration | [`docs/Installation/Setup.md`](./docs/Installation/Setup.md) |
| Prérequis | [`docs/Installation/Requirements.md`](./docs/Installation/Requirements.md) |
| Manuel des commandes (`vlt`) | [`docs/Utilisation/MAN.md`](./docs/Utilisation/MAN.md) |
| CLI distante par API | [`docs/Utilisation/vaultairectl.md`](./docs/Utilisation/vaultairectl.md) |
| Groupes & permissions | [`docs/Utilisation/Group-Permission.md`](./docs/Utilisation/Group-Permission.md) |
| Module LDAP | [`docs/Utilisation/vaultaireLDAP.md`](./docs/Utilisation/vaultaireLDAP.md) |
| Protocole Ducky Network | [`docs/Developement/how it work/ducky-network/`](./docs/Developement/how%20it%20work/ducky-network/README.md) |
| Créer un nouveau service | [`docs/Developement/how it work/Nouveau_service.md`](./docs/Developement/how%20it%20work/Nouveau_service.md) |
| Dépôt de paquets Nexus | [`src/vaultaire_nexus/README.md`](./src/vaultaire_nexus/README.md) |
| GPO | [`docs/Developement/how it work/GPO.md`](./docs/Developement/how%20it%20work/GPO.md) |
| Modèle de permissions | [`docs/Developement/how it work/Permissions_RBAC.md`](./docs/Developement/how%20it%20work/Permissions_RBAC.md) · [`Utilisation/Actions_et_Permissions.md`](./docs/Utilisation/Actions_et_Permissions.md) |
| Schéma de base de données | [`docs/Developement/how it work/Base_de_donnees.md`](./docs/Developement/how%20it%20work/Base_de_donnees.md) |
| Sécurité | [`docs/Securite/SECURITY.md`](./docs/Securite/SECURITY.md) |
| Releases, SELinux, LDAPS/Keycloak | [`docs/exploitation/`](./docs/exploitation/) |
| DNS | [`docs/Utilisation/DNS.md`](./docs/Utilisation/DNS.md) |
| Historique des versions | [`docs/Version_History.md`](./docs/Version_History.md) — index ; détail dans [`docs/Version/`](./docs/Version/) |
| Reste à faire | [`docs/Developement/TO-DO.md`](./docs/Developement/TO-DO.md) |

---

## 🚀 Démarrage rapide

Objectif : un serveur Vaultaire qui tourne, et une première connexion au portail,
en une dizaine de minutes. La pile de démonstration (serveur + MariaDB + Keycloak)
utilise les **binaires de la dernière release** : rien à compiler.

### 1. Lancer la pile

Sur une machine Linux avec Docker ≥ 24, `git`, `curl` :

```bash
git clone https://github.com/Vaultaire-AD/vaultaire-core.git
cd vaultaire-core
./deployments/pre-prod/docker-update.sh      # télécharge la release, construit l'image, démarre
docker compose -f deployments/pre-prod/docker-compose.yml ps
```

Le premier démarrage crée les tables, génère les clés du core et les certificats
TLS. Il est terminé quand le journal affiche l'empreinte du core :

```bash
docker compose -f deployments/pre-prod/docker-compose.yml logs -f vaultaire-ad | grep empreinte
```

### 2. Se connecter

| Accès | Adresse | Identifiants par défaut |
| --- | --- | --- |
| Portail d'administration | `https://<hôte>:4443/login` | `admin` / `admin123` (le compte `vaultaire` n'a pas de mot de passe tant qu'on ne lui en donne pas un — [jalon 1.3](./docs/training/01-installation-serveur/03-premier-acces.md)) |
| CLI sur le serveur | `docker exec -it vaultaire-ad /opt/vaultaire/bin/vaultaire_cli` | aucun (socket local) |
| CLI à distance (`vlt`) | `https://<hôte>:6643` | compte `admin` + clé [`deployments/configs/demo_admin_key`](./deployments/configs/demo_admin_key) |
| MariaDB | `<hôte>:3306` | `root` / `root` |
| Keycloak | `http://<hôte>:8080/auth` | `admin` / voir `KEYCLOAK_ADMIN_PASSWORD` dans le compose |

Le certificat du portail est **auto-signé** : le navigateur affiche un
avertissement au premier accès, c'est attendu.

- `vaultaire` est le compte d'amorçage, membre du groupe protégé `vaultaire`
  (tous les droits). Il ne peut être ni supprimé ni renommé.
- `admin` est créé depuis la section `administreur` de
  [`serveur_conf.yaml`](./deployments/configs/serveur_conf.yaml), avec la clé
  publique de démonstration.

> ⚠️ **Identifiants et clé de démonstration publics.** Hors démo, changez les
> mots de passe dès la première connexion (`update -u vaultaire -p <nouveau>`),
> désactivez `debug` et remplacez la section `administreur` de la configuration.

### 3. Premières commandes

```bash
alias vlt='docker exec -it vaultaire-ad /opt/vaultaire/bin/vaultaire_cli'

vlt version                                           # version du core
vlt create -g Infra infra.acme.lan                    # un groupe et son domaine
vlt create -u alice.martin infra.acme.lan 'Ch4ngeMe!' 14/03/1990
vlt add -u alice.martin -g Infra
vlt get -g Infra
vlt eyes -g                                           # l'arborescence des domaines
```

Toute commande répond à `-h`. Le manuel complet est
[`docs/Utilisation/MAN.md`](./docs/Utilisation/MAN.md) ; la suite guidée
(machines, GPO, DNS, LDAP…) est dans la [formation](./docs/training/README.md).

### Autres façons de lancer

| Besoin | Commande | Détail |
| --- | --- | --- |
| Une version précise | `./deployments/pre-prod/docker-update.sh --version 2.1.0` | [`deployments/pre-prod/README.md`](./deployments/pre-prod/README.md) |
| Développer sur le code | `./deployments/dev/up.sh` — sources montées, `go run` | [`deployments/dev/README.md`](./deployments/dev/README.md) |
| Installation sans Docker (systemd) | — | [`docs/Installation/Setup.md`](./docs/Installation/Setup.md) |

---

## 🔌 Ports exposés par le serveur central

| Port | Protocole | Service | Réglage (`serveur_conf.yaml`) |
| --- | --- | --- | --- |
| 6666 | TCP | Ducky Network : agents et proxies | `serveurlistenport` |
| 4443 | TCP | Portail web (HTTPS) | `website.website_port` |
| 6643 | TCP | API REST (HTTPS) — `vlt` à distance | `api.api_port` |
| 389 | TCP | LDAP | `ldap.ldap_port` |
| 636 | TCP | LDAPS | `ldap.ldaps_port` |
| 53 | UDP | DNS | `dns.dns_enable` — port fixe, **non publié** par le compose |
| 3306 | TCP | MariaDB (compose) | section `database` |
| 8080 | TCP | Keycloak (compose, optionnel) | — |

Services du cluster, sur leur propre hôte :

| Port | Protocole | Service | Réglage |
| --- | --- | --- | --- |
| 8843 | TCP | Nexus — interface, dépôts, registre Docker (HTTPS) | `listen` (`src/vaultaire_nexus/config.example.yaml`) |
| 8443 | TCP | réservé au proxy (répartition de charge à venir) | — |

Le compose de préprod publie tous les ports du serveur central sauf **53/udp**. Pour interroger le
DNS depuis l'extérieur du conteneur, ajoutez `"53:53/udp"` aux `ports` du service
`vaultaire-ad`.

Configuration de référence :
[`deployments/configs/serveur_conf.yaml`](./deployments/configs/serveur_conf.yaml).

---

## ⚙️ Prérequis de développement

Uniquement pour **compiler** ou modifier le code — la démo ci-dessus n'en a pas
besoin.

| | |
| --- | --- |
| **Go** | **1.26** pour les sept modules (`toolchain go1.26.5`). Un Go plus ancien suffit : `GOTOOLCHAIN=auto`, le défaut, télécharge le toolchain réclamé. |
| **GCC, `pam-devel`, `libcurl-devel`, `libxcrypt-devel`** | Modules PAM/NSS en C (`src/vaultaire_client/pam_module/`) — `libpam0g-dev`, `libcurl4-openssl-dev` sur Debian/Ubuntu |
| **Docker / Docker Compose** | ≥ 24.x |
| **Git** | ≥ 2.30 |

Cible de déploiement : **Rocky Linux 9** (les releases y sont compilées). Depuis
Windows, développer dans **WSL**.

```bash
./auto-compil.sh          # compile les sept modules et les modules PAM dans cmd/ (non versionné)
```

Il n'y a **pas de `go.mod` à la racine** : chaque répertoire de `src/` est un
module Go autonome.

---

## 🛠 Branches & workflow Git

| Branche | Rôle | Ce qui s'y passe |
| --- | --- | --- |
| `main` | Stable, publié | Chaque PR `preprod` → `main` fusionnée publie une **release** `vX.Y.Z` |
| `preprod` | Validation avant publication | Déployée sur l'hôte de préproduction |
| `dev` | Intégration | Audit CI (lint, SAST, dépendances) à chaque push et PR |
| `feature/<sujet>-<issue>` | Une fonctionnalité | Part de `dev`, y revient par PR |
| `hotfix/<sujet>-<issue>` | Un correctif urgent | Part de `main`, revient dans `main` **et** `dev` |
| `docs/…`, `ci/…` | Documentation, CI | Même cycle qu'une feature |

**Ne jamais committer directement** sur `main`, `preprod` ou `dev` : on crée une
branche, puis une pull request.

```bash
git switch dev && git pull
git switch -c feature/gpo-user-drift-33
# … commits …
git push -u origin feature/gpo-user-drift-33      # puis PR vers dev
```

Le cycle d'une modification : `feature/*` → **`dev`** → **`preprod`** → **`main`**.
Les branches de travail sont supprimées une fois fusionnées.
[`repo_manage.sh`](./repo_manage.sh) automatise la création et la fusion en
respectant ces règles.

| Workflow | Déclencheur | Rôle |
| --- | --- | --- |
| [`dev.yaml`](./.github/workflows/dev.yaml) | push / PR sur `dev`, hebdomadaire | lint, format, SAST, audit des dépendances |
| [`release.yaml`](./.github/workflows/release.yaml) | PR `preprod` → `main` fusionnée | compile sur Rocky 9, publie la release, garde les 5 dernières |
| [`codeql.yml`](./.github/workflows/codeql.yml) | push / PR sur `main`, `preprod`, `dev` | analyse CodeQL |

Numérotation et contenu des releases :
[`docs/exploitation/Releases.md`](./docs/exploitation/Releases.md).

---

## 📝 Conventions

- 🌿 **Une branche par modification**, jamais de commit direct sur `main`,
  `preprod`, `dev`.
- ✍️ **Messages de commit** : `type(PORTÉE): résumé` — `feat`, `fix`, `docs`,
  `ci`, `test`… (ex. `fix(DUCKY): …`).
- ❌ **Pas de binaires dans Git.** `auto-compil.sh` les produit dans `cmd/`
  (ignoré) ; les binaires distribués sont ceux des releases.
- 📂 **Structure** : le code vit dans `src/`, avec ses tests ; le portail dans
  `web_packet/` ; les déploiements dans `deployments/`.
- 🗒️ **Documenter chaque changement** en haut de
  `docs/Version/<majeure>/<mineure>.md`.
- ✅ **TO-DO** : une tâche terminée **quitte**
  [`docs/Developement/TO-DO.md`](./docs/Developement/TO-DO.md) pour
  `docs/Developement/DO/<version>/` — voir la convention en tête du fichier.
- 🏷️ **Changer de série** (2.1 → 2.2) : modifier `VERSION` et la valeur de repli
  `var Version` des trois paquets `version`, dans la PR vers `main`.
- 🔤 **Fins de ligne LF** partout (`.gitattributes`), sauf `*.ps1`.
- 📚 **Aide des commandes** : `vlt <commande> -h` fait foi ; tenir `MAN.md` à
  jour avec elle.

Détail dans [`CONTRIBUTING.MD`](./CONTRIBUTING.MD).

---

## 📬 Contact

**contact@vaultaire.fr**
