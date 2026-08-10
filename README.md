# Vaultaire Core

Annuaire et contrôleur de domaine pour parcs Linux : authentification centralisée,
RBAC multi-domaines, LDAP(S), DNS, GPO, portail web et API REST.

Ce dépôt contient **le code source, la documentation et les outils de déploiement**
pour les environnements de développement, préproduction et production.
Il s'adresse aux développeurs, testeurs et partenaires techniques connaissant déjà
la solution.

---

## 📂 Structure du dépôt

```plaintext
vaultaire-core/
│
├── src/                            # Code source — 7 modules Go indépendants
│   ├── vaultaire_serveur/          #   Serveur central (« core »)
│   │   ├── core/                   #     auth, permission, ldap, dns, gpo, api,
│   │   │                           #     web_serveur, database, action, command…
│   │   ├── ducky-network/          #     Implémentation serveur du protocole Ducky
│   │   ├── cluster/                #     Découverte de service, nœuds, métriques
│   │   └── main/
│   ├── vaultaire_client/           #   Agent poste client
│   │   ├── pam_module/             #     Modules PAM + NSS, en C
│   │   ├── pam_communication/      #     Socket UNIX agent ↔ PAM (/run/vaultaire)
│   │   ├── duckynetworkClient/     #     Implémentation client du protocole Ducky
│   │   ├── gpo/, sessionmgr/, storage/, tools/
│   ├── vaultaire_proxy/            #   Relais entre clients et cores
│   ├── vaultaire_cli/              #   CLI locale, via le socket d'administration
│   ├── vaultaire_ctl/              #   CLI distante, via l'API REST signée
│   ├── api_client_package/         #   Bibliothèque cliente de l'API (Go)
│   └── ducky-network-sdk-service/  #   SDK Ducky Network pour clients de type service
│
├── web_packet/sso_WEB_page/        # Portail web — SOURCE
│   ├── templates/                  #   Gabarits HTML (login, profil, admin_*)
│   └── static/                     #   CSS / JS
│
├── cmd/                            # SORTIE DE COMPILATION (produite par auto-compil.sh)
│   ├── vaultaire_server/           #   vaultaire_serveur, vaultaire_cli
│   ├── vaultaire_client/           #   vaultaire_client, *.so (PAM/NSS)
│   ├── vaultaire_ctl/              #   vaultaire_ctl
│   ├── vaultaire_proxy/            #   vaultaire_proxy
│   └── web_packet/                 #   copie de web_packet/, régénérée à chaque build
│
├── deployments/
│   ├── configs/serveur_conf.yaml   #   Configuration serveur de référence
│   ├── dev/                        #   Compose de développement + Rocky/SSH de test
│   ├── pre-prod/                   #   Compose préprod, deploy.sh, scripts d'init
│   └── selinux/                    #   Politique SELinux (vaultaire.te / .fc)
│
├── automatisation/                 # Scripts déployés côté client (auto-join Rocky)
├── docs/                           # Documentation technique — voir docs/README.md
├── images/                         # Logo
│
├── auto-compil.sh                  # Compilation des 7 modules + des modules C
├── repo_manage.sh                  # Création/fusion de branches selon le workflow
├── .gitattributes                  # Normalisation LF (voir « Fins de ligne »)
├── CONTRIBUTING.MD
├── LICENSE
└── README.md
```

> ⚠️ `cmd/` est un **répertoire de sortie**, pas du code. Il est produit par
> `auto-compil.sh` et listé dans `.gitignore`. Quelques binaires y restent suivis
> pour des raisons historiques : la procédure de détachement est dans
> [`deployments/pre-prod/README.md`](./deployments/pre-prod/README.md).

> ℹ️ Il n'y a **pas de `go.mod` à la racine** : chaque répertoire de `src/` est un
> module Go autonome, avec sa propre directive `go`. `auto-compil.sh` les compile
> l'un après l'autre.

---

## 🔗 Points d'entrée de la documentation

| Sujet | Fichier |
| --- | --- |
| Index de la documentation | [`docs/README.md`](./docs/README.md) |
| Installation & configuration | [`docs/Installation/Setup.md`](./docs/Installation/Setup.md) |
| Prérequis | [`docs/Installation/Requirements.md`](./docs/Installation/Requirements.md) |
| Manuel des commandes (`vlt`) | [`docs/Utilisation/MAN.md`](./docs/Utilisation/MAN.md) |
| CLI distante par API | [`docs/Utilisation/vaultairectl.md`](./docs/Utilisation/vaultairectl.md) |
| Groupes & permissions | [`docs/Utilisation/Group-Permission.md`](./docs/Utilisation/Group-Permission.md) |
| Module LDAP | [`docs/Utilisation/vaultaireLDAP.md`](./docs/Utilisation/vaultaireLDAP.md) |
| Protocole Ducky Network | [`docs/Developement/Tableau_Protocole_Réseau.md`](./docs/Developement/Tableau_Protocole_Réseau.md) |
| GPO | [`docs/Developement/GPO.md`](./docs/Developement/GPO.md) |
| Modèle de permissions | [`docs/Developement/Permissions.md`](./docs/Developement/Permissions.md) · [`Actions_et_Permissions.md`](./docs/Developement/Actions_et_Permissions.md) |
| Schéma de base de données | [`docs/Developement/DataBase_Struct.md`](./docs/Developement/DataBase_Struct.md) |
| Sécurité | [`docs/Securite/SECURITY.md`](./docs/Securite/SECURITY.md) |
| SELinux, LDAPS/Keycloak | [`docs/exploitation/`](./docs/exploitation/) |
| Historique des versions | [`docs/Version_History.md`](./docs/Version_History.md) — index ; détail dans [`docs/Version/`](./docs/Version/) |
| Reste à faire | [`docs/Developement/TO-DO.md`](./docs/Developement/TO-DO.md) |

---

## ⚙️ Prérequis de développement

| | |
| --- | --- |
| **Go** | **1.26** pour les sept modules, avec `toolchain go1.26.5`. Un Go local plus ancien suffit : `GOTOOLCHAIN=auto` — le défaut — télécharge le toolchain réclamé. La CI compile avec 1.26.5. |
| **GCC + `libpam0g-dev`** | Pour les modules PAM/NSS en C (`src/vaultaire_client/pam_module/`) |
| **Docker / Docker Compose** | ≥ 24.x, pour les environnements dev et préprod |
| **MariaDB** | Fournie par le compose ; sinon instance accessible |
| **Git** | ≥ 2.30 |

Cibles de déploiement : **Linux** (Debian 11+, Ubuntu 20.04+, Rocky/CentOS 8+).
Le développement depuis Windows se fait via **WSL** — `auto-compil.sh` pointe sur
le dépôt monté sous `/mnt/c/...`.

---

## 🚀 Démarrage

### Compiler

```bash
./auto-compil.sh
```

La racine du dépôt est **déduite de l'emplacement du script** : il fonctionne
depuis n'importe quel répertoire et sur n'importe quelle machine. `VAULTAIRE_ROOT`
permet de la désigner autrement, et le script refuse une racine qui ne contient
pas `src/vaultaire_serveur` — sans ce contrôle, une valeur erronée ferait boucler
sur zéro module et annoncer une compilation réussie sans avoir rien construit.

Le script vérifie les directives `go` des sept `go.mod`, refuse les `replace`
vers un chemin absolu, compile les binaires dans `cmd/` et construit les modules
PAM/NSS.

### Lancer la pile préprod (serveur + MariaDB + Keycloak)

```bash
./deployments/pre-prod/docker-build-and-up.sh
# ou, depuis PowerShell
.\deployments\pre-prod\docker-build-and-up.ps1
```

### Environnement de développement

```bash
./deployments/dev/up.sh
```

### Ports exposés par le serveur central

| Port | Service |
| --- | --- |
| 6666 | Ducky Network (clients, proxies) |
| 4443 | Portail web (HTTPS) |
| 6643 | API REST (HTTPS) |
| 389 / 636 | LDAP / LDAPS |
| 3306 | MariaDB (compose) |
| 8080 | Keycloak (compose, optionnel) |

Configuration de référence : [`deployments/configs/serveur_conf.yaml`](./deployments/configs/serveur_conf.yaml).

---

## 🛠 Branches & workflow Git

Modèle inspiré de **Gitflow** :

- `main` → production, code stable uniquement
- `preprod` → tests finaux avant mise en production
- `dev` → intégration continue
- `feature/<description>-<numéro-issue>` → nouvelles fonctionnalités
- `hotfix/<description>-<numéro-issue>` → correctifs

`./repo_manage.sh` crée et fusionne les branches en respectant cette convention
et refuse d'écrire directement sur les branches protégées.

La CI ([`.github/workflows/dev.yaml`](./.github/workflows/dev.yaml)) exécute lint,
format et audit de sécurité sur `dev`, à chaque push et pull request, plus un
passage hebdomadaire.

---

## ↩️ Fins de ligne

Le dépôt est normalisé en **LF**, dans l'historique comme dans la copie de
travail, y compris sous Windows : tout ce qui est produit ici s'exécute sous
Linux, et un `\r` en fin de shebang suffit à casser un script shell ou un
entrypoint Docker. Les règles sont dans [`.gitattributes`](./.gitattributes) ;
seul `*.ps1` reste en CRLF.

Après un `git pull` qui apporte ce fichier, une fois pour toutes :

```bash
git add --renormalize .
git status          # ne doit lister que de vraies modifications
```

---

## 📝 Conventions

- ❌ **Pas de binaires dans Git.** Ils sont produits par `auto-compil.sh` et
  transférés par `rsync` (`deployments/pre-prod/deploy.sh`).
- 📂 **Respecter la structure** : toute nouvelle fonctionnalité vit dans `src/`,
  avec ses tests.
- 🗒️ **Documenter les changements** : consigner dans le fichier de la version en
  cours, `docs/Version/<majeure>/<mineure>.md`. Les nouvelles entrées vont **en
  haut**.
- 🔁 **Modifier le portail web dans `web_packet/`**, jamais dans `cmd/web_packet/`,
  qui est écrasé à chaque compilation.
- ✅ Une tâche terminée se déplace de `docs/Developement/TO-DO.md` vers
  `docs/Developement/DO/<version>/`.

Détail dans [`CONTRIBUTING.MD`](./CONTRIBUTING.MD).

---

## 📬 Contact

**contact@vaultaire.fr**
