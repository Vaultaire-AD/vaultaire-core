# Créer un nouveau service

**Public : développeurs.** Tout ce qu'il faut faire pour ajouter un programme au
cluster Vaultaire — du dossier `src/` à la release — dans l'ordre où on le
fait. L'exemple suivi est **Nexus** (`src/vaultaire_nexus`), le dernier service
ajouté : chaque étape renvoie au fichier qui la réalise.

> Un **service** s'enrôle seul et déclare une *fonction* (interface web, dépôt de
> paquets, API). Un **agent** est créé sur le core et représente une *machine*.
> Ce guide ne traite que des services. Vocabulaire :
> [`Lexique.md`](../../Utilisation/Lexique.md).

---

## Sommaire

1. [Choisir le nom et le périmètre](#1-choisir-le-nom-et-le-périmètre)
2. [Créer le module Go](#2-créer-le-module-go)
3. [Déclarer le type au catalogue du core](#3-déclarer-le-type-au-catalogue-du-core)
4. [Se raccorder au réseau Ducky](#4-se-raccorder-au-réseau-ducky)
5. [Authentifier les utilisateurs du service](#5-authentifier-les-utilisateurs-du-service)
6. [Ajouter des droits RBAC](#6-ajouter-des-droits-rbac)
7. [Ajouter une trame (si besoin)](#7-ajouter-une-trame-si-besoin)
8. [Build, CI et release](#8-build-ci-et-release)
9. [Déploiement](#9-déploiement)
10. [Documentation à mettre à jour](#10-documentation-à-mettre-à-jour)
11. [Liste de contrôle](#11-liste-de-contrôle)

---

## 1. Choisir le nom et le périmètre

| Décision | Règle | Nexus |
|---|---|---|
| Nom du type | `vaultaire_<nom>` — écrit tel quel dans `id_logiciels.logiciel_type` | `vaultaire_nexus` |
| Dossier | `src/vaultaire_<nom>/` | `src/vaultaire_nexus/` |
| Port | libre dans le tableau des ports du `README.md` racine | `8843` |
| Trames émises | le **strict** nécessaire — chaque sous-trame est un privilège | voir § 3 |
| Agit au nom d'un compte ? | presque toujours **non** (`AssertsUser: false`) | non |
| Apprend des droits sur les comptes ? | si le service a ses propres rôles : oui, par clés dédiées | `read:nexus`, `write:nexus`, `write:nexus_admin` |

**Règle d'or du dépôt** : un service ne modifie ni le core ni les autres
modules pour fonctionner **seul**. Tout ce qu'il attend du core est ajouté au
core dans un lot séparé, décrit avant d'être écrit.

---

## 2. Créer le module Go

Chaque dossier de `src/` est un **module indépendant** (pas de `go.work`, pas de
`go.mod` racine).

```
module vaultaire_<nom>

go 1.26.1
toolchain go1.26.5

require duckynetworkclient/V1 v0.0.0

replace duckynetworkclient/V1 => ../ducky-network-sdk-service
```

| Contrainte | Pourquoi | Vérifiée par |
|---|---|---|
| directive `go` **avec** correctif (`1.26.1`, jamais `1.26`) | sinon Go cherche le toolchain « go1.26 », qui n'existe pas | `auto-compil.sh` |
| `replace` **relatif** uniquement | un chemin absolu compile autre chose que le dépôt | `auto-compil.sh` |
| `gofmt` propre | la CI de dev le vérifie sur tout le dépôt | `dev.yaml` |
| dépendances minimales | chaque dépendance doit passer les proxys d'entreprise | revue |

### Le paquet `version`

Même contrat que le core, l'agent et le proxy
([`Versions.md`](./Versions.md)) :

```go
package version

var Version = "2.1.0" // remplacée à la release (-ldflags -X)
var (
	Commit = "dev"      // injecté par auto-compil.sh
	Date   = "inconnue"
)
func Complete() string { … } // « 2.1.0+gabc1234 (2026-09-17) »
```

La série (`2.1`) doit suivre le fichier `VERSION` de la racine : la CI de
release émet un avertissement sinon (§ 8).

### Structure conseillée

```
src/vaultaire_<nom>/
├── main.go                 flags -config / -version / -check, arrêt propre
├── version/
├── internal/config/        YAML strict (UnmarshalStrict) + variables d'environnement
├── internal/clusterlink/   raccordement Ducky (§ 4)
├── internal/auth/          compte local, LDAP, Ducky (§ 5)
├── deploy/                 Dockerfile, compose, unité systemd, ducky.example.yaml
├── test/                   test de bout en bout
├── config.example.yaml
└── README.md
```

---

## 3. Déclarer le type au catalogue du core

Fichier : `src/vaultaire_serveur/core/clienttype/clienttype.go`. Sans cette
entrée, le core **refuse l'enrôlement** et toute trame du service
(fail-closed).

```go
const Nexus = "vaultaire_nexus"

{
	Name:   Nexus,
	Label:  "Dépôt de paquets",
	Family: FamilyService,
	Description: "…",
	Frames: []string{
		"01_01", "01_05", "01_07",          // socle + enrôlement — obligatoire
		"02_01", "02_03", "02_05", "02_12", // session de service — obligatoire (02_12 compris)
		"04_09", "04_12", "04_14",          // s'enregistrer comme SERVICE
		"08_01", "08_04",                   // vérifier des comptes (§ 5)
	},
	UserRights:  []string{"read:nexus", "write:nexus", "write:nexus_admin"},
	AssertsUser: false,
},
```

| Champ | À savoir |
|---|---|
| `Frames` | exhaustif, à la sous-trame. Le socle `01_01 02_01 02_03 02_12` est vérifié pour TOUS les types (`TestSocleDeConnexionCommun`), l'enrôlement `01_05 01_07` pour tous les services. |
| `04_09/04_12/04_14` ou `04_01/04_07` | un service déclare une fonction (`04_09`) ; seul un nœud joignable par les agents (proxy) déclare une machine (`04_01`). Ne jamais donner les deux. |
| `UserRights` | clés que le service peut **apprendre** sur un compte (§ 5, § 6). Liste vide si le service n'a pas de rôles. |
| `AssertsUser` | le privilège le plus lourd du catalogue ; `TestAssertUserIsRare` veut qu'il reste à `vaultaire_web` seul. |

`RoleCluster` ne change **pas** pour un service : le rôle écrit dans
`cluster_nodes` est son type.

**Tests** (`clienttype_test.go`, `role_cluster_test.go`) : trames autorisées,
trames refusées (au moins `04_01`, `03_01`, `05_01`, `07_01`),
`RoleCluster(<type>) == ""`.

**Ce qui suit sans rien écrire** : `vlt enroll types` et la page Enrôlement
listent le type ; la purge des services partis le prend en compte
(`ServiceNames()`).

**Deux listes écrites à la main** à compléter, sinon elles **suppriment** les
clients du nouveau type :

- `deployments/pre-prod/scripts/migrate-clienttype.sh` (deux requêtes `NOT IN`) ;
- `docs/migrations/clienttype_catalogue.md` (tableau et requêtes).

---

## 4. Se raccorder au réseau Ducky

Tout passe par le SDK `duckynetworkclient/V1` : le service **n'écrit pas** le
chiffrement, la poignée de main ni l'enrôlement.

```go
storage.VersionComposant = version.Complete()     // annoncée en 02_12 et 04_09
storage.NomJournal = "vaultaire_<nom>_ducky.log"

// 1. brancher les gestionnaires AVANT toute émission
tramesmanager.RegisterHandler("04", link.handle04)
tramesmanager.RegisterHandler("08", link.handle08)

// 2. ouvrir la session (enrôlement automatique au premier lancement)
session, err := ducky.Start(ducky.Options{
	ConfigPath:    "/etc/vaultaire_<nom>/ducky.yaml", // servers + enrollment.key
	KeyPath:       "/var/lib/vaultaire_<nom>/ducky",  // identité — DOIT persister
	Enroll:        true,
	Persistent:    true,                              // reconnexion automatique
	SilentConsole: true,
})

// 3. s'enregistrer, battre, sortir
send("04_09", version, publicURL, "capacité1,capacité2")
// toutes les 60 s : send("04_12") — le core marque hors ligne après 3 min
// à l'arrêt      : send("04_14")
```

Référence : `src/vaultaire_nexus/internal/clusterlink/clusterlink.go`.

| Piège | Conséquence | Parade |
|---|---|---|
| `KeyPath` non persistant (conteneur sans volume) | réenrôlement à chaque démarrage, quota de la clé épuisé | volume dédié, sous le répertoire de données |
| gestionnaire branché après l'émission | l'accusé `04_10` arrive sans destinataire | brancher d'abord |
| rejouer `04_09` à chaque `04_11` | boucle serrée si le refus est définitif | rejouer au battement suivant |
| échec du raccordement fatal | le service tombe avec le core | journaliser, afficher l'état, réessayer (backoff) et **continuer à servir** |
| service arrêté plus longtemps que le délai de purge | ligne et client supprimés | nouvelle clé d'enrôlement |

Fichier `ducky.yaml` : même format que celui du proxy (`servers:`,
`enrollment.key`, `enrollment.label`). Exemple :
`src/vaultaire_nexus/deploy/ducky.example.yaml`.

Enrôlement, côté administrateur :

```bash
vlt enroll create --type vaultaire_<nom> --uses 1 --expires 1h --label <nom>-01
```

Protocole : [`ducky-network/04-cluster`](./ducky-network/04-cluster/README.md).

---

## 5. Authentifier les utilisateurs du service

Trois sources, cumulables. Nexus les a toutes.

| Source | Quand | Ce que le core fournit |
|---|---|---|
| **Compte local** | toujours, en secours (core injoignable) | rien — le service le gère seul (mot de passe initial aléatoire, empreinte PBKDF2) |
| **Réseau Ducky — trame 08** | cas nominal | mot de passe, **second facteur**, expiration, révocation, groupes `nom@domaine`, clés de service |
| **LDAP(S)** | service sans Ducky, ou repli | bind (mot de passe, permission `auth`), `memberOf`, attribut **`vaultaireServiceRights`** demandé nommément |

### Par la trame 08

Voir [le chapitre 8 du protocole](./ducky-network/08-authentification-service/README.md),
en particulier [8.4 — Brancher un nouveau service](./ducky-network/08-authentification-service/04-brancher-un-service.md).
Résumé :

- déclarer `08_01`, `08_04` et `UserRights` au catalogue ;
- corréler les réponses par `ref:` ;
- traiter `mfa_required` comme une étape du formulaire, pas comme un échec ;
- relire les comptes actifs (`08_04`) et couper sur `revoked`, `deleted`,
  `expired`, `denied`, `unknown` ;
- donner des **jetons** aux clients qui ne peuvent pas saisir de code (docker,
  dnf, apt, CI).

### Par LDAP

- Bind : `uid=<compte>,<base_dn>` — le core vérifie la permission `auth` sur le
  domaine du DN.
- Recherche : `(uid=<compte>)` avec les attributs `memberOf` **et**
  `vaultaireServiceRights`. Si la recherche se fait avec la session de
  l'utilisateur, il lui faut la permission `search` ; avec un compte de service,
  ce compte doit porter `read:get:user` sur le domaine des comptes pour voir
  leurs clés.
- Au bind LDAP, un compte soumis au second facteur fournit son mot de passe
  **suivi** du code (`motdepasse123456`), sauf `ldap.mfa_bypass: true` côté
  core. Un service qui sait demander le code peut l'accoler lui-même (c'est ce
  que fait Nexus en mode `ldap`) ; sinon, préférez la catégorie `08`.

Détail : [`Utilisation/vaultaireLDAP.md`](../../Utilisation/vaultaireLDAP.md).

---

## 6. Ajouter des droits RBAC

Quand le service a ses propres niveaux (lire, publier, administrer), on les
exprime en **actions spéciales globales** du core : un service n'appartient à
aucun domaine. Raisonnement complet : [`Permissions_RBAC.md`](./Permissions_RBAC.md) § 5.

Fichier : `src/vaultaire_serveur/core/permission/isValidAction.go`.

1. Déclarer les constantes, avec un commentaire qui dit **qui les évalue** :

   ```go
   const (
   	ActionReadNexus  = "read:nexus"
   	ActionWriteNexus = "write:nexus"
   	ActionAdminNexus = "write:nexus_admin"
   )
   ```

2. Les ajouter à `specialActions` **et** à `globalOnlyActions`.
3. Leur donner un libellé dans la matrice :
   `core/web_serveur/web_admin_permission_matrix.go`, `specialActionLabels`.
4. Les lister dans `UserRights` du type (§ 3). Le test
   `TestUserRightsDuCatalogueSontDesClesConnues` vérifie qu'elles existent et
   sont globales.

**Ce qui suit sans rien écrire** : `vaultaire_all` les reçoit au démarrage
suivant (`EnsureSuperadminActions`), la matrice de l'interface et `vlt get -p -u`
les affichent, `vlt update -pu <perm> <clé> all|nil` les accepte, le stockage se
fait dans `user_permission_action` (aucune migration SQL).

Nommage : `read:<service>`, `write:<service>`, `write:<service>_admin`. Jamais
une troisième catégorie (`admin:…`) : `IsRBACActionKey` et les affichages
supposent `read` ou `write`.

---

## 7. Ajouter une trame (si besoin)

À éviter tant qu'une catégorie existante suffit — la 08 est générique. Sinon :
[1.3 — Ajouter une trame : la liste](./ducky-network/01-socle/03-types-ordre-et-controles.md#ajouter-une-trame--la-liste).

---

## 8. Build, CI et release

| Fichier | À ajouter | Exemple Nexus |
|---|---|---|
| `auto-compil.sh` | variable de sortie, `mkdir -p`, `build_go … "CGO_ENABLED=0" "$(ldflags_pour <module>/version app) $(ldflags_pour duckynetworkclient/V1/duckynetwork/version)"`, copie des fichiers d'exemple, binaire dans les **deux** boucles de contrôle de version | `NEXUS_BIN` |
| `.github/workflows/release.yaml` | `paquet vaultaire_<nom> "$B"/vaultaire_<nom>/*` et le `version.go` dans le garde-fou de série | archive `vaultaire_nexus-vX.Y.Z-linux-amd64.tar.gz` |
| `.github/workflows/dev.yaml` | le module dans la boucle `go vet` | `vaultaire_nexus` |
| `deployments/pre-prod/docker-update.sh` | le composant dans `COMPOSANTS` **seulement** si la pré-prod l'installe ; la vérification ne porte que sur les archives téléchargées | — |

`CGO_ENABLED=0` : binaire statique, qui démarre dans n'importe quelle image.
Un binaire lié à la glibc de la machine de build échoue dans un conteneur plus
ancien avec un « no such file or directory » trompeur.

Vérification locale :

```bash
VAULTAIRE_BUILD_DIR=/tmp/build VAULTAIRE_VERSION=2.1.9 ./auto-compil.sh
/tmp/build/vaultaire_<nom>/vaultaire_<nom> -version   # 2.1.9+g…
```

---

## 9. Déploiement

| Élément | Règle |
|---|---|
| Utilisateur | non privilégié, **UID 10001** comme les autres images |
| Données | un seul répertoire (`/var/lib/vaultaire_<nom>`), identité Ducky comprise, en volume |
| Configuration | `/etc/vaultaire_<nom>/`, en lecture seule ; secrets par variables d'environnement |
| Journal | sortie standard + `/var/log/vaultaire/` |
| TLS | certificat fourni, ou auto-signé au premier démarrage |
| Santé | un point `/healthz` pour le `HEALTHCHECK` |
| systemd | `ExecStartPre=… -check`, `ProtectSystem=strict`, `StateDirectory=` |

Modèles : `src/vaultaire_nexus/deploy/`.

---

## 10. Documentation à mettre à jour

| Page | Quoi |
|---|---|
| `README.md` (racine) | tableau des ports, liste des composants |
| `docs/README.md` | lien vers le README du service |
| `docs/Developement/how it work/README.md` | ligne du module dans le tableau des modules |
| [`Versions.md`](./Versions.md) | chemin du paquet `version` |
| [`Permissions_RBAC.md`](./Permissions_RBAC.md) | les nouvelles clés |
| `docs/Utilisation/Actions_et_Permissions.md` | les nouvelles clés, côté exploitant |
| `docs/Utilisation/Lexique.md` | le type |
| `docs/Utilisation/MAN.md` | exemple `enroll create --type …` |
| `docs/exploitation/Releases.md` | l'archive de release |
| `docs/migrations/clienttype_catalogue.md` | le type (§ 3) |
| [`ducky-network/`](./ducky-network/README.md) | tableau « Qui émet quoi », et toute nouvelle trame |

---

## 11. Liste de contrôle

- [ ] `src/vaultaire_<nom>/` : `go.mod` conforme, paquet `version`, `-version`, `-check`
- [ ] Le service fonctionne **seul** (compte local) quand le core est injoignable
- [ ] Type au catalogue : trames minimales, `UserRights`, `AssertsUser: false`, tests
- [ ] Listes de migration complétées (`migrate-clienttype.sh`, `clienttype_catalogue.md`)
- [ ] Raccordement : gestionnaires avant émission, `04_09`/`04_12`/`04_14`, identité persistante
- [ ] Authentification : 08 (avec TOTP) et/ou LDAP (`vaultaireServiceRights`), jetons pour les machines
- [ ] Clés RBAC : `specialActions`, `globalOnlyActions`, libellés de la matrice, tests
- [ ] `auto-compil.sh`, `release.yaml`, `dev.yaml` ; `docker-update.sh` si la pré-prod l'installe
- [ ] Déploiement : Dockerfile (UID 10001), compose, systemd, exemples de configuration
- [ ] Port réservé dans le `README.md` racine
- [ ] Documentation (§ 10)
- [ ] Test de bout en bout : enrôlement, `vlt cluster list`, connexion d'un compte avec et sans second facteur, retrait d'un droit, révocation
