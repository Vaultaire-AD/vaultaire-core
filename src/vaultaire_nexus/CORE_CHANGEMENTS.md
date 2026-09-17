# Vaultaire Nexus — changements à apporter au core

> **Rien de ce document n'est appliqué.** Nexus a été écrit sans toucher une ligne du
> core ni des autres services. Ce fichier liste ce qu'il faut y ajouter, dans l'ordre
> où c'est utile, avec le code proposé.
>
> Nexus **fonctionne déjà sans ces changements** (compte local + LDAP). Ils apportent :
> l'apparition de Nexus dans le cluster, des droits RBAC natifs, l'authentification
> par le réseau Ducky, et l'intégration à la chaîne de build et de release.

| § | Changement | Débloque | Taille |
|---|---|---|---|
| [1](#1-type-de-client-vaultaire_nexus) | Type de client `vaultaire_nexus` | enrôlement, présence dans le cluster | petit |
| [2](#2-clés-rbac-nexus) | Clés RBAC `read:nexus`, `write:nexus`, `write:nexus_admin` | droits gérés dans la matrice du core | petit |
| [3](#3-authentification-ldap--rien-à-changer-deux-réglages) | Permission `auth` et MFA pour le bind LDAP | mode `ldap` (déjà utilisable) | réglage |
| [4](#4-catégorie-de-trames-08--authentification-par-un-service) | Catégorie de trames `08` | mode `ducky` | moyen |
| [5](#5-migrations-et-scripts-existants) | Listes de types en dur (migration) | ne pas supprimer les clients Nexus | petit |
| [6](#6-interface-dadministration-et-vlt) | Interface web, `vlt` | lien, affichage | petit |
| [7](#7-build-release-et-déploiement) | `auto-compil.sh`, `release.yaml`, `dev.yaml`, pré-prod | binaire dans les releases | petit |
| [8](#8-documentation-du-dépôt) | Docs | — | petit |

---

## 1. Type de client `vaultaire_nexus`

**Pourquoi.** Le core n'accepte une trame que si le **type** du client l'y autorise
(`core/clienttype`, fail-closed). Sans type, `vlt enroll create --type vaultaire_nexus`
est refusé et Nexus ne peut ni s'enrôler ni s'enregistrer.

**Ce que Nexus émet** (`internal/clusterlink`) :

| Trame | Rôle | Déjà gérée par le core ? |
|---|---|---|
| `01_01`, `01_05`, `01_07` | authentification du serveur, enrôlement | oui (SDK Ducky) |
| `02_01`, `02_03`, `02_05`, `02_12` | session de service, inventaire | oui (SDK Ducky) |
| `04_09`, `04_12`, `04_14` | enregistrement **de service**, battement, sortie | oui (`host_handler/service_registry.go`) |
| `08_01`, `08_04`, `08_07` | *mode ducky* — voir § 4 | **non** |

Nexus s'enregistre comme **service** (04_09) et non comme **machine** (04_01) : il
déclare une fonction et n'a pas à être servi aux agents. Le rôle écrit dans
`cluster_nodes` est donc son type, `vaultaire_nexus` — **`RoleCluster` n'a pas à changer**.

### `src/vaultaire_serveur/core/clienttype/clienttype.go`

```go
const (
	Client = "vaultaire_client"
	Proxy  = "vaultaire_proxy"
	Web    = "vaultaire_web"
	Nexus  = "vaultaire_nexus" // ← ajout
)
```

Dans `catalogue`, après `Web` :

```go
	{
		Name:   Nexus,
		Label:  "Dépôt de paquets",
		Family: FamilyService,
		Description: "Dépôt central : paquets RPM et Debian, images Docker, " +
			"releases Vaultaire. Vérifie les comptes, n'agit au nom de personne.",

		// Même socle de connexion que le proxy et l'interface web : 01 puis 02,
		// 02_12 compris (le core répond 02_11 à tout service et attend
		// l'inventaire).
		//
		// 04_09/04_12/04_14 : Nexus déclare une FONCTION, pas une machine. Il
		// n'a rien à faire dans la liste servie aux agents (04_03/04_04), et
		// 04_01 le ferait exister comme nœud joignable.
		//
		// 08_01/08_04/08_07 : vérification d'un compte, relecture de ses droits,
		// remontée d'utilisation — voir DUCKY_AUTH.md. À n'ajouter qu'avec la
		// catégorie 08 côté serveur (§ 4) ; sans elle, les laisser dehors.
		Frames: []string{
			"01_01", "01_05", "01_07",
			"02_01", "02_03", "02_05", "02_12",
			"04_09", "04_12", "04_14",
			// "08_01", "08_04", "08_07",   // § 4
		},

		// FAUX, délibérément. Nexus VÉRIFIE un mot de passe qu'on lui a donné
		// (08_01) ; il ne DÉCLARE jamais agir au nom d'un compte qu'il n'a pas
		// prouvé. Ce privilège-là reste à l'interface web seule.
		AssertsUser: false,
	},
```

### Tests à ajuster

- `core/clienttype/clienttype_test.go` : ajouter les cas `{Nexus, "04_09"}` (autorisée),
  `{Nexus, "04_01"}`, `{Nexus, "03_01"}`, `{Nexus, "05_01"}` (refusées).
  `TestAssertsUser…` reste vrai : `Web` est toujours le seul porteur.
- `role_cluster_test.go` : `RoleCluster(Nexus) == ""` (service, pas machine).

### Conséquences à connaître

- **Purge des services** (`PurgeDepartedServices`) : elle prend `ServiceNames()`, donc
  Nexus y entre automatiquement. Un Nexus arrêté plus longtemps que le délai de purge
  perd sa ligne **et son client** : il faudra une nouvelle clé d'enrôlement. C'est le
  comportement déjà en place pour le proxy et l'interface web.
- **Enrôlement** : `vlt enroll create --type vaultaire_nexus --uses 1 --expires 1h`.
  `vlt enroll types` le liste sans autre changement (lecture du catalogue).

---

## 2. Clés RBAC Nexus

**Pourquoi.** En mode LDAP, le rôle Nexus vient des **noms de groupe** listés dans la
configuration de Nexus. C'est suffisant pour démarrer, mais les droits vivent alors
hors du core : la matrice des permissions ne les montre pas, et un auditeur doit lire
un fichier YAML sur une autre machine. Des clés dédiées ramènent la décision dans le
core — c'est ce que le mode `ducky` (§ 4) consomme.

### Le modèle retenu : trois actions spéciales, portée globale

Même raisonnement que `read:cluster` / `write:cluster` (voir le commentaire de
`ActionReadCluster`) : un dépôt Nexus **n'appartient à aucun domaine**. Un objet RBAC
`nexus` engendrerait six clés (`read:get:nexus`, `write:add:nexus`…) dont trois
n'auraient aucun sens, et une clé qui n'accorde rien est indiscernable d'un oubli.

| Clé | Rôle Nexus | Accorde |
|---|---|---|
| `read:nexus` | `reader` | lire les dépôts **privés**, rechercher, `docker pull` |
| `write:nexus` | `publisher` | publier, supprimer une version, `docker push`, réindexer |
| `write:nexus_admin` | `admin` | créer / régler / supprimer des dépôts, import GitHub, jetons de tous, GC |

Les dépôts **publics** restent lisibles sans compte : ce n'est pas un droit du core.
Les listes `readers` / `publishers` **par dépôt** restent dans Nexus : ce sont des
restrictions d'usage d'un dépôt, pas des droits sur l'annuaire.

`write:nexus_admin` et non `admin:nexus` : `IsRBACActionKey` et plusieurs affichages
supposent une catégorie `read` ou `write`. Une troisième catégorie serait une
exception de plus à connaître.

### `src/vaultaire_serveur/core/permission/isValidAction.go`

```go
	specialActions = []string{
		"write:dns", "write:eyes",
		ActionKillSwitch, ActionReadLog, ActionManageMFA,
		ActionReadCluster, ActionWriteCluster,
		ActionReadCertificate, ActionWriteCertificate,
		ActionReadDNS, ActionReadEnrollment, ActionWriteServer,
		ActionReadNexus, ActionWriteNexus, ActionAdminNexus, // ← ajout
	}
```

```go
// ActionReadNexus, ActionWriteNexus et ActionAdminNexus : droits sur le dépôt
// de paquets (src/vaultaire_nexus).
//
// # Pourquoi des actions spéciales et non un objet RBAC
//
// Même raisonnement que le cluster : un dépôt n'appartient à aucun domaine.
// Trois clés et pas six, parce que trois niveaux seulement ont un sens.
//
// # Qui les évalue
//
// Pas le core : Nexus, à qui le core transmet la liste des clés accordées au
// compte (trame 08_02). Le core reste la source de vérité, Nexus applique.
//
// # Fail-closed
//
// Accordées à personne tant qu'on ne les accorde pas, sauf à vaultaire_all
// (EnsureSuperadminActions les ajoute au démarrage suivant).
const (
	ActionReadNexus  = "read:nexus"
	ActionWriteNexus = "write:nexus"
	ActionAdminNexus = "write:nexus_admin"
)
```

Et dans `globalOnlyActions` :

```go
var globalOnlyActions = []string{
	"web_admin", "write:dns", ActionReadLog,
	ActionReadCluster, ActionWriteCluster,
	ActionReadCertificate, ActionWriteCertificate,
	ActionReadDNS, ActionReadEnrollment, ActionWriteServer,
	ActionReadNexus, ActionWriteNexus, ActionAdminNexus, // ← ajout
}
```

### Ce qui suit sans rien écrire

- `AllActionKeys()` les inclut → `EnsureSuperadminActions` les accorde à
  `vaultaire_all` au démarrage suivant (INSERT IGNORE, pas de migration SQL).
- Elles sont stockées dans `user_permission_action` (pas de colonne à créer).
- La matrice des permissions (`web_admin_permission_matrix.go`) les affiche dans la
  section des actions spéciales via `SpecialActionKeys()`.

### À écrire

- Libellés lisibles dans la matrice, si la page en porte pour les actions spéciales :
  « Nexus — lecture », « Nexus — publication », « Nexus — administration ».
- `vlt permission` : l'autocomplétion / l'aide des clés, si elle en a une liste.
- Test : les trois clés sont valides, globales, et présentes dans `AllActionKeys()`.
- Test existant qui compte les actions spéciales, s'il y en a un
  (`actions_enroll_dns_test.go` en vérifie une) : ajuster.

### Rattachement dans Nexus (à écrire avec le mode `ducky`)

En mode `ducky`, Nexus déduira le rôle des clés reçues :
`write:nexus_admin` → admin, sinon `write:nexus` → publisher, sinon `read:nexus` ou
simple compte authentifié → reader (réglable). La table `auth.roles` de la
configuration reste utilisable en complément, comme en mode LDAP.

---

## 3. Authentification LDAP — rien à changer, deux réglages

Le mode `ldap` fonctionne **avec le core tel qu'il est**. Deux points à régler côté
exploitation :

1. **Permission `auth`.** `LDAP_bind.go` vérifie la permission `auth` sur le domaine
   **du DN présenté**. Nexus binde en `uid=<compte>,<base_dn>` : le domaine vérifié est
   donc celui de `base_dn` (par exemple `acme.lan`). Les groupes qui doivent utiliser
   Nexus ont besoin de `auth` sur ce domaine, **avec propagation** si leurs comptes
   vivent dans des sous-domaines.
   Alternative : saisir `alice@infra.acme.lan` à la connexion, transmis tel quel.

2. **MFA.** Si `RefuseBindWhenMFARequired` est activé, les comptes soumis au second
   facteur ne peuvent plus se connecter à Nexus. Le mode `ducky` (§ 4) porte le code
   TOTP et lève cette limite.

**Observation (pas bloquante).** `ToRootDN` ne garde que les deux derniers niveaux du
domaine : `memberOf` vaut `cn=Infra,ou=groups,dc=acme,dc=lan` même pour un groupe de
`infra.acme.lan`. Nexus lit donc les groupes par leur **nom**. C'est sûr aujourd'hui
parce que `groups.group_name` est `UNIQUE` dans toute la base ; si cette contrainte
devait tomber (groupes homonymes par domaine), `memberOf` deviendrait ambigu pour tous
les clients LDAP, Nexus compris.

---

## 4. Catégorie de trames `08` — authentification par un service

Spécification complète : **[DUCKY_AUTH.md](DUCKY_AUTH.md)**. Résumé de ce que le
core doit porter :

| Trame | Sens | Nom |
|---|---|---|
| `08_01` | service → core | `service_user_auth` : compte, mot de passe, code TOTP facultatif |
| `08_02` | core → service | `service_user_auth_ok` : compte canonique, nom affiché, groupes, clés Nexus |
| `08_03` | core → service | `service_user_auth_failed` : code et raison |
| `08_04` | service → core | `service_user_refresh` : relire groupes et clés d'un compte |
| `08_05` | core → service | `service_user_refresh_ok` |
| `08_06` | core → service | `service_user_refresh_denied` : compte supprimé, désactivé, droits retirés |
| `08_07` | service → core | `service_usage_report` : agrégats d'utilisation (facultatif) |
| `08_08` | core → service | `service_usage_report_ack` |
| `08_09` | core → service | `service_usage_report_error` |

### Fichiers

| Fichier | Changement |
|---|---|
| `ducky-network/trames_manager/Spliter.go` | `case "08": message = serviceauth.Manager(trames_content, duckysession)` |
| `ducky-network/serviceauth/` (nouveau) | gestionnaire 08 : voir l'ordre des contrôles dans DUCKY_AUTH.md |
| `core/clienttype/clienttype.go` | décommenter `08_01`, `08_04`, `08_07` pour `Nexus` |
| `ducky-network/networkSecurity/CheckIntegrity.go` | **rien** : les trames 08 n'arrivent qu'après `02_03`, quand la session est marquée sûre |
| `docs/Developement/how it work/Protocole_Ducky.md` | ajouter la catégorie au tableau et une section de détail |
| `core/database` (facultatif) | table `service_usage` pour 08_07 |

### Réutilisations — ne rien réécrire

Le gestionnaire 08 doit appeler **les mêmes fonctions** que les portes existantes,
dans le même ordre que `SSH_SEND_Pubkey_AUTH` (03_01) et `LDAP_bind.go` :
limitation de débit (`ratelimit`), compte inconnu = même refus qu'un mauvais mot de
passe, vérification du mot de passe, `passwordpolicy.Check`, second facteur
(`dbauthpolicy.IsMFARequired`, `dbauthpolicy.GetAuthState`, `totp.Validate` puis la
consommation anti-rejeu du compteur, comme `MFAPageHandler`), `permission.IsRevoked`,
`permission.PrePermissionCheck(user, "auth")` sur le domaine du compte, puis
`permission.HasActionAnywhere` pour chacune des trois clés Nexus.

---

## 5. Migrations et scripts existants

Deux endroits listent les types **en dur** et **suppriment** les clients d'un type
inconnu. Appliqués après l'enrôlement d'un Nexus sans être mis à jour, ils
**effaceraient son client** :

| Fichier | Ligne actuelle |
|---|---|
| `deployments/pre-prod/scripts/migrate-clienttype.sh` | `WHERE logiciel_type NOT IN ('vaultaire_client', 'vaultaire_proxy', 'vaultaire_web');` (×2) |
| `docs/migrations/clienttype_catalogue.md` | la même requête (×2) et le tableau des types |

Ajouter `'vaultaire_nexus'` à chaque liste, et une ligne au tableau :

```
| `vaultaire_nexus` | service | enrôlement (01_05 → 01_08) |
```

---

## 6. Interface d'administration et `vlt`

Rien n'est bloquant ; tout est de confort.

- **Page Cluster** : Nexus y apparaît déjà (rôle `vaultaire_nexus`, point d'accès =
  `public_url`, capacités `rpm,deb,docker,vaultaire,generic`). Un libellé lisible pour
  ce rôle et un lien cliquable vers le point d'accès suffisent.
- **Barre latérale** : une entrée « Dépôts (Nexus) » qui ouvre le point d'accès du
  service enregistré, visible si l'utilisateur porte `read:nexus` ou plus
  (`permission.HasActionAnywhere`), comme l'entrée Cluster avec `read:cluster`.
- **Enrôlement** (`web_admin_enroll.go`) : le type apparaît dans la liste déroulante
  via `ServiceNames()` — rien à écrire.
- **`vlt cluster list`** : rien à écrire ; `DisplayClusterNodes` affiche le rôle.
- **`docs/Utilisation/MAN.md` § enroll** : ajouter l'exemple
  `enroll create --type vaultaire_nexus --uses 1 --expires 1h`.

---

## 7. Build, release et déploiement

### `auto-compil.sh`

```bash
NEXUS_BIN="$BUILD_DIR/vaultaire_nexus/vaultaire_nexus"
# … dans le mkdir -p :
         "$BUILD_DIR/vaultaire_nexus"

# -------------------------
# Build Nexus
# -------------------------
# CGO_ENABLED=0 pour la même raison que le proxy : binaire statique, qui tourne
# dans n'importe quelle image. Nexus n'a besoin ni de cgo ni de NSS.
build_go "de Nexus" "$ROOT_DIR/src/vaultaire_nexus" "$NEXUS_BIN" "CGO_ENABLED=0" \
    "$(ldflags_pour vaultaire_nexus/version app) $(ldflags_pour duckynetworkclient/V1/duckynetwork/version)"
cp "$ROOT_DIR/src/vaultaire_nexus/config.example.yaml" "$BUILD_DIR/vaultaire_nexus/"
```

Et le contrôle de version injectée (voir le commentaire « verifier_version » du
script), sur le modèle du proxy.

### `.github/workflows/release.yaml`

```yaml
          paquet vaultaire_nexus  "$B"/vaultaire_nexus/*
```

et `src/vaultaire_nexus/version/version.go` dans la boucle du garde-fou de série.

> ⚠️ `docker-update.sh` vérifie avec `sha256sum -c SHA256SUMS` **tous** les fichiers
> listés mais ne télécharge que `COMPOSANTS`. Ajouter une archive à la release sans
> l'ajouter à `COMPOSANTS` fait échouer la mise à jour de la pré-prod
> (« somme de contrôle invalide »). Deux options :
> - ajouter `vaultaire_nexus` à `COMPOSANTS` (et le déployer en pré-prod), **ou**
> - passer `sha256sum --quiet --ignore-missing -c` dans `docker-update.sh`, en
>   vérifiant que chaque archive de `COMPOSANTS` est bien listée.

### `.github/workflows/dev.yaml`

Le `go vet` parcourt une liste en dur : ajouter `vaultaire_nexus`. `gofmt -l .` le
couvre déjà (fichiers formatés).

### Pré-prod

Un service `vlt-nexus` sur le modèle de `vlt-proxy` : binaire monté depuis
`cmd/vaultaire_nexus/`, volume nommé pour `/var/lib/vaultaire_nexus`, port `8843`,
configuration montée en lecture seule. `src/vaultaire_nexus/deploy/` contient un
Dockerfile autonome (multi-étapes) utilisable tel quel en attendant.

### Ports

Ajouter au tableau des ports du README principal :

```
| 8843 | TCP | Vaultaire Nexus (HTTPS : interface, dépôts, registre Docker) | `listen` (src/vaultaire_nexus) |
```

---

## 8. Documentation du dépôt

- `README.md` (racine) : Nexus dans la liste des composants et dans les ports.
- `docs/Utilisation/Lexique.md` : entrée `vaultaire_nexus`, famille service.
- `docs/exploitation/Releases.md` : ligne de l'archive `vaultaire_nexus-vX.Y.Z-linux-amd64.tar.gz`.
- `docs/Developement/how it work/Versions.md` : `vaultaire_nexus/version`.
- `docs/Developement/how it work/Protocole_Ducky.md` : catégorie 08 (§ 4).

---

## Ordre conseillé

1. **§ 1 + § 5** ensemble (type + listes de migration) → activer `ducky.enable` : Nexus
   apparaît dans le cluster.
2. **§ 7** → Nexus est livré dans les releases.
3. **§ 2** → les clés existent, s'accordent dans la matrice.
4. **§ 4** → `auth.mode: ducky` dans Nexus (et la MFA fonctionne).
5. **§ 6, § 8** au fil de l'eau.
