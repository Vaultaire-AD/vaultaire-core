# Vaultaire Nexus — ce qui a été ajouté au core

> **Statut : appliqué.** Nexus a d'abord été écrit sans toucher au core ; ce
> fichier listait les ajouts nécessaires. Ils ont été validés puis réalisés.
> Il sert désormais de **carte** : où chaque morceau vit, et ce qui reste.
>
> Pour ajouter un autre service de la même façon :
> `docs/Developement/how it work/Nouveau_service.md`.

| § | Ajout | Statut | Où |
|---|---|---|---|
| 1 | Type de client `vaultaire_nexus` | ✅ | `core/clienttype/clienttype.go` |
| 2 | Droits `read:nexus`, `write:nexus`, `write:nexus_admin` | ✅ | `core/permission/isValidAction.go`, matrice web |
| 3 | Droits exposés en LDAP (`vaultaireServiceRights`) | ✅ | `core/ldap/LDAP_SEARCH-REQUEST/newmodule/service_rights.go` |
| 4 | Catégorie de trames `08` (générique, TOTP) | ✅ | `ducky-network/serviceauth/`, `trames_manager/Spliter.go` |
| 5 | Listes de types des migrations | ✅ | `deployments/pre-prod/scripts/migrate-clienttype.sh`, `docs/migrations/clienttype_catalogue.md` |
| 6 | Interface d'administration, `vlt` | ✅ partiel | page Cluster, matrice, `vlt enroll types` |
| 7 | Build, CI, release | ✅ | `auto-compil.sh`, `release.yaml`, `dev.yaml`, `docker-update.sh` |
| 8 | Documentation | ✅ | voir § 8 |

---

## 1. Type de client

```go
Nexus = "vaultaire_nexus"

Frames: 01_01 01_05 01_07 · 02_01 02_03 02_05 02_12 · 04_09 04_12 04_14 · 08_01 08_04
UserRights: read:nexus write:nexus write:nexus_admin
AssertsUser: false
```

- Nexus s'enregistre comme **service** (`04_09`) : rôle `vaultaire_nexus` dans
  `cluster_nodes`, `RoleCluster` inchangé.
- Tests : `clienttype_test.go` (trames autorisées et refusées, catégorie 08
  réservée aux services, `UserRights` filtrés), `role_cluster_test.go`.
- Ajout générique : le champ **`UserRights`** du catalogue (clés qu'un service
  peut apprendre sur un compte) et `clienttype.UserRightsFor`.

À savoir : la purge des services partis (`PurgeDepartedServices`) s'applique à
Nexus — arrêté plus longtemps que le délai, il doit être réenrôlé.

## 2. Droits RBAC

Trois **actions spéciales globales** (`specialActions` + `globalOnlyActions`),
accordées à `vaultaire_all` au démarrage suivant par `EnsureSuperadminActions`.
Libellés lisibles dans la matrice (`specialActionLabels`, affichés à côté de la
clé). Tests : `core/permission/nexus_actions_test.go`, dont la cohérence
catalogue ↔ moteur (`TestUserRightsDuCatalogueSontDesClesConnues`).

Doc : `docs/Developement/how it work/Permissions_RBAC.md` § 5,
`docs/Utilisation/Actions_et_Permissions.md` § « Droits de service ».

## 3. Droits exposés en LDAP

Attribut opérationnel **`vaultaireServiceRights`** sur l'entrée d'un compte :

- calculé **seulement** s'il est demandé nommément (ni `*` ni `+`) ;
- valeurs = clés de service accordées (union des `UserRights` du catalogue) ;
- visible par le compte lui-même, ou par un compte qui a `read:get:user` sur le
  domaine de l'entrée ;
- déclaré dans le sous-schéma.

Tests : `newmodule/service_rights_test.go`. Doc :
`docs/Utilisation/vaultaireLDAP.md`.

Rien à changer pour le bind : il vérifie déjà la permission `auth` sur le domaine
du DN. Nexus en mode LDAP a besoin de `search` pour lire sa propre entrée.

## 4. Catégorie 08 — authentification par un service

Générique : aucun code propre à Nexus. `08_01` (vérifier, TOTP compris),
`08_02`/`08_03` (réponse), `08_04` (relire), `08_05`/`08_06` (réponse) ;
`08_07`–`08_19` réservées. Corrélation par `ref:`.

Ordre des contrôles repris des autres portes : limitation (par compte et par
service), compte, mot de passe, révocation, expiration, second facteur
(`totp.Validate` + `ConsumeMFACounter`), permission `auth` (sur chacun des
domaines du compte quand l'identifiant n'en porte pas), groupes, droits filtrés.
`08_04` ne vaut que pour les comptes présentés par ce service (24 h).

Tests : `ducky-network/serviceauth/handler_test.go`. Doc :
`docs/Developement/how it work/ducky-network/08-authentification-service/`.

**Écart avec la proposition initiale** : le rapport d'utilisation (`08_07`–`08_09`)
n'est pas implémenté ; ces numéros restent réservés.

## 5. Migrations

`'vaultaire_nexus'` ajouté aux deux listes `NOT IN` qui suppriment les clients
d'un type inconnu.

## 6. Interface d'administration et `vlt`

| Fait | Détail |
|---|---|
| Page **Cluster** | les services qui annoncent une URL ont un lien cliquable ; rôle affiché « Nexus (dépôt de paquets) » |
| Matrice des permissions | libellés des actions spéciales, dont les trois clés Nexus |
| `vlt enroll types` | affiche les droits qu'un service apprend |
| Page Enrôlement | le type apparaît via `ServiceNames()` |

**Non fait** : une entrée « Dépôts » dans la barre latérale. Chaque page passe
sa propre structure au gabarit `admin_sidebar.html` ; y ajouter un lien
conditionnel demande un champ commun à toutes les pages. Le lien de la page
Cluster en tient lieu.

## 7. Build, CI, release

| Fichier | Ajout |
|---|---|
| `auto-compil.sh` | build statique de Nexus, version injectée et vérifiée, exemples copiés (`config.example.yaml`, `ducky.example.yaml`, `vaultaire_nexus.service`) |
| `.github/workflows/release.yaml` | archive `vaultaire_nexus-vX.Y.Z-linux-amd64.tar.gz`, `version.go` dans le garde-fou de série |
| `.github/workflows/dev.yaml` | `go vet` de `vaultaire_nexus` |
| `deployments/pre-prod/docker-update.sh` | ne vérifie plus que les archives qu'il installe — chacune doit figurer dans `SHA256SUMS` —, pour qu'une release contenant Nexus ne casse pas la préprod |

## 8. Documentation

| Page | Changement |
|---|---|
| `docs/Developement/how it work/ducky-network/` | **nouveau** : protocole découpé en 8 chapitres (modèle `docs/training`) ; `Protocole_Ducky.md` devient une table de correspondance |
| `docs/Developement/how it work/Nouveau_service.md` | **nouveau** : créer un service de bout en bout |
| `Permissions_RBAC.md`, `MFA_et_Expiration.md`, `Versions.md`, `GPO.md`, `README.md` (dev) | droits de service, second facteur hors portail, liens |
| `docs/Utilisation/Actions_et_Permissions.md`, `vaultaireLDAP.md`, `Lexique.md`, `MAN.md` | droits de service, attribut LDAP, Nexus, enrôlement |
| `docs/exploitation/Releases.md`, `docs/migrations/clienttype_catalogue.md` | archive Nexus, type |
| `README.md` racine, `docs/README.md` | port 8843, liens |

## Reste à faire

- Entrée « Dépôts » dans la barre latérale de l'administration (§ 6).
- Rapport d'utilisation vers le core (`08_07`) et vue « Dépôts » dans
  l'administration.
- Service `vlt-nexus` dans la préprod, sur le modèle de `vlt-proxy`
  (`src/vaultaire_nexus/deploy/` fournit Dockerfile et compose autonomes).
- Bit exécutable de `build.sh` et `test/e2e.sh` : le commit fait depuis Windows
  les a enregistrés en `100644` —
  `git update-index --chmod=+x src/vaultaire_nexus/build.sh src/vaultaire_nexus/test/e2e.sh`.
