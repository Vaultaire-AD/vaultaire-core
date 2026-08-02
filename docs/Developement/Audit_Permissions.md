# Audit du système de permissions — points ouverts

Audit statique du serveur (`src/vaultaire_serveur`) sur les quatre points
d'entrée : client Ducky, LDAP, CLI (local et distant), interface web.

**Ce fichier ne contient que ce qui reste à traiter.** Les constats corrigés ont
été retirés d'ici et consignés dans `DO/2.0/2.0.md`, entrée 10 — avec le détail
de chaque correction et les points d'attention associés.

Aucune compilation ni exécution n'a été possible pendant l'audit : tout ce qui
suit est un constat de lecture de code, avec le chemin exact.

---

## Récapitulatif

| # | Gravité | Point d'entrée | Constat | Décision |
|---|---------|----------------|---------|----------|
| 1 | **Critique** | Ducky | `04_01` ouvre la session sans authentification et débloque toutes les autres trames | Reporté — 04 expérimental |
| 2 | **Critique** | Ducky | `04_01` crée groupe et domaine en base, sans authentification | Reporté — 04 expérimental |
| 3 | **Moyenne** | LDAP | Le contrôle `search` distingue la propagation, la résolution l'ignore | Reporté — avec les autres sujets LDAP |
| 4 | **Moyenne** | CLI / web | Rien n'empêche d'ajouter un utilisateur au groupe `vaultaire` | **Accepté** — responsabilité administrateur |
| 5 | **Faible** | Transverse | Deux parseurs de permission aux sémantiques divergentes | Ouvert |
| 6 | **Faible** | CLI distant | `vaultaire_ctl` ne vérifie pas le certificat du serveur | Ouvert (relevé pendant les correctifs) |
| 7 | **Note** | Web | `remove_permission` gardé par la mauvaise clé | Ouvert |

---

## 1 et 2. Critique — le chemin `04_01` (reporté)

> **Décision : la partie 04 est expérimentale. À traiter quand le sujet cluster
> sera repris.** Ces deux constats sont conservés ici tels quels pour que le
> travail ne redémarre pas de zéro.

**Chemins :** `ducky-network/networkSecurity/CheckIntegrity.go`,
`ducky-network/sessionmgr/trames.go:82`, `ducky-network/host_handler/handler.go:66`

L'automate d'ordre des trames attend `01_01 → 02_01 → 02_03`. Deux lignes le
court-circuitent :

```go
// CheckIntegrity.go
if lastTrame == "01_01" && newTrame == "04_01" { return true }

// trames.go
if newTrame == "04_01" { s.TrameIsSafe = true }
```

Et en tête de `UpdateConnectionTrame` :

```go
if s.TrameIsSafe { return nil }   // plus aucun contrôle d'ordre ensuite
```

Or `01_01` n'authentifie rien : `Prove_Identity` se contente de renvoyer le
contenu reçu — c'est le *serveur* qui prouve son identité au client.

**Chaîne d'attaque, sans aucune donnée d'authentification :**

1. TCP vers le port Ducky
2. `askkey` → clé publique RSA du serveur, avant toute session
3. `01_01` → clé de session AES établie
4. `04_01` → `TrameIsSafe = true`, **et** création d'un groupe et d'un domaine
   arbitraires (`handleRegisterHost` : `groupName` et `domain` viennent du
   contenu de la trame)
5. Toutes les autres trames deviennent accessibles

**Atténuation depuis l'audit.** L'étape 5 a perdu l'essentiel de son intérêt : le
`ClientSoftwareID` est désormais figé à `01_01` et vérifié à chaque trame (voir
DO/2.0, entrée 10-1). Un attaquant ne peut plus réclamer les GPO ni le sel d'une
machine autre que celle dont il possède la clé privée. **Restent ouverts :** la
création de groupe et de domaine sans authentification, et le fait que la porte
elle-même n'est pas fermée.

**Correction proposée :** ne poser `TrameIsSafe` qu'après une authentification
réellement établie. Le chemin host a besoin de la sienne — un secret de nœud, ou
le même challenge que les clients. Le raccourci `04_01` devrait disparaître.

---

## 3. Moyenne — LDAP : la propagation est contrôlée puis ignorée (reporté)

> **Décision : reporté, à traiter avec les autres sujets LDAP.**

**Chemins :** `core/ldap/LDAP_SEARCH-REQUEST/newmodule/handler.go:31`,
`.../scope/resolver.go:40` et `:100`, `core/domain/GET-GroupsUnderDomain.go:49`

L'autorisation est vérifiée sur le seul domaine de base :

```go
if !security.IsAuthorizedToSearch(session.Username, baseDN) { ... refus }
```

`IsUserAuthorizedToSearch` distingue correctement les deux modes : suffixe pour
`WithPropagation`, égalité stricte pour `WithoutPropagation`. Mais la résolution
qui suit descend systématiquement le sous-arbre :

```go
if dn == target || strings.HasSuffix(dn, "."+target) {
```

Et pour un conteneur `ou=users`, un scope `one-level` est promu en `subtree`
(`resolver.go:40`, pour JumpServer). Résultat : un compte autorisé
`(0:vaultaire.fr)` — sans propagation — énumère l'annuaire entier.

Le reste du chemin LDAP est correct : le bind est bien vérifié
(`DispatchLDAPOperation` refuse tout hors RootDSE avant bind, et restreint
l'anonyme), et l'ensemble est bien en lecture seule.

**Correction proposée :** filtrer les candidats sur les domaines réellement
autorisés plutôt que sur le seul `baseDN`, ou refuser d'élargir le scope quand
la permission est sans propagation.

**À noter pour ce chantier :** `search` est bien une permission vivante, contrôlée
par un chemin distinct du reste (`db_permission.GetUserPermissionsForAction`,
et non `CheckPermissionsMultipleDomains`). Seules `none` et `compare` sont
réellement sans appelant.

---

## 4. Moyenne — l'entrée dans le groupe `vaultaire` reste possible (accepté)

> **Décision : comportement voulu. On garde la possibilité d'ajouter des
> utilisateurs au groupe `vaultaire` ; la responsabilité en revient à
> l'administrateur.** Conservé ici comme point de vigilance, pas comme défaut.

**Chemin :** `core/database/Command_ADD_UserToGroup.go` — aucun appel à
`GuardProtected*`

`core/database/protected.go` protège la suppression, le renommage et le déliage
de l'identité d'amorçage. Il ne protège pas l'entrée : `add -u X -g vaultaire`,
ou l'action `add_user` de la page groupe, font de X un superadmin.

**Ce qui a changé depuis l'audit et limite la portée :** l'opération exige
désormais `write:add:user` sur **tous** les domaines de X, plus le droit sur les
domaines du groupe `vaultaire` (voir DO/2.0, entrée 10-3 et 10-10). Un délégué
d'un seul domaine ne suffit plus.

**Ce qui reste vrai :** quiconque a le droit sur les domaines concernés peut
fabriquer un superadmin. C'est assumé — mais cela veut dire que **déléguer
`write:add:user` revient à déléguer la capacité de créer des superadmins**. À
garder en tête au moment de construire des permissions déléguées, et à
mentionner dans la documentation d'exploitation.

---

## 5. Faible — deux parseurs, deux sémantiques

**Chemins :** `core/permission/parserPermission.go` et
`core/permission/permissionActionParser.go`

| Valeur | `ParsePermissionContent` | `ParsePermissionAction` |
|--------|--------------------------|--------------------------|
| `nil` | `Deny` | type `nil` |
| `all` | `All` | type `all` |
| `*` | **`All`** | type `custom` sans domaine → **refus** |
| `""` | listes vides → refus | type `nil` |

Le CLI et le web passent par le premier, le LDAP et l'affichage de la matrice
des permissions par le second. Une valeur `*` en base autoriserait donc via le
CLI et refuserait via LDAP. Pas exploitable en soi, mais deux parseurs pour un
même format finiront par diverger davantage.

**À signaler dans le même fichier :**
`db_permission/LDAP_GET_IsUserAllowToSearchInADomain.go:17` construit la requête
par concaténation (`SELECT up.` + action). `action` vaut toujours `"search"`
aujourd'hui, donc ce n'est pas exploitable — mais c'est une injection dans un nom
de colonne qui n'attend qu'un second appelant. `SanitizeIdentifier` couvre
désormais ce paramètre, ce qui ferme le risque pratique sans supprimer la
concaténation.

---

## 6. Faible — `vaultaire_ctl` ne vérifie pas le certificat serveur

**Chemin :** `src/vaultaire_ctl/vaultairectl.go`

```go
TLSClientConfig: &tls.Config{InsecureSkipVerify: true}, // ⚠️ en prod remplacer par vérif réelle
```

Le commentaire dit déjà l'essentiel. Conséquence concrète : un attaquant en
position d'interception voit passer les commandes en clair et peut les capturer.
L'anti-rejeu ajouté (DO/2.0, entrée 10-4) rend la capture inexploitable au-delà
de deux minutes, mais ne protège ni la confidentialité des commandes, ni un
rejeu immédiat.

**Correction proposée :** distribuer le certificat du serveur avec la
configuration du client, et le vérifier. C'est un sujet de déploiement plus que
de code — d'où le report.

---

## 7. Note — mauvaise clé sur `remove_permission`

**Chemin :** `core/web_serveur/web_admin_pages.go`, `AdminGroupsHandler`

Retirer une permission d'un groupe est gardé par `write:delete:group` au lieu de
`write:delete:permission`. Ce n'est pas un trou béant, mais un titulaire de
`write:delete:group` sans droit sur les permissions peut dépouiller un groupe de
ses droits.

---

## Ce qui fonctionne

- **Le CLI** : les 20 sous-commandes contrôlent toutes une clé RBAC avant d'agir, avec un log `WARNING` + `SECURITY` en cas de refus. Les routeurs délèguent sans branche qui contourne. Les écritures sont désormais en contrôle strict sur tous les domaines de la cible.
- **L'interface web** : `requireWebAdmin` sur tous les handlers `/admin/*`, puis une clé RBAC par action, vérifiée sur les domaines de l'entité visée.
- **LDAP** : lecture seule effective, bind obligatoire, anonyme cantonné au RootDSE.
- **L'API** : signature SSH vérifiée contre les clés en base, horodatage et nonce à usage unique.
- **Ducky** : identité machine prouvée par construction (chiffrement de `01_02` avec la clé publique du client) et figée pour la durée de la connexion.
- **Les GPO** : restrictions fail-closed, garde machine-only côté serveur *et* côté agent, empreintes couvrant le contenu des définitions.
- **`protected.go`** : gardes posées dans la couche base, donc valables pour tous les appelants — y compris ceux qui seront écrits plus tard.

---

## Limites de cet audit

- **Tout est statique.** Aucune compilation, aucune exécution, aucun test d'intrusion. La chaîne d'attaque `04_01` est déduite de la lecture et mérite d'être confirmée par un test réel avant qu'on y consacre du temps.
- **Non audités :** le serveur DNS (port UDP séparé), le module cluster en profondeur, `vaultaire_proxy` et le SDK `ducky-network-sdk`.
