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
| 3 | **Moyenne** | LDAP | Le contrôle `search` distingue la propagation, la résolution l'ignore | Reporté — avec les autres sujets LDAP |
| 5 | **Faible** | Transverse | Deux parseurs de permission aux sémantiques divergentes | Ouvert |
| 6 | **Faible** | CLI distant | `vaultaire_ctl` ne vérifie pas le certificat du serveur | Ouvert (relevé pendant les correctifs) |
| 7 | **Note** | Web | `remove_permission` gardé par la mauvaise clé | Ouvert |


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
