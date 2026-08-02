# Permissions — modèle RBAC et interface d'administration

Ce document décrit comment les permissions utilisateur sont modélisées, comment
la page d'administration en dérive, et ce qu'il faut toucher pour ajouter un
objet ou un verbe. Il ne couvre pas les permissions **client** (droits des
machines), qui sont un simple couple nom + drapeau admin.

---

## 1. Le modèle en une page

Une clé RBAC est un triplet `catégorie:action:objet`, par exemple
`write:create:user`. Les trois dimensions sont déclarées dans
`core/permission/isValidAction.go` :

| Variable | Contenu actuel |
|----------|----------------|
| `RBACObjects` | `user`, `group`, `client`, `permission`, `gpo` |
| `RBACRead` | `get`, `status` |
| `RBACWrite` | `create`, `delete`, `update`, `add` |

Le produit donne aujourd'hui **30 clés**. Deux ensembles s'y ajoutent, hors
modèle :

| Variable | Contenu | Pourquoi c'est à part |
|----------|---------|-----------------------|
| `legacyActions` | `none`, `web_admin`, `auth`, `compare`, `search` | Héritées du modèle LDAP d'origine. Stockées dans des colonnes de `user_permission`, pas dans `user_permission_action`. |
| `specialActions` | `write:dns`, `write:eyes` | Commandes précises, sans objet au sens RBAC. |

La couche base masque la différence de stockage : `Command_GET_UserPermissionAction`
et `Command_SET_UserPermissionAction` routent vers la colonne ou vers la table
selon `legacyColumns`. **Aucun appelant ne doit refaire ce test.**

### Valeur d'une action

| Valeur | Sens |
|--------|------|
| `nil` | Refus |
| `all` | Accordé sur tous les domaines |
| `(1:a.fr,b.fr)(0:c.fr)` | Accordé sur les domaines énumérés — `1` propage aux sous-domaines, `0` non |

`ParsePermissionAction` lit cette syntaxe, `ConvertPermissionActionToString`
l'écrit, `UpdatePermissionAction` ajoute ou retire un domaine.

---

## 2. Actions à portée globale

Certaines actions sont **toujours** contrôlées contre le domaine `*` :

```go
var globalOnlyActions = []string{"web_admin", "write:dns"}
```

Leur donner une liste de domaines ne les restreint pas — cela les **refuse**,
puisque aucun domaine nommé ne correspond à `*`. Pour `web_admin`, la
conséquence est brutale : l'auteur du changement perd l'accès à l'interface
d'administration, y compris pour se corriger.

L'interface n'affiche donc pas les boutons de domaine sur ces actions, et le
serveur refuse l'opération `add` / `remove` même sur une requête forgée —
l'interface ne doit jamais être la seule barrière.

**Si vous modifiez un appelant** pour qu'il transmette un domaine réel, retirez
l'entrée correspondante de `globalOnlyActions`. Les appelants concernés sont
nommés en commentaire à côté de la déclaration.

---

## 3. La page d'administration

`/admin/permissions` (liste) et `/admin/permissions?perm=NOM` (détail).

### Pourquoi une matrice

Énumérer les clés une par une donnait 37 lignes, chacune portant deux
formulaires. Deux problèmes : on ne pouvait pas répondre d'un coup d'œil à
« qu'est-ce que cette permission autorise ? », et le nombre de formulaires
rendus croissait avec le nombre d'objets.

La page de détail présente donc les clés RBAC en **matrice** : objets en lignes,
verbes en colonnes, une pastille par case résumant la valeur.

| | get | status | create | delete | update | add |
|---|---|---|---|---|---|---|
| Utilisateurs | tous | tous | 2 dom. | — | 2 dom. | — |
| Groupes | tous | tous | — | — | 1 dom. | — |

Ajouter un objet coûte une ligne, ajouter un verbe une colonne.

### L'éditeur unique

Cliquer une case ouvre **un seul formulaire**, sous la matrice, sur l'action
choisie. Un seul éditeur quel que soit le nombre d'actions déclarées : c'est ce
qui rend la page insensible à la croissance du modèle.

Les cases sont de simples liens vers `?perm=…&field=…`. L'éditeur est rendu par
le serveur, en un seul endroit — pas de duplication de la logique d'affichage en
JavaScript, donc rien qui puisse diverger, et la page fonctionne à l'identique
sans JavaScript.

Les domaines accordés sont listés avec un bouton **Retirer** chacun, qui
transmet le domaine et son mode de propagation en champs cachés. Auparavant il
fallait ressaisir le nom du domaine : une faute de frappe affichait « domaine
retiré » sans que rien n'ait changé. Le serveur vérifie maintenant que le
domaine est réellement accordé avant d'annoncer le retrait.

### Découpage en onglets

Détail : **Droits / Groupes / Réglages**. Liste : **Utilisateur / Client /
Créer**. Le script `static/gpo_admin.js` (partagé avec les pages GPO) pose la
classe `.gpo-js` qui active le découpage. Sans lui, tout s'affiche à la suite :
la page redevient longue, jamais inutilisable.

Après une action, le serveur rouvre l'onglet d'origine via le champ caché
`active_tab`, validé contre une liste en dur côté Go — une valeur forgée ne peut
pas atterrir dans un attribut HTML.

---

## 4. Ajouter un objet RBAC

Exemple : l'objet `ticket` du système de ticketing.

### Étape 1 — Déclarer l'objet

```go
// core/permission/isValidAction.go
RBACObjects = []string{"user", "group", "client", "permission", "gpo", "ticket"}
```

C'est tout pour le modèle. `buildValidActions`, `AllRBACActionKeys` et
`IsRBACActionKey` en dérivent, donc les six clés `read:get:ticket` …
`write:add:ticket` deviennent valides partout : CLI, base, interface.

### Étape 2 — Un libellé lisible (facultatif)

```go
// core/web_serveur/web_admin_permission_matrix.go
var rbacObjectLabels = map[string]string{
    …
    "ticket": "Tickets",
}
```

Sans cette entrée, la ligne s'affiche sous son nom technique. Une traduction
manquante dégrade la présentation, elle ne fait pas disparaître la ligne.

### Étape 3 — Contrôler l'accès aux endroits concernés

```go
if !checkWebAdminRBAC(w, r, groupIDs, "read:get:ticket") { return }
```

C'est la seule étape qui demande de la réflexion : déclarer une clé ne protège
rien tant que personne ne la vérifie.

### Ce qui se met à jour tout seul

| | |
|---|---|
| La matrice | Une ligne de plus, alignée sur les colonnes existantes |
| Le formulaire d'édition | Inchangé — il y en a un seul |
| Le HTML | **Rien à toucher** |
| Le CSS | **Rien à toucher** |
| La base | Rien — `user_permission_action` stocke des clés, pas des colonnes |

Ajouter un **verbe** suit la même logique : une entrée dans `RBACRead` ou
`RBACWrite`, une traduction facultative dans `rbacVerbLabels`, et une colonne
apparaît.

---

## 5. Garde-fous à l'écriture

`permissionFieldExists` vérifie que la clé postée est réellement administrable
avant toute écriture. Sans ce contrôle, une clé inventée s'insérerait dans
`user_permission_action` et y resterait : jamais évaluée par le moteur RBAC,
donc sans effet, mais invisible dans l'interface — un déchet silencieux.

Les combinaisons objet × verbe sont **vérifiées et non supposées** au moment de
construire la matrice. Si le modèle cessait d'être un produit cartésien plein,
la case deviendrait grise au lieu d'exposer une clé que le serveur refuserait.

---

## 6. Diagnostic

| Symptôme | Piste |
|----------|-------|
| Une action reste à `nil` après enregistrement | La clé n'existe pas : `permissionFieldExists` a refusé, un message d'erreur s'affiche en haut de page |
| Un droit accordé ne s'applique pas | Le domaine ne correspond pas à celui contrôlé par l'appelant — vérifiez si l'appelant passe `"*"` ou un domaine réel |
| Perte d'accès à `/admin` après édition | `web_admin` est passé à autre chose que `all` ; corriger en base ou via le CLI |
| Une ligne s'affiche sous un nom technique | Entrée manquante dans `rbacObjectLabels` — cosmétique |
