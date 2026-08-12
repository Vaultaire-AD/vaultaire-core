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
| `specialActions` | `write:dns`, `write:eyes`, `write:killswitch`, `read:log`, `write:mfa` | Actions sans objet au sens RBAC. |

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

## 1 bis. Comment une clé est exigée : les trois portées

Détenir `read:get:user` sur `paris` doit permettre de **voir les utilisateurs de
paris**. Encore faut-il que l'action sache quoi exiger. Trois cas, déclarés sur
chaque action dans `core/action` :

| Déclaration | Ce qui est exigé | Pour quoi |
|---|---|---|
| *(défaut)* | la clé sur **tous** les domaines de la cible | les **écritures**. Un compte à cheval sur `paris` et `lyon` ne se modifie qu'avec le droit sur les deux : le geste porterait aussi sur `lyon`. |
| `UnDomaineSuffit` | la clé sur **au moins un** des domaines de la cible | la **lecture d'une entité**. Ce même compte m'est légitimement visible si j'administre `paris` : me le cacher m'empêcherait de constater qu'il y est. |
| `PorteeOuverte` | la clé **quelque part**, puis le `Filtre` réduit le résultat | les **listes**. « As-tu quelque chose à faire ici ? » ouvre la vue ; « qu'as-tu le droit de voir ? » décide du contenu. |

### Le piège, et pourquoi il a coûté un cycle

`PorteeOuverte` n'existait pas. Les onze listes d'entités déclaraient
`Portee: PorteeGlobale` + `UnDomaineSuffit` + un filtre, ce qui se lit
naturellement comme « le droit sur un domaine ouvre la liste ».

Ce n'est pas ce que ça faisait. `PorteeGlobale` rend la liste de domaines
`["*"]`, et « au moins un des domaines de cette liste » n'a qu'**un seul
candidat** : `*`. Ces lectures exigeaient donc le droit **global**, et le filtre
écrit pour chacune n'était jamais atteint.

Symptômes, tous dus à cette seule cause :

```
$ vlt get -u
Permission refusée : * : refusée

[WARNING] Action 'read:get:user' refusée sur le domaine '*' (aucune règle applicable dans les groupes [11])
[ERROR]   webadmin: list users failed: permission refusée pour user.list (read:get:user)
```

Le portail, lui, laissait bien entrer — il pose la bonne question,
`HasActionAnywhere` — puis l'action qu'il appelait refusait. La page s'ouvrait
sur une erreur, ce qui a fait chercher du côté de l'affichage.

> **Le contrôle qui ferme la classe de défaut.** `PorteeGlobale` + un `Filtre`
> sans `PorteeOuverte` est désormais **refusé à l'enregistrement**, donc au
> démarrage du serveur : exiger `*` puis filtrer est contradictoire, qui détient
> `*` n'a rien à se voir filtrer. Symétriquement, `PorteeOuverte` sans filtre est
> refusée — elle rendrait tout à qui détient le droit sur un seul domaine.

La propagation (`1:` / `0:`) n'était pour rien dans l'affaire : elle n'entrait
jamais en jeu, l'exigence portant sur `*`.

---

## 2. Actions à portée globale

Certaines actions sont **toujours** contrôlées contre le domaine `*` :

```go
var globalOnlyActions = []string{"web_admin", "write:dns", "read:log"}
```

Leur donner une liste de domaines ne les restreint pas — cela les **refuse**,
puisque aucun domaine nommé ne correspond à `*`. Pour `web_admin`, la
conséquence est brutale : l'auteur du changement perd l'accès à l'interface
d'administration, y compris pour se corriger.

L'interface n'affiche donc pas les boutons de domaine sur ces actions, et le
serveur refuse l'opération `add` / `remove` même sur une requête forgée —
l'interface ne doit jamais être la seule barrière.

La liste réelle, dans `core/permission/isValidAction.go` :

| Clé | Pourquoi elle ne se délègue pas |
|---|---|
| `web_admin` | ouvre l'interface d'administration : c'est un accès, pas un périmètre |
| `read:log` | une ligne de journal n'appartient à aucun domaine, et elle porte l'activité de **tout** le parc |
| `read:dns`, `write:dns` | une zone DNS n'est pas une entité de l'annuaire |
| `read:enrollment` | une clé d'enrôlement n'appartient à aucun domaine |
| `read:cluster`, `write:cluster` | un nœud du cluster n'appartient à aucun domaine |
| `read:certificate`, `write:certificate` | un certificat sert tout le serveur ; le régénérer ou le supprimer coupe le service pour tout le monde |
| `write:server` | un réglage du serveur — mode debug, purge des sessions — engage l'ensemble |

Ces clés s'accordent avec **`all`**, ou pas du tout. Leur donner une liste de
domaines les refuse.

> Le cas DNS est traité comme booléen **par choix**, pas par impossibilité : une
> zone pourrait un jour être rattachée à un domaine de l'annuaire, et la clé
> deviendrait alors déléguable comme les autres. Tant que ce lien n'existe pas,
> la restreindre par domaine ne ferait que la refuser.

Les actions du registre qui portent ces clés gardent donc `PorteeGlobale` **sans**
`PorteeOuverte`. Le `UnDomaineSuffit` qu'elles portaient a été retiré : il ne
faisait rien — « au moins un de `["*"]` » n'a qu'un candidat — et laissait croire
à une souplesse inexistante. C'est exactement la confusion décrite en §1 bis.

**Si vous modifiez un appelant** pour qu'il transmette un domaine réel, retirez
l'entrée correspondante de `globalOnlyActions`. Les appelants concernés sont
nommés en commentaire à côté de la déclaration.

`read:log` est dans cette liste pour une raison différente des deux autres : ce
n'est pas l'appelant qui impose `*`, c'est la donnée qui n'a pas de domaine. Une
ligne de journal enregistre une tentative d'authentification ou un refus de
permission ; elle n'appartient à aucun domaine de l'annuaire, et la restreindre
n'aurait donc pas de sens.

### `read:log` — consultation des journaux

Sépare l'audit de l'administration. Auparavant les pages `/admin/logs` et
`/admin/api/logs` étaient adossées à `read:get:user` : quiconque pouvait
consulter l'annuaire d'un seul domaine lisait l'activité de **tout le parc** —
tentatives d'authentification, refus de permission, déclenchements de kill
switch, toutes machines confondues.

Le droit est désormais distinct dans les deux sens : on peut confier l'audit à
quelqu'un qui n'administre rien, et administrer un domaine sans lire les
journaux des autres.

### `write:mfa` — second facteur

Réinitialise le second facteur d'un compte (téléphone perdu) et règle
l'exigence `mfa_required` d'un groupe.

**N'est PAS dans `globalOnlyActions`**, contrairement aux deux précédentes : un
second facteur appartient à un compte, qui appartient à des domaines. Le droit se
délègue donc par domaine comme les autres droits sur les utilisateurs, et il est
vérifié en contrôle strict — sur **tous** les domaines de la cible.

Séparé de `write:update:user` dans les deux sens : débloquer un téléphone est une
tâche de support qui ne doit pas emporter le droit de reconfigurer des comptes,
et gérer l'annuaire au quotidien ne doit pas permettre de retirer discrètement le
second facteur d'un administrateur.

Détails dans [`MFA_et_Expiration.md`](./MFA_et_Expiration.md).

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
