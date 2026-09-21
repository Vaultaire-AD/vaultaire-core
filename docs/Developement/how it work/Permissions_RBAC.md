# Permissions — modèle RBAC et interface d'administration

Ce document décrit comment les permissions utilisateur sont modélisées, comment
la page d'administration en dérive, et ce qu'il faut toucher pour ajouter un
objet ou un verbe. Il ne couvre pas les permissions **client** (droits des
machines), qui sont un simple couple nom + drapeau admin.

> **Public : développeurs.** Pour *déléguer* des droits au quotidien, voir
> [`Utilisation/Group-Permission.md`](../../Utilisation/Group-Permission.md) ;
> pour savoir *quel droit* exige telle opération,
> [`Utilisation/Actions_et_Permissions.md`](../../Utilisation/Actions_et_Permissions.md).
> Pour le registre qui applique ces droits, [`Actions.md`](./Actions.md).

---

## 1. Le modèle en une page

Une clé RBAC est un triplet `catégorie:action:objet`, par exemple
`write:create:user`. Les trois dimensions sont déclarées dans
`core/permission/isValidAction.go` :

| Variable | Contenu actuel |
|----------|----------------|
| `RBACObjects` | `user`, `group`, `client`, `permission`, `gpo` |
| `RBACRead` | `get`, `status` |
| `RBACWrite` | `create`, `delete`, `update`, `add`, `remove` |

Le produit donne aujourd'hui **35 clés**. Deux ensembles s'y ajoutent, hors
modèle :

| Variable | Contenu | Pourquoi c'est à part |
|----------|---------|-----------------------|
| `legacyActions` | `none`, `web_admin`, `auth`, `compare`, `search` | Héritées du modèle LDAP d'origine. Stockées dans des colonnes de `user_permission`, pas dans `user_permission_action`. |
| `specialActions` | `write:dns`, `write:eyes`, `write:killswitch`, `read:log`, `write:mfa`, `read:cluster`, `write:cluster`, `read:certificate`, `write:certificate`, `read:dns`, `read:enrollment`, `write:server`, `read:nexus`, `write:nexus`, `write:nexus_admin` | Actions sans objet au sens RBAC — dont les **droits de service** (§ 5). |

### `add` et `remove` : rattacher, détacher

`add` (**Rattacher**) et `remove` (**Détacher**) portent sur l'entité qu'on
rattache à un groupe ou qu'on en retire — le compte, la machine, la permission,
la GPO —, pas sur le groupe :

| Opération | Clé |
|---|---|
| `add -u … -g …` / `remove -u … -g …` | `write:add:user` / `write:remove:user` |
| `add -c … -g …` / `remove -c … -g …` | `write:add:client` / `write:remove:client` |
| `add -gu/-gc … -p …` / `remove -gu/-gc … -p …` | `write:add:permission` / `write:remove:permission` |
| `add -gpo … -g …` / `remove -gpo … -g …` | `write:add:gpo` / `write:remove:gpo` |

**`remove` est récent.** Avant lui, chaque retrait empruntait la clé `delete` de
l'objet : pour sortir un compte d'un groupe, il fallait `write:delete:user` — le
droit de **supprimer des comptes** —, et le donner à un délégué lui ouvrait
aussi la suppression. Détacher ne détruit rien ; `delete` reste le droit de
détruire l'objet lui-même (`delete -u`, `delete -p`, `delete -gpo`…).

À la mise à jour, la migration `rbac_verbe_detacher` recopie **une fois**
chaque `write:delete:<objet>` en `write:remove:<objet>`, portée comprise : un
délégué qui détachait hier détache toujours. Ensuite les deux droits sont
indépendants. La migration est notée dans la table `schema_migrations` et ne se
rejoue pas — sinon elle recopierait aussi les permissions créées après, et
rendrait le détachement à qui on vient de le refuser.

`write:add:group` et `write:remove:group` existent (le produit est complet)
mais **aucune opération ne les vérifie** : on ne rattache pas un groupe à un
groupe. Les accorder n'ouvre rien.

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
var globalOnlyActions = []string{"web_admin", "write:dns", ActionReadLog, …} // extrait
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
| `read:nexus`, `write:nexus`, `write:nexus_admin` | un dépôt Nexus n'appartient à aucun domaine ; c'est le service qui les applique (§ 5) |

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

Énumérer les clés une par une donnait 37 lignes (55 aujourd'hui : 35 clés du
modèle, 5 historiques, 15 spéciales), chacune portant deux formulaires. Deux problèmes : on ne pouvait pas répondre d'un coup d'œil à
« qu'est-ce que cette permission autorise ? », et le nombre de formulaires
rendus croissait avec le nombre d'objets.

La page de détail présente donc les clés RBAC en **matrice** : objets en lignes,
verbes en colonnes, une pastille par case résumant la valeur.

| | get | status | create | delete | update | add | remove |
|---|---|---|---|---|---|---|---|
| Utilisateurs | tous | tous | 2 dom. | — | 2 dom. | 1 dom. | 1 dom. |
| Groupes | tous | tous | — | — | 1 dom. | — | — |

Les colonnes s'intitulent Consulter, État, Créer, Supprimer, Modifier,
**Rattacher**, **Détacher**.

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

### La clé de chaque page

Chaque page d'administration exige la **même clé** que la commande qui lit la
même donnée ; une page qui lit la base directement n'est protégée que par ce
contrôle. `web_cles_des_pages_test.go` en vérifie une partie.

| Page | Clé | Remarque |
|---|---|---|
| Cluster (`/admin/cluster`) | `read:cluster` | était `read:get:client` : qui lisait une seule machine ouvrait la carte des nœuds |
| Arborescence (`/admin/tree`, `/admin/api/ldap-tree`) | `read:get:group`, **filtrée** au périmètre | passe par l'action `domain.list_tree`, comme `eyes -g`. Les comptes d'un groupe n'apparaissent qu'avec `read:get:user` sur son domaine |
| Fiche d'un groupe dans l'arbre (`/admin/api/group-info`) | `read:get:group` sur le domaine du groupe | hors périmètre, répond « introuvable » ; chaque rubrique (membres, machines, permissions, GPO) suit sa propre clé de lecture |

`write:eyes` n'est plus vérifiée nulle part : l'arborescence exigeait ce droit
d'**écriture** pour une page qui ne fait que lire, et montrait tout l'annuaire
à qui le détenait. La clé reste dans le vocabulaire — des permissions existantes
la portent — et la matrice l'affiche comme obsolète.

---

## 4. Ajouter un objet RBAC

Exemple : l'objet `ticket` du système de ticketing.

### Étape 1 — Déclarer l'objet

```go
// core/permission/isValidAction.go
RBACObjects = []string{"user", "group", "client", "permission", "gpo", "ticket"}
```

C'est tout pour le modèle. `buildValidActions`, `AllRBACActionKeys` et
`IsRBACActionKey` en dérivent, donc les sept clés `read:get:ticket` …
`write:remove:ticket` deviennent valides partout : CLI, base, interface.

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

## 5. Droits de service

Un service du cluster qui a ses propres niveaux — lire, publier, administrer —
les reçoit du core sous forme de **clés RBAC dédiées**. Aujourd'hui : Nexus.

| Clé | Rôle Nexus | Accorde |
|---|---|---|
| `read:nexus` | lecteur | lire les dépôts **privés**, rechercher, `docker pull` |
| `write:nexus` | publieur | publier, supprimer une version, `docker push`, réindexer |
| `write:nexus_admin` | administrateur | créer, régler, supprimer des dépôts ; import GitHub ; jetons de tous ; nettoyage |

### Pourquoi des actions spéciales globales

Même raisonnement que le cluster (`ActionReadCluster`) : un dépôt n'appartient à
aucun domaine. Un objet RBAC `nexus` engendrerait sept clés dont quatre
n'accorderaient rien. `write:nexus_admin` et non `admin:nexus` :
`IsRBACActionKey` et les affichages supposent `read` ou `write`.

Elles s'accordent avec `all` ou `nil`. Le périmètre fin (tel dépôt pour tel
groupe) reste dans le service : ce sont des réglages du dépôt, pas des droits
sur l'annuaire.

### Qui les évalue

**Pas le core.** Le core les **transmet** ; le service les **applique**.

| Chemin | Transport | Filtrage |
|---|---|---|
| Réseau Ducky | ligne `rights:` de la trame `08_02` / `08_05` | seules les clés de `UserRights` du type du service ([chapitre 8](./ducky-network/08-authentification-service/README.md)) |
| LDAP | attribut opérationnel `vaultaireServiceRights`, **demandé nommément** | union des `UserRights` du catalogue ; visible par le compte lui-même, ou par un compte qui a `read:get:user` sur son domaine |

Le calcul est le même des deux côtés : `GetGroupIDsForUser` puis
`HasActionAnywhere` pour chaque clé. Un compte révoqué n'a aucun groupe, donc
aucune clé.

Côté LDAP, le code est `core/ldap/LDAP_SEARCH-REQUEST/newmodule/service_rights.go`.
L'attribut n'est pas calculé pour `+` : des navigateurs d'annuaire l'envoient sur
des sous-arbres entiers, et chaque entrée coûterait plusieurs requêtes.

### Ajouter les clés d'un nouveau service

1. Constantes et commentaire dans `isValidAction.go` ; ajout à `specialActions`
   **et** `globalOnlyActions`.
2. Libellé dans `specialActionLabels` (`web_admin_permission_matrix.go`) — la
   clé seule ne dit pas à quel service elle s'adresse.
3. `UserRights` dans l'entrée du type (`core/clienttype`).
4. Tests : `nexus_actions_test.go` sert de modèle ;
   `TestUserRightsDuCatalogueSontDesClesConnues` vérifie la cohérence
   catalogue ↔ moteur.

Guide complet : [`Nouveau_service.md`](./Nouveau_service.md).

---

## 6. Garde-fous à l'écriture

`permissionFieldExists` vérifie que la clé postée est réellement administrable
avant toute écriture. Sans ce contrôle, une clé inventée s'insérerait dans
`user_permission_action` et y resterait : jamais évaluée par le moteur RBAC,
donc sans effet, mais invisible dans l'interface — un déchet silencieux.

Les combinaisons objet × verbe sont **vérifiées et non supposées** au moment de
construire la matrice. Si le modèle cessait d'être un produit cartésien plein,
la case deviendrait grise au lieu d'exposer une clé que le serveur refuserait.

---

## 7. Diagnostic

| Symptôme | Piste |
|----------|-------|
| Une action reste à `nil` après enregistrement | La clé n'existe pas : `permissionFieldExists` a refusé, un message d'erreur s'affiche en haut de page |
| Un droit accordé ne s'applique pas | Le domaine ne correspond pas à celui contrôlé par l'appelant — vérifiez si l'appelant passe `"*"` ou un domaine réel |
| Perte d'accès à `/admin` après édition | `web_admin` est passé à autre chose que `all` ; corriger en base ou via le CLI |
| Une ligne s'affiche sous un nom technique | Entrée manquante dans `rbacObjectLabels` (objets) ou `specialActionLabels` (actions spéciales) — cosmétique |
| Un service ne voit pas les droits d'un compte | Clé absente de `UserRights` du type ; en LDAP, attribut non demandé nommément, ou compte de service sans `read:get:user` |
