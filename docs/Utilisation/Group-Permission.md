# Explication du fonctionnement des **Groupes** et des **Permissions**

Dans cette Section Vous allez apprendre le fonctionnement des Groupes et
des 2 types de Permissions qui existent dans l'environnement Vaultaire.

## 1.🚀 `Liste des entités`

-   🧑‍💻 **Utilisateurs**
-   📁 **Groupes**
-   🔐 **Permissions**
-   🖥️ **Clients**

## 2.📁 Les groupes

Les groupes sont des dossiers qui servent à regrouper différentes
entités ensemble.

## \### 2.1.❓ À quoi sert un groupe ?

Les groupes servent à gérer plus facilement l'accès et les permissions
des différents utilisateurs aux ressources mises à disposition par le
domaine.

## \### 2.2.🎯 Intérêt de mettre un utilisateur dans un groupe

Un utilisateur hérite automatiquement des permissions associées au
groupe, ce qui simplifie la gestion des droits et évite une
configuration individuelle complexe.

## \### 2.3.🎯 Intérêt de mettre un client dans un groupe

Un client (machine/ressource) placé dans un groupe hérite des
permissions définies pour ce groupe, facilitant la gestion centralisée
des accès.

## \### 2.4.🤝 Relation directe client ↔ user

Si un client et un utilisateur sont dans un groupe commun alors le user
aura accès au client (par défaut sans privilèges administrateur).

## 3.🔐 Les Permissions

Il existe 2 types de permissions : les permissions dites **client** et
les permissions dites **user**.\

## \### 3.1.⚙️ Permission Client

Les permissions Client gèrent les droits que possèdent les users
lorsqu'ils accèdent aux machines via leur groupe.\
C'est via ces permissions que l'on peut donner :\
- des droits d'administration sur une machine,\
- charger des permissions personnalisées pour un user,\
- gérer les partitions qui seront montées sur la machine.

-   ## En **résumé**

    -   Gère les permissions des utilisateurs sur les machines.\
    -   Gère les partitions montées sur les machines.

## \### 3.2.🌍 Permission User (nouvelle gestion)

Les permissions User gèrent l'accès aux ressources **hors client** comme
les services Web, notamment via le SSO.

#### Nouveau système de gestion

Les permissions User ne sont plus stockées comme de simples booléens
mais sous forme **structurée et flexible** :

-   Chaque action (auth, search, compare, etc.) est définie par une
    règle.\
-   Une règle peut être :
    -   `"nil"` → accès refusé.\
    -   `"all"` → accès autorisé à tous les domaines.\
    -   `"custom"` → liste de domaines précis avec ou sans propagation.

#### Exemple de format :

    (1:infra.company.fr,it.company.fr)(0:finance.company.fr)

-   `1:` → domaine avec **propagation** (les sous-domaines sont
    inclus).\
-   `0:` → domaine sans propagation (uniquement ce domaine précis).

#### Liste des actions possibles (RBAC)
-   **Attention** : le `nil` n'a pas la priorité si un user est dans plusieurs groupes ; si un groupe a `all` ou `custom`, cela prévaut.
-   **Format** : `<catégorie>:<action>:<objet>`. Commande : `update -pu <perm> <action_key> nil|all|-a|-r ...`

-   `none` → action neutre / désactivée.
-   `web_admin` → accès à l'interface d'administration Web.
-   `auth` → autorisation d'authentification (si désactivé, l'utilisateur ne peut pas se connecter ; à utiliser avec un groupe de quarantaine dédié).
-   `compare` → comparaison LDAP/ressource (authentification).
-   `search` → recherche d'objets (LDAP, base de données, etc.).
-   **RBAC** (table `user_permission_action`) : clés `read:get:user`, `read:status:user`, `write:create:user`, `write:delete:user`, `write:update:user`, `write:add:user` (idem pour `group`, `client`) + `write:dns`, `write:eyes`.
-   Exemples (CLI) : l’admin et l’`vaultaire update -pu Inspecteur read:get:user all` ; `vaultaire update -pu DevApp write:create:client -a 1 apps.interne`.

## 📖 **CONVENTION**

Pour la nomenclature du domaine il est recommandé de :\
- Créer les Permission User = `U_nomdelaperm`\
- Créer les Permission Client = `C_nomdelaperm`
