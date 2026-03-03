# Manuel Vaultaire — Documentation Wiki

Ce document est rédigé pour alimenter un **wiki** : il regroupe les commandes d’administration, les **commandes DNS** et la **configuration LDAP** de manière claire et structurée.

---

## Table des matières

1. [Présentation](#1-présentation)
2. [Configuration serveur (YAML)](#2-configuration-serveur-yaml)
3. [Configuration LDAP](#3-configuration-ldap)
4. [Commandes principales](#4-commandes-principales)
5. [create — Création](#5-create--création)
   - [5.0 Modèle des permissions (user)](#50-modèle-des-permissions-user)
6. [status — État des sessions](#6-status--état-des-sessions)
7. [clear — Nettoyage des sessions](#7-clear--nettoyage-des-sessions)
8. [get — Consultation](#8-get--consultation)
9. [add — Ajout](#9-add--ajout)
10. [remove — Retrait](#10-remove--retrait)
11. [delete — Suppression](#11-delete--suppression)
12. [update — Mise à jour](#12-update--mise-à-jour)
    - [12.3 Mise à jour des actions d'une permission utilisateur (-pu)](#123-mise-à-jour-des-actions-dune-permission-utilisateur--pu)
13. [eyes — Arborescence LDAP](#13-eyes--arborescence-ldap)
14. [Commandes DNS](#14-commandes-dns)
15. [Référence rapide](#15-référence-rapide)

---

## 1. Présentation

Vaultaire est un contrôleur de domaine / annuaire centralisé. Les administrateurs utilisent :

- **vaultaire** (CLI sur le serveur, via socket) pour les commandes ci-dessous.
- **vaultaire_ctl** (vlt) pour les mêmes commandes à distance via l’API (voir [vaultairectl.md](./vaultairectl.md)).
- L’**interface web** (/admin) pour la gestion des utilisateurs, groupes, permissions, clients et DNS.

Les entités gérées : **Utilisateurs**, **Groupes**, **Permissions** (user et client), **Clients** (machines), **GPO**, **Zones DNS**.

---

## 2. Configuration serveur (YAML)

Fichier typique : `serveur_conf.yaml` (ou équivalent en déploiement).

### 2.1 Extrait commenté

```yaml
serveurlistenport: "6666"

file-path:
  socketpath: "/opt/vaultaire/vaultaire.sock"
  # Les chemins de clés (privatekeypath, publickeypath, privatekeyforlogintoclient, publickeyforlogintoclient)
  # ne sont plus nécessaires - toutes les clés et certificats sont maintenant stockés en base de données
  # ... autres chemins (clientconfpath, logpath, servercheckonlinetimer, etc.)

ldap:
  ldap_enable: true    # LDAP (port 389)
  ldaps_enable: true   # LDAPS (port 636)
  ldap_port: 389
  ldaps_port: 636

dns:
  dns_enable: true     # Active le serveur DNS intégré

database:
  username: root
  password: root
  ip_database: "vaultaire-db"
  port_database: "3306"
  databaseName: "vaultaire"

website:
  website_enable: true
  website_port: 443

api:
  api_enable: true
  api_port: 6643

administreur:
  enable: true
  username: admin
  password: admin123
  public_key: "ssh-rsa ..."
```

**À ne pas oublier** : en production, désactiver `debug` (section debug) et changer les mots de passe / clés.

---

## 3. Configuration LDAP

### 3.1 Côté serveur Vaultaire

- Activer LDAP/LDAPS et les ports dans `serveur_conf.yaml` (voir [§2](#2-configuration-serveur-yaml)).
- Créer un **compte dédié** pour l’application qui fera les requêtes LDAP (ex. `proxmox_ldap_account`).
- Définir le **domaine (base DN)** en fonction de l’arborescence des groupes (`vaultaire eyes -g`).  
  Exemple : pour `it.company.com` → base DN `dc=it,dc=company,dc=com`.

### 3.2 Syntaxe du DN

Toujours séparer chaque niveau avec `dc=` :

- Zone `company.com` → `dc=company,dc=com`
- Sous-domaine `it.company.com` → `dc=it,dc=company,dc=com`
- Sous-domaine `infra.it.company.com` → `dc=infra,dc=it,dc=company,dc=com`

### 3.3 Exemple de configuration client (Keycloak)

| Champ                | Valeur type |
|----------------------|-------------|
| **Connection URL**   | `ldap://<ip_ou_fqdn>` ou `ldaps://...` si TLS |
| **Bind DN**          | `cn=proxmox_ldap_account,dc=company,dc=com` |
| **Bind Credentials** | Mot de passe du compte |

**Utilisateurs (Users DN)** :

| Champ                       | Valeur |
|-----------------------------|--------|
| Users DN                    | `dc=it,dc=company,dc=com` |
| Username LDAP attribute     | `uid` |
| RDN / UUID LDAP attribute   | `uid` |
| User object classes         | `inetOrgPerson`, `organizationalPerson`, `posixaccount`, `person`, `user` |
| Search scope                | One Level |
| Group member attribute      | `member` |

**Groupes (Group Mapping)** :

| Champ                      | Valeur |
|----------------------------|--------|
| LDAP Groups DN             | `dc=it,dc=company,dc=com` |
| Group Name LDAP Attribute   | `cn` |
| Group Object Classes       | `groupOfNames` |
| Membership LDAP Attribute  | `member` |
| Membership Attribute Type  | UID |
| Preserve Group Inheritance | OFF |

**Important** : activer la **RFC 2307** quand c’est possible pour que les utilisateurs soient correctement liés aux groupes.

Pour plus de détails et d’exemples : [vaultaireLDAP.md](./vaultaireLDAP.md).

---

## 4. Commandes principales

| Commande | Description |
|----------|-------------|
| `create` | Créer utilisateur, groupe, permission, client, GPO |
| `status` | Sessions (utilisateurs connectés, clients) |
| `clear`  | Nettoyer les sessions expirées |
| `get`    | Lister / détail utilisateurs, groupes, clients, permissions, GPO |
| `add`    | Ajouter user à un groupe, client à un groupe, permission à un groupe, GPO à un groupe |
| `remove` | Retirer user d’un groupe, client d’un groupe, permission (user/client) d’un groupe, GPO d’un groupe |
| `delete` | Supprimer une entité (user, groupe, permission, client, GPO) |
| `update` | Renommer user, modifier actions d'une permission user (-pu, RBAC / legacy), debug |
| `eyes`   | Arborescence des groupes (forêt LDAP) |
| `dns`    | Gestion DNS (zones, enregistrements, PTR) — voir [§14](#14-commandes-dns) |

---

## 5. create — Création

### 5.0 Modèle des permissions (user)

Les **permissions utilisateur** contrôlent l’accès aux ressources (SSO, API, LDAP, etc.). Chaque permission possède un ensemble d’**actions** configurables par domaine :

- **Valeur par action** : `nil` (refusé), `all` (tous les domaines), ou une liste de domaines avec ou sans propagation.
- **Format des domaines** : `(1:domaine.fr)(0:sous.domaine.fr)` — `1:` = avec propagation (sous-domaines inclus), `0:` = sans propagation.

**Actions disponibles** :

| Type | Actions |
|------|--------|
| **Legacy** | `none`, `web_admin`, `auth`, `compare`, `search` |
| **RBAC** | Format `catégorie:action:objet` — ex. `read:get:user`, `write:create:group` |
| **Spécial** | `write:dns`, `write:eyes` |

**Objets RBAC** : `user`, `group`, `client`, `permission`, `gpo`.  
**Lecture** : `read:get:<objet>`, `read:status:<objet>`.  
**Écriture** : `write:create:<objet>`, `write:delete:<objet>`, `write:update:<objet>`, `write:add:<objet>`.

La configuration se fait via `update -pu` (voir [§12.3](#123-mise-à-jour-des-actions-dune-permission-utilisateur--pu)) ou l’interface web **Admin → Permissions**.

### 5.1 Permission utilisateur

```bash
create -p -u "nom_permission" <description_sans_espace>
```

Crée une permission **user**. Les actions (legacy et RBAC) sont ensuite configurées avec `update -pu` ou depuis l’admin web.

### 5.2 Permission client

```bash
create -p -c "nom_permission" <yes|not>
```

### 5.3 Groupe

```bash
create -g "nom_du_groupe" "domain_name"
```

Exemple : `create -g "IT_Group" "it.company.com"`

### 5.4 Utilisateur

```bash
create -u username domain password birthdate(JJ/MM/AAAA) email
# Option : firstname.lastname pour remplir prénom/nom
create -u user.name domain password birthdate email
# Option : firstname lastname en fin pour priorité
create -u user.name domain password birthdate email firstname lastname
```

Exemples :

```bash
create -u alice company.com secret123 06/02/1992 alice@company.com
create -u bob.lenon company.com strongpass 09/12/1988 bob@company.com
```

### 5.5 Client

```bash
create -c <type_client> <yes|not>
# Option : intégration automatique
create -c <type_client> <yes|not> -join <IP> <Username>
```

### 5.6 GPO

```bash
create -gpo <nom_gpo> [--cmd <commande>]
create -gpo <nom_gpo> --ubuntu <cmd_ubuntu> --debian <cmd_debian> --rocky <cmd_rocky>
```

Exemple : `create -gpo alias --cmd "alias vlt=vaultaire"`

---

## 6. status — État des sessions

### 6.1 Utilisateurs connectés

```bash
status -u
status -u "username"
status -u -g "group_name"
```

### 6.2 Clients connectés

```bash
status -c
status -c <type_client>
status -c -g "group_name"
```

---

## 7. clear — Nettoyage des sessions

Exécute le nettoyage des sessions inactives (sinon exécuté périodiquement).

```bash
clear
```

---

## 8. get — Consultation

### 8.1 Utilisateurs

```bash
get -u
get -u "username"
get -u -g "group_name"
```

### 8.2 Permissions

```bash
get -p -u
get -p -u "permission_name"
get -p -c
get -p -c "permission_name"
```

### 8.3 Groupes

```bash
get -g
get -g "group_name"
get -g -c "group_name"
get -g -u "group_name"
```

### 8.4 Clients

```bash
get -c
get -c "computeur_id"
```

### 8.5 GPO

```bash
get -gpo
get -gpo "nom_gpo"
```

---

## 9. add — Ajout

### 9.1 Utilisateur dans un groupe

```bash
add -u "username" -g "group_name"
```

### 9.2 Client dans un groupe

```bash
add -c "computeur_id" -g "group_name"
```

### 9.3 Permission (user) à un groupe

```bash
add -gu "group_name" -p "permission_name"
```

### 9.4 Permission (client) à un groupe

```bash
add -gc "group_name" -p "permission_name"
```

### 9.5 GPO à un groupe

```bash
add -gpo "gpo_name" -g "group_name"
```

---

## 10. remove — Retrait

### 10.1 Utilisateur d’un groupe

```bash
remove -u "username" -g "group_name"
```

### 10.2 Client d’un groupe

```bash
remove -c "computeur_id" -g "group_name"
```

### 10.3 Permission user d’un groupe

```bash
remove -g "group_name" -pu "permission_name"
```

### 10.4 Permission client d’un groupe

```bash
remove -g "group_name" -pc "permission_name"
```

### 10.5 GPO d’un groupe

```bash
remove -gpo "gpo_name" -g "group_name"
```

---

## 11. delete — Suppression

Supprime l’entité et ses liaisons.

```bash
delete -u "username"
delete -g "group_name"
delete -p -u "permission_name"
delete -p -c "permission_name"
delete -c "computeur_id"
delete -gpo "gpo_name"
```

---

## 12. update — Mise à jour

### 12.1 Renommer un utilisateur

```bash
update -u "username" -uu "new_username"
```

### 12.2 Mode debug

```bash
update -debug true
update -debug false
```

### 12.3 Mise à jour des actions d'une permission utilisateur (-pu)

Modèle :

```bash
update -pu <PermissionName> <ActionKey> <Arg> [ChildOrAll] [Domain]
```

- **PermissionName** : nom de la permission (ex. LDAP_AdminPanel).
- **ActionKey** : clé d’action (voir [§5.0](#50-modèle-des-permissions-user)).
  - **Legacy** : `none`, `web_admin`, `auth`, `compare`, `search`.
  - **RBAC** : `read:get:user`, `read:status:user`, `write:create:user`, `write:delete:user`, `write:update:user`, `write:add:user` (et idem pour `group`, `client`, `permission`, `gpo`).
  - **Spécial** : `write:dns`, `write:eyes`.
- **Arg** :
  - `nil` — aucun accès.
  - `all` — tous les domaines.
  - `-a` — ajouter un domaine (nécessite ChildOrAll et Domain).
  - `-r` — retirer un domaine (nécessite ChildOrAll et Domain).
- **ChildOrAll** (avec -a ou -r) : `0` = sans propagation, `1` = avec propagation (sous-domaines inclus).
- **Domain** (avec -a ou -r) : nom du domaine (ex. company.fr).

Exemples :

```bash
# Autoriser tous les domaines pour auth
update -pu LDAP_AdminPanel auth all

# Refuser
update -pu LDAP_AdminPanel auth nil

# Ajouter un domaine avec propagation
update -pu LDAP_AdminPanel auth -a 1 company.fr

# Retirer un domaine
update -pu LDAP_AdminPanel auth -r 0 legacy.company.fr

# RBAC : autoriser la lecture des utilisateurs sur tous les domaines
update -pu Inspecteur read:get:user all

# RBAC : autoriser la création de clients sur un domaine (avec propagation)
update -pu DevApp write:create:client -a 1 apps.company.fr
```

Si après un `-r` il ne reste plus aucun domaine, l’action repasse en `nil`.

---

## 13. eyes — Arborescence LDAP

Affiche l’arbre des groupes au format forêt LDAP.

```bash
eyes -g
```

Exemple de sortie :

```
├── data
│   └── solution
│       └── test
│           └── * Group: externe (test.solution.data)
└── fr
    └── vaultaire
        ├── * Group: direction (vaultaire.fr)
        ├── admin
        │   ├── * Group: admin (admin.vaultaire.fr)
        │   └── virtu
        │       └── * Group: admin-virtu (virtu.admin.vaultaire.fr)
        └── audit
            └── * Group: audit (audit.vaultaire.fr)
```

Utile pour définir les base DN des clients LDAP.

---

## 14. Commandes DNS

Les commandes DNS s’appellent via le préfixe **`dns`** (en CLI : `dns <sous-commande> ...`). Elles nécessitent la permission **`write:dns`** sur les domaines concernés et que le module DNS soit activé (`dns_enable: true`).

### 14.1 Aide

```bash
dns -h
# ou
dns help
```

### 14.2 Créer une zone

```bash
dns create_zone <nom_de_zone>
```

Exemple : `dns create_zone example.com`

### 14.3 Lister les zones / contenu d’une zone

```bash
dns get_zone
dns get_zone <nom_de_zone>
```

- Sans argument : liste toutes les zones.
- Avec argument : liste les enregistrements de la zone.

### 14.4 Ajouter un enregistrement

```bash
dns add_record <fqdn> <type> <data> <ttl> [priority]
```

- **fqdn** : nom complet (ex. `www.example.com` ou `@.example.com` pour l’apex).
- **type** : A, CNAME, MX, NS, TXT (voir règles ci-dessous).
- **data** : valeur (IP pour A, FQDN pour CNAME/MX/NS, texte pour TXT).
- **ttl** : entier (ex. 300).
- **priority** : optionnel, pour MX (ex. 10).

Exemples :

```bash
dns add_record www.example.com A 192.168.1.1 300
dns add_record mail.example.com CNAME srv.example.com 300
dns add_record @.example.com MX 10 mail.example.com 300
dns add_record @.example.com NS ns1.example.com 300
dns add_record @.example.com TXT "v=spf1 ..." 300
```

Règles (résumé) : A → IP ; CNAME → FQDN ; MX/NS → nom souvent en `@.<zone>` et cible FQDN ; TXT → texte.

### 14.5 Enregistrements PTR (inverse)

Lister les PTR :

```bash
dns get_ptr
```

Les PTR sont gérés via la base (table `ptr_records`). La création peut se faire via des mécanismes internes (ex. enregistrement A avec création PTR automatique selon le code).

### 14.6 Suppression

```bash
dns delete zone <nom.zone>
dns delete record <fqdn> <type>
dns delete ptr <ip>
```

Exemples :

```bash
dns delete zone example.com
dns delete record www.example.com A
dns delete ptr 192.168.1.1
```

### 14.7 Types d’enregistrements supportés

| Type  | Validation |
|-------|------------|
| A     | IP valide, FQDN existant dans une zone |
| CNAME | FQDN valide pour nom et cible |
| MX    | Nom type @.zone, cible FQDN |
| NS    | Idem MX |
| TXT   | Nom @ ou FQDN valide |
| PTR   | Géré séparément (get_ptr, delete ptr) |

---

## 15. Référence rapide

| Besoin | Commande type |
|--------|----------------|
| Créer un user | `create -u user domain pass JJ/MM/AAAA email` |
| Créer un groupe | `create -g "Nom" "domain"` |
| Voir les sessions | `status -u` / `status -c` |
| Détail d’un groupe | `get -g "group_name"` |
| Ajouter user au groupe | `add -u "user" -g "group"` |
| Permission user : tous domaines (auth) | `update -pu PERM auth all` |
| Permission user : un domaine (auth) | `update -pu PERM auth -a 1 domain.fr` |
| Permission user : lecture utilisateurs (RBAC) | `update -pu PERM read:get:user all` |
| Arborescence LDAP | `eyes -g` |
| Zone DNS | `dns create_zone example.com` ; `dns get_zone` ; `dns get_zone example.com` |
| Enregistrement DNS | `dns add_record www.example.com A 192.168.1.1 300` |
| Supprimer zone / record | `dns delete zone example.com` ; `dns delete record www.example.com A` |
| Config LDAP serveur | `serveur_conf.yaml` → section `ldap` |
| Config LDAP client | Voir [§3.3](#33-exemple-de-configuration-client-keycloak) et [vaultaireLDAP.md](./vaultaireLDAP.md) |

---

*Ce manuel est conçu pour être copié dans un wiki (sections, ancres, table des matières). Pour les détails d’exemples de sortie et les cas particuliers, se reporter au [MAN.md](./MAN.md) d’origine.*
