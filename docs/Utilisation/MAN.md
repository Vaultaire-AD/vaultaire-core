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
   - [5.6 GPO](#56-gpo) — modèle déclaratif, restrictions, définitions
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
16. [certificate — Certificats TLS](#16-certificate--certificats-tls)
17. [kill — Verrouillage d'urgence](#17-kill--verrouillage-durgence)
18. [mfa — Second facteur et mots de passe](#18-mfa--second-facteur-et-mots-de-passe)
19. [enroll — Clés d'enrôlement](#19-enroll--clés-denrôlement)
20. [gpo — Application et conformité](#20-gpo--application-et-conformité)
21. [cluster — Nœuds du parc](#21-cluster--nœuds-du-parc)
22. [settings — Durées d'exploitation](#22-settings--durées-dexploitation)

---

## 1. Présentation

Vaultaire est un contrôleur de domaine / annuaire centralisé. Les administrateurs utilisent :

- **vaultaire** (CLI sur le serveur, via socket) pour les commandes ci-dessous.
- **vaultaire_ctl** (vlt) pour les mêmes commandes à distance via l’API (voir [vaultairectl.md](./vaultairectl.md)).
- L’**interface web** (/admin) pour la gestion des utilisateurs, groupes, permissions (utilisateur et client), clients, GPO et DNS.

Le **détail d'un groupe** (`/admin/groups?group=<nom>`) rassemble tout ce qui est
attaché au groupe : membres, clients, permissions utilisateur, permissions
client et GPO — chacun avec son ajout et son retrait, et un lien vers la fiche
de l'élément.

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
  # ... autres chemins (clientconfpath, logpath, etc.)
  #
  # servercheckonlinetimer a QUITTÉ ce fichier : les durées d'exploitation
  # vivent en base — voir §22. Une ligne laissée ici produit un avertissement
  # au démarrage plutôt que d'être ignorée en silence.

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
| `create` | Créer utilisateur, groupe, permission, client, GPO (`-gpo <nom> --scope <machine\|user>`) |
| `status` | Sessions (utilisateurs connectés, clients) |
| `clear`  | Nettoyer les sessions expirées |
| `get`    | Lister / détail utilisateurs, groupes, clients, permissions, GPO |
| `add`    | Ajouter user à un groupe, client à un groupe, permission à un groupe, GPO à un groupe |
| `remove` | Retirer user d’un groupe, client d’un groupe, permission (user/client) d’un groupe, GPO d’un groupe |
| `delete` | Supprimer une entité (user, groupe, permission, client, GPO) |
| `update` | Renommer user, modifier actions d'une permission user (-pu, RBAC / legacy), debug |
| `eyes`   | Arborescence des groupes (forêt LDAP) |
| `dns`    | Gestion DNS (zones, enregistrements, PTR) — voir [§14](#14-commandes-dns) |
| `certificate` | Certificats TLS du serveur : LDAPS, portail web, API — voir [§16](#16-certificate--certificats-tls) |
| `kill`   | Verrouillage d’urgence d’un compte — voir [§17](#17-kill--verrouillage-durgence) |
| `mfa`    | Second facteur et politique d’expiration des mots de passe — voir [§18](#18-mfa--second-facteur-et-mots-de-passe) |
| `enroll` | Clés d’enrôlement des clients **service** — voir [§19](#19-enroll--clés-denrôlement) |
| `gpo`    | État d’application et de conformité des GPO du parc — voir [§20](#20-gpo--application-et-conformité) |
| `cluster`| Nœuds enregistrés et délai de purge — voir [§21](#21-cluster--nœuds-du-parc) |
| `settings`| Durées d'exploitation du serveur — voir [§22](#22-settings--durées-dexploitation) |
| `help`   | Liste les commandes. Chaque commande accepte `-h`. |

> Chaque commande répond à `-h` avec sa syntaxe à jour. En cas de désaccord entre ce manuel et `vlt <commande> -h`, **c’est l’aide qui fait foi** : elle vit dans le même fichier que le code qui l’applique.

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
| **Spécial** | `read:log`, `read:dns`, `write:dns`, `write:mfa`, `write:killswitch`, `read:enrollment`, `read:cluster`, `write:cluster`, `read:certificate`, `write:certificate`, `write:server` |

**Objets RBAC** : `user`, `group`, `client`, `permission`, `gpo`.  
**Lecture** : `read:get:<objet>`, `read:status:<objet>`.  
**Écriture** : `write:create:<objet>`, `write:delete:<objet>`, `write:update:<objet>`, `write:add:<objet>`.

La configuration se fait via `update -pu` (voir [§12.3](#123-mise-à-jour-des-actions-dune-permission-utilisateur--pu)) ou l’interface web **Admin → Permissions**.

#### Ce qu'un droit sur un domaine précis vous donne

```bash
update -pu lecture read:get:user -a 1 paris.fr   # paris.fr et ses sous-domaines
update -pu lecture read:get:user -a 0 paris.fr   # paris.fr seul
get -u                                            # les utilisateurs de paris.fr
```

| Vous voulez | Il vous faut |
|---|---|
| **lister** des entités | le droit sur **un domaine quelconque** — la liste est réduite à votre périmètre |
| **consulter** une entité | le droit sur **un** de ses domaines |
| **modifier** une entité | le droit sur **tous** ses domaines |

Certains droits ne se délèguent **pas** par domaine et s'accordent avec `all` ou
pas du tout : `web_admin`, `read:log`, `read:dns`, `write:dns`,
`read:enrollment`, `read:cluster`, `write:cluster`, `read:certificate`,
`write:certificate`, `write:server`.

> 📘 **Détail, exemples et raisons** : [`Group-Permission.md`](./Group-Permission.md).
> **Quel droit pour quelle opération** : [`Actions_et_Permissions.md`](./Actions_et_Permissions.md).

### 5.1 Permission utilisateur

```bash
create -p <nom_permission> <oui|non> [--desc "texte"]
```

Le second argument accorde ou non l’accès à l’**administration web**.

> ⚠️ La syntaxe documentée ici jusqu’à la version 2.1 — `create -p -u "nom" <description>` — n’a jamais existé : `-u` était pris pour le nom de la permission. De même, `<yes|not>` n’est pas accepté : `not` n’a jamais figuré parmi les valeurs booléennes reconnues.

**Valeurs booléennes acceptées**, partout dans `vlt` : `oui|non`, `yes|no`, `true|false`, `on|off`, `1|0`.

Une permission naît **sans aucun droit RBAC** : elle n’autorise rien tant qu’elle n’est pas réglée.

```bash
create -p lecture non --desc "Consultation de l'annuaire"
update -pu lecture read:get:user all      # lui donner un droit
get -p -u lecture                          # vérifier
add -gu IT_Group -p lecture                # la rattacher à un groupe
```

### 5.2 Permission client

```bash
create -pc <nom_permission> <oui|non>
```

Le second argument accorde l’administration aux **machines** du groupe qui portera la permission — ce n’est pas le même privilège que le `web_admin` de `-p`.

```bash
create -pc postes-admin oui
get -p -c postes-admin
add -gc IT_Group -p postes-admin
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
create -c <oui|non>
# Option : intégration automatique
create -c <oui|non> -join <hôte[:port]> <Username>
```

Le paramètre `<oui|non>` indique si l'agent tourne sur un serveur membre. Ce
n'est pas un type : c'est le même binaire, qui émet les mêmes trames et ouvre
seulement un tunnel machine en plus.

> ⚠️ Ce manuel écrivait `<yes|not>`. `not` **n'est pas accepté** — les valeurs booléennes reconnues sont `oui|non`, `yes|no`, `true|false`, `on|off`, `1|0`.

Le port de `-join` est facultatif et vaut 22. Une adresse IPv6 suivie d'un port s'écrit entre crochets.

**Le type de client n'est plus demandé.** Cette commande ne peut créer qu'un
**agent** — un programme installé sur une machine du parc, dont le core génère la
paire de clés et produit la configuration.

Un **client service** — interface web, proxy, extension — ne se crée pas ici. Il
s'enrôle lui-même en présentant une clé d'enrôlement, et génère sa paire sur son
propre hôte pour que sa clé privée ne voyage jamais :

```bash
enroll create --type vaultaire_web --uses 1 --expires 30m
enroll types      # le catalogue des types connus
```

Voir `enroll -h` et `docs/Developement/Architecture_Services.md`.

### 5.6 GPO

```bash
create -gpo <nom_gpo> --scope <machine|user> [--desc "description"]
```

Exemple : `create -gpo durcissement_ssh --scope machine --desc "Baseline SSH du domaine"`

Une GPO ne contient **jamais** de commande ni de script : elle est une liste de
**modules** choisis dans un catalogue figé côté serveur, chacun paramétré par les
seuls champs de son schéma. Les options `--cmd`, `--ubuntu`, `--debian` et
`--rocky` de l'ancien modèle n'existent plus.

Le **scope** est définitif et détermine deux choses :

| Scope | Quand elle s'applique | Modules disponibles |
|-------|-----------------------|---------------------|
| `machine` | Au démarrage du client puis par rafraîchissement périodique, indépendamment de l'utilisateur connecté | Tous, y compris ceux touchant aux privilèges (SSH serveur, sudo, sysctl, paquets, services) |
| `user` | Après une authentification réussie, pour l'utilisateur authentifié | Uniquement les modules sans effet sur les privilèges (environnement, tâches planifiées user, fichiers sous le home) |

Cette séparation est le garde-fou anti-élévation de privilège : les modules
`machine` sont refusés dans une GPO `user` côté serveur **et** côté agent, même
si la politique est signée par le serveur central.

L'ajout et l'édition des modules se font depuis l'interface web
**Admin → GPO**, où les formulaires sont générés depuis le catalogue.

#### Restrictions et besoins custom

Ce que les modules acceptent comme valeurs n'est pas figé dans le code : les
listes vivent en base et s'éditent dans **Admin → GPO → Restrictions**, page
réservée aux membres du groupe superadmin `vaultaire`. Chaque modification est
journalisée en `SECURITY` avec son auteur.

Chaque champ à domaine dynamique a un **mode** :

| Mode | Comportement | Quand l'utiliser |
|------|--------------|------------------|
| `list` | Seules les valeurs énumérées passent | Cas normal : on déclare explicitement `mon-monitoring.service` ou un paquet interne |
| `pattern` | Toute valeur conforme à une expression régulière passe | Familles de valeurs : `^[a-z0-9@._-]+\.(service\|socket\|timer)$` |
| `free` | Aucune contrainte de domaine | Champ totalement ouvert |

Le **motif d'exclusion** (`deny_pattern`) est prioritaire dans les trois modes :
c'est ce qui permet d'ouvrir largement un champ tout en gardant des refus fermes
(ex. mode motif sur les unités systemd, mais exclusion de `^(sshd|systemd-)`).

Sont également éditables : les emplacements de fichiers autorisés et refusés (par
scope), et les variables d'environnement interdites.

**Où vivent ces valeurs.** Uniquement en base, dans `gpo_restriction`,
`gpo_field_rule` et `gpo_value_definition`. Aucune liste n'existe en dur dans le
code Go. Le socle initial est un script SQL embarqué dans le binaire
(`core/database/db_gpo/seed/gpo_seed.sql`), exécuté **une seule fois** : au
premier démarrage, quand les tables n'existent pas encore. Deux conséquences
pratiques :

- une valeur supprimée depuis l'interface ne réapparaît **jamais** au
  redémarrage — il n'y a rien pour la réécrire ;
- pour revenir au socle initial, il faut le demander explicitement via le bouton
  **Réinitialiser** (purge puis rejeu du script, réservé au groupe superadmin et
  journalisé).

Seule exception : les *règles de champ* (le mode et les motifs) sont vérifiées à
chaque démarrage et créées si absentes. Une règle n'est pas une valeur, c'est la
définition de la façon dont le champ se valide ; un champ ajouté au catalogue
sans règle refuserait tout sur les bases existantes. Les règles déjà présentes,
même modifiées, ne sont jamais écrasées.

**Si la base ne répond pas.** La lecture des restrictions est *fail-closed* :
aucune valeur n'est considérée comme autorisée, donc aucune GPO ne valide ni ne
s'applique, et un bandeau l'indique dans l'interface. Il n'y a volontairement
aucun repli sur un socle interne — un repli rétablirait le temps de la panne des
valeurs que vous auriez retirées.

**Champs à contenu (définitions).** Certains champs ne se contentent pas d'un
nom. Un *jeu de commandes sudo* porte un nom — utilisé comme valeur dans la GPO —
et la liste réelle des commandes qu'il autorise, qui est ce que l'agent rend dans
le fichier `/etc/sudoers.d/` généré. Créer un jeu custom se fait entièrement
depuis l'interface, sans code côté agent :

```
Nom      : monitoring_ops
Contenu  : /usr/bin/systemctl restart mon-monitoring.service
           /usr/bin/journalctl -u mon-monitoring.service
```

Une commande par ligne, chemin absolu obligatoire, arguments fixes acceptés ;
`ALL` seul autorise tout. Les métacaractères shell et les jokers sont refusés :
sans cela, `/bin/sh` ou `/usr/bin/*` rendrait le jeu équivalent à un accès root
complet sans que ce soit visible dans son nom. Une définition encore référencée
par un module de GPO ne peut pas être supprimée.

Le mécanisme est générique : un futur module dont un champ a besoin d'un contenu
se branche en déclarant un `PayloadKind` et son validateur dans
`core/gpo/payload.go` — rien à modifier dans la couche base ni dans l'interface.

**Récapitulatif par module :**

| Module | Champ extensible | Comment |
|--------|------------------|---------|
| Service systemd | `systemd_service/service` | Ajouter l'unité (liste) ou ouvrir une famille (motif), puis en choisir l'état comme n'importe quelle autre |
| Paquet logiciel | `package/package` | Ajouter le nom du paquet ; présence, absence et version épinglée suivent |
| Paramètre noyau | `sysctl/key` et `sysctl/value` | Ajouter la clé ; élargir le motif de `sysctl/value` si elle attend une valeur non numérique |
| Droits sudo | `sudoers_rule/command_set` | Créer une définition : un nom et sa liste de commandes |
| Tâche planifiée user | `user_cron/command_id` | Ajouter l'identifiant — nécessite l'implémentation correspondante côté agent |
| Fichier | (règles de chemin) | Emplacements autorisés / refusés par scope |
| SSH serveur | — | Jeu de directives fixe, volontairement non extensible |
| Variable d'environnement | (liste d'interdits) | Retirer ou ajouter une variable interdite |

#### Identité d'amorçage protégée

L'utilisateur `vaultaire`, le groupe `vaultaire` et les permissions
`vaultaire_all` / `vaultaire_admin` ne sont ni supprimables ni renommables, et le
compte ne peut pas être retiré de son groupe. Les refus sont posés dans la couche
base, donc valent pour le CLI, l'interface web, LDAP et l'API. Le **changement de
mot de passe du compte `vaultaire` reste autorisé** : le compte naît avec un mot
de passe par défaut connu, bloquer sa rotation serait contre-productif.

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
get -gpo              # liste : nom, scope, version, activation, nb de modules, groupes liés
get -gpo "nom_gpo"    # détail : métadonnées, groupes, puis modules dans leur ordre d'application
```

Le détail affiche aussi l'**empreinte** de la politique (SHA-256 de sa forme
canonique). C'est ce hash qui décidera, côté agent, s'il faut réappliquer la GPO :
il change dès qu'un module, un paramètre ou la version bouge, et il est stable
quel que soit l'ordre de lecture en base.

Les droits requis suivent les domaines des groupes liés à la GPO. Une GPO sans
groupe ne couvre aucun domaine : la consultation exige alors le droit global,
pour qu'une GPO en attente de rattachement ne soit pas visible ou modifiable par
n'importe quel délégué.

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

### 9.6 Clé publique SSH à un compte

```bash
add -u "username" -k "libellé" "ssh-ed25519 AAAAC3Nz…"
```

Le **libellé** est obligatoire : c'est lui qui permettra de retirer la clé plus tard (`remove -u "username" -k <id>`).

> Une clé publique donne un accès SSH au compte **sans mot de passe**, sur toutes les machines du parc où il est provisionné, et son titulaire n'a aucune raison d'aller inspecter la liste de ses clés. L'opération exige donc `write:update:user` sur les domaines du compte visé, et elle est tracée.

**Types acceptés** : `ssh-rsa`, `ssh-ed25519`, `ecdsa-sha2-nistp256|384|521`, et leurs variantes `sk-…@openssh.com`.
`ssh-dss` (DSA) est refusé : OpenSSH le désactive par défaut depuis la version 7.0, et la clé serait acceptée ici pour être ensuite ignorée par le serveur SSH — un échec de connexion sans cause visible.

Une clé n'appartient qu'à **un seul compte** : la contrainte est globale, parce que l'API authentifie par signature SSH. Une clé partagée entre deux comptes permettrait à son porteur d'agir sous l'une ou l'autre identité, au choix, à chaque requête.

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
remove -gu "group_name" -p "permission_name"
```

### 10.4 Permission client d’un groupe

```bash
remove -gc "group_name" -p "permission_name"
```

> ⚠️ Ce manuel documentait `remove -g "group" -pu "perm"` et `remove -g "group" -pc "perm"`. Ces formes **n’existent pas** : c’est le drapeau du groupe qui porte le type (`-gu` / `-gc`), et `-p` désigne la permission — symétrique de `add`.

### 10.5 GPO d’un groupe

```bash
remove -gpo "gpo_name" -g "group_name"
```

### 10.6 Clé publique SSH d’un compte

```bash
remove -u "username" -k <id_clé>
```

L’identifiant se lit dans `get -u "username"`. Le retrait vérifie que la clé appartient bien au compte visé : sans ce contrôle, un délégué autorisé sur un compte pourrait supprimer la clé d’un autre en devinant un identifiant — un entier, donc facile à parcourir.

> `remove` **détache**, il ne supprime pas. Retirer un utilisateur d’un groupe ne supprime pas son compte : voir [§11](#11-delete--suppression).

---

## 11. delete — Suppression

Supprime l’entité et ses liaisons.

```bash
delete -u "username"        # supprime le compte et le révoque sur tout le parc
delete -g "group_name"
delete -c "computeur_id"    # retire la machine de l'annuaire
delete -p "permission_name" # permission utilisateur
delete -gpo "gpo_name"
```

> ⚠️ Ce manuel documentait `delete -p -u "perm"` et `delete -p -c "perm"`. La première forme prend `-u` pour le nom de la permission ; la seconde n’existe pas — **la suppression d’une permission client n’a pas de commande** et se fait depuis l’interface web (**Admin → Permissions**).

**Notes :**

- `-u` la suppression **révoque** le compte sur les machines : celles qui sont hors ligne le nettoieront à leur reconnexion. Vous ne pouvez pas supprimer votre propre compte.
- `-c` retire la machine de l’annuaire mais **ne désinstalle pas** l’agent, qui reste en place sur le poste.

---

## 12. update — Mise à jour

### 12.1 Changer le mot de passe d’un utilisateur

```bash
update -u "username" -p <nouveau mot de passe>
```

Le mot de passe occupe **tous les arguments restants** : les espaces qu’il contient sont conservés.

> ⚠️ Ce manuel documentait `update -u "username" -uu "new_username"`. Le renommage **n’existe pas en ligne de commande** ; il se fait depuis la page profil ou l’administration web, qui reporte le nom sur les sessions ouvertes et émet un jeton neuf — ce qu’un simple `UPDATE` ne ferait pas.

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

Les commandes DNS s’appellent via le préfixe **`dns`**. Elles nécessitent la permission **`write:dns`** et que le module DNS soit activé (`dns_enable: true`).

> **La syntaxe a changé.** Elle suit désormais la forme `dns <objet> <verbe>`, comme `enroll create` et `certificate list`.
>
> L’ancienne se contredisait : on créait une zone avec `create_zone` mais on la supprimait avec `delete zone`. Rien ne le laissait deviner.
>
> **Les anciennes formes restent comprises** et répondent avec un avertissement. Aucun script ne casse.

### 14.1 Aide

```bash
dns -h
```

### 14.2 Zones

```bash
dns zone create <nom.zone>     # crée une zone
dns zone list                  # liste les zones
dns zone show <nom.zone>       # affiche les enregistrements
dns zone delete <nom.zone>     # supprime la zone ET son contenu
```

Exemple :

```bash
dns zone create example.com
dns zone show example.com
```

⚠️ `zone delete` emporte tous les enregistrements de la zone. Les noms qu’elle résolvait cessent de l’être, et il n’y a pas de retour en arrière : la zone se recrée, son contenu non.

### 14.3 Enregistrements

```bash
dns record add <fqdn> <type> <données> [ttl] [priorité]
dns record delete <fqdn> <type>
```

- **fqdn** : nom complet (ex. `www.example.com`, ou `@.example.com` pour l’apex).
- **type** : A, CNAME, MX, NS, TXT.
- **données** : IP pour A, FQDN pour CNAME/MX/NS, texte pour TXT.
- **ttl** : **facultatif**, 300 secondes par défaut.
- **priorité** : facultative, pour MX et SRV uniquement.

Le TTL était auparavant obligatoire, ce qui obligeait à saisir `300` sur chaque enregistrement ordinaire. Une valeur tapée à la hâte vaut moins qu’un défaut choisi.

L’enregistrement est placé dans la **zone la plus spécifique** qui contient le FQDN — inutile de nommer la zone.

Exemples :

```bash
dns record add www.example.com A 192.168.1.1
dns record add mail.example.com CNAME srv.example.com 600
dns record add @.example.com MX mail.example.com 300 10
dns record delete www.example.com A
```

### 14.4 Résolution inverse (PTR)

```bash
dns ptr list                   # liste les enregistrements inverses
dns ptr delete <ip>            # supprime celui d’une adresse
```

Les PTR sont créés automatiquement à l’ajout d’un enregistrement A, selon la configuration.

### 14.5 Correspondance avec l’ancienne syntaxe

| Ancienne forme | Nouvelle forme |
|---|---|
| `dns create_zone <zone>` | `dns zone create <zone>` |
| `dns get_zone` | `dns zone list` |
| `dns get_zone <zone>` | `dns zone show <zone>` |
| `dns add_record <fqdn> <type> <data> <ttl>` | `dns record add <fqdn> <type> <data> [ttl]` |
| `dns delete zone <zone>` | `dns zone delete <zone>` |
| `dns delete record <fqdn> <type>` | `dns record delete <fqdn> <type>` |
| `dns get_ptr` | `dns ptr list` |
| `dns delete ptr <ip>` | `dns ptr delete <ip>` |

### 14.6 Droits

Toutes les opérations d’écriture passent par le registre d’actions (`dns.create_zone`, `dns.delete_zone`, `dns.add_record`, `dns.delete_record`, `dns.delete_ptr`) et exigent `write:dns` sur `*`.

Les lectures — `zone list`, `zone show`, `ptr list` — exigent la même clé, faute d’une clé de lecture distincte. Voir `./Actions_et_Permissions.md`.

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
| Ajouter une clé SSH à un compte | `add -u "user" -k "libellé" "ssh-ed25519 AAAA…"` |
| Permission user : tous domaines (auth) | `update -pu PERM auth all` |
| Permission user : un domaine (auth) | `update -pu PERM auth -a 1 domain.fr` |
| Permission user : lecture utilisateurs (RBAC) | `update -pu PERM read:get:user all` |
| Créer une GPO machine | `create -gpo durcissement_ssh --scope machine --desc "Baseline SSH"` |
| Créer une GPO utilisateur | `create -gpo env_dev --scope user` |
| Lister / détailler les GPO | `get -gpo` ; `get -gpo "nom_gpo"` |
| Lier une GPO à un groupe | `add -gpo "nom_gpo" -g "group"` |
| Délier une GPO d'un groupe | `remove -gpo "nom_gpo" -g "group"` |
| Supprimer une GPO | `delete -gpo "nom_gpo"` |
| Ajouter / éditer les modules d'une GPO | Interface web : **Admin → GPO → détail** |
| Déclarer un service, paquet ou jeu sudo custom | Interface web : **Admin → GPO → Restrictions** (groupe `vaultaire`) |
| Voir tout ce qui est attaché à un groupe | Interface web : **Admin → Groupes → détail** |
| Créer une permission user | `create -p lecture non --desc "Consultation"` |
| Créer une permission client | `create -pc postes-admin oui` |
| Attribuer une permission user à un groupe | `add -gu "group" -p "perm"` |
| Attribuer une permission client à un groupe | `add -gc "group" -p "perm"` |
| Régénérer le certificat du portail | `certificate regenerate web --dns sso.interne.lan` |
| Verrouiller un compte en urgence | `kill -u alice --reason compromised` |
| Imposer le second facteur à un groupe | `mfa -g IT_Group --require` |
| Émettre une clé d'enrôlement de service | `enroll create --type proxy --uses 1 --expires 30m` |
| Machines en écart de conformité GPO | `gpo drift` |
| Voir les durées d'exploitation | `settings list` |
| Changer une cadence sans redémarrer | `settings set check_online_minutes 5` |
| Arborescence LDAP | `eyes -g` |
| Zone DNS | `dns create_zone example.com` ; `dns get_zone` ; `dns get_zone example.com` |
| Enregistrement DNS | `dns add_record www.example.com A 192.168.1.1 300` |
| Supprimer zone / record | `dns delete zone example.com` ; `dns delete record www.example.com A` |
| Config LDAP serveur | `serveur_conf.yaml` → section `ldap` |
| Config LDAP client | Voir [§3.3](#33-exemple-de-configuration-client-keycloak) et [vaultaireLDAP.md](./vaultaireLDAP.md) |

---

## 16. certificate — Certificats TLS

Les certificats du **LDAPS**, du **portail web** et de l’**API REST** sont auto-signés et conservés en base. Ils sont produits au premier démarrage : une déclaration `web_tls_dns_names` ajoutée ensuite reste sans effet tant que le certificat n’a pas été régénéré.

```bash
certificate list                    # certificats en base et ce qu'ils couvrent
certificate show [ldaps|web|api]    # détail, défauts constatés, PEM à distribuer
certificate fingerprint             # empreinte de la clé du core, attendue par les agents
certificate regenerate <cible>      # régénère et remplace en base
```

**Cibles de `regenerate`** : `ldaps`, `web`, `api`, `all`.

**Options** — elles **s’ajoutent** à la configuration et à la détection automatique :

| Option | Effet |
|--------|-------|
| `--dns nom1,nom2` | noms DNS supplémentaires à couvrir |
| `--ip 10.0.0.1`   | adresses supplémentaires à couvrir |

Les noms de la machine et ses adresses sont détectés seuls. Déclarez en plus **tout nom par lequel un client vous joint sans que le serveur le connaisse** : nom de service DNS, nom de conteneur, alias derrière un répartiteur.

> Les clients Java — Keycloak, connecteurs JNDI — ignorent le CommonName depuis le JDK 9 et exigent un nom alternatif (SAN) correspondant. Un certificat sans SAN échoue sur `SSLHandshakeFailed`, sans autre indice.

Le certificat étant auto-signé, il doit aussi être importé dans le magasin de confiance de chaque client : `certificate show` en affiche la partie publique.

```bash
certificate regenerate web --dns sso.interne.lan,vaultaire.exemple.fr
certificate show web
```

> `certificate delete` existe côté action mais est réservé au **groupe protégé** : supprimer un certificat interrompt le service concerné jusqu’au prochain démarrage, et les clients qui avaient importé l’ancien devront réimporter le nouveau.

---

## 17. kill — Verrouillage d'urgence

Coupe l’accès d’un compte **partout à la fois** : portail, LDAP, Ducky. Le refus précède toute évaluation du mot de passe, et le message renvoyé est le même que pour un mot de passe faux — sans quoi le verrouillage deviendrait un moyen de confirmer qu’un compte existe.

```bash
kill -u <username>                  # verrouille (mode par défaut)
kill -u <username> --unlock         # lève le verrouillage
kill -u <username> --hard           # SUPPRIME le compte de l'annuaire et des machines
kill -u <username> --reason <code>  # compromised (défaut) | offboarding | admin_request
```

> `--hard` est irréversible : il ne verrouille pas, il supprime.

---

## 18. mfa — Second facteur et mots de passe

```bash
mfa -u <user>                          # état du second facteur d'un compte
mfa -u <user> --reset                  # efface son secret            (write:mfa)
mfa -g <groupe> --require              # impose le second facteur     (write:mfa)
mfa -g <groupe> --optional             # le rend facultatif           (write:mfa)
mfa policy                             # lit la politique d'expiration
mfa policy --max-age <j> --warn <j>    # l'écrit          (groupe vaultaire)
```

L’exigence se pose sur un **groupe**, pas sur un compte : elle s’applique à tous ses membres.

> LDAP n’a aucun mécanisme standard de second facteur. Le bind d’un compte soumis au MFA est refusé, et non challengé — comportement désactivé par défaut (`RefuseBindWhenMFARequired`), pour ne pas couper un parc existant à la mise à jour.

---

## 19. enroll — Clés d'enrôlement

Un client **service** ne se crée pas avec `create -c` : il s’enrôle lui-même, avec sa propre paire de clés, dont la partie privée ne doit jamais quitter l’hôte qui l’utilisera. Ces clés d’enrôlement sont ce qui l’autorise à le faire.

```bash
enroll create --type <type> [--uses N] [--expires 30m] [--label texte]
enroll list                      # les clés émises et leur état
enroll show <id>                 # détail d'une clé et services entrés avec
enroll revoke <id>               # neutralise une clé sans effacer sa trace
enroll types                     # catalogue des types de clients
```

`--uses` borne le nombre d’enrôlements, `--expires` la durée de validité. Les deux limitent ce qu’une clé divulguée permet.

> `revoke` **neutralise sans effacer** : la trace de ce qui s’est enrôlé avec cette clé reste consultable, ce qui est précisément ce qu’on cherche après une fuite.

---

## 20. gpo — Application et conformité

```bash
gpo status                 # état d'application et de conformité du parc
gpo status <computeur_id>  # détail d'une machine : modules en échec, écarts
gpo drift                  # uniquement les machines en écart
```

**Trois informations distinctes, à ne pas confondre :**

| | Ce qu'elle dit |
|---|---|
| **SUIVI**       | la machine parle-t-elle encore ? `à jour`, `en retard`, `jamais` |
| **APPLICATION** | le dernier rapport de l’agent — la politique a-t-elle **pu être posée** ? |
| **CONFORMITÉ**  | le dernier scan de l’agent — est-elle **encore en place** ? |

> « non vérifié » ne veut pas dire conforme : il veut dire que l’agent n’a pas encore rapporté de scan, ou qu’il n’a aucun fichier inventorié.

**La vue part de l’inventaire, pas des rapports.** Une machine créée mais jamais
installée, ou dont l’agent est tombé, apparaît donc — en `jamais` ou en `en
retard`. C’est volontaire : auparavant elle n’apparaissait pas du tout, et son
silence se lisait comme une absence de problème.

`en retard` se déclenche après **trois** cycles manqués, soit trois heures. Un
redémarrage ou une fenêtre de maintenance coûtent un cycle et ne remontent pas.

### La même vue sur le portail

**Admin → Conformité** (`/admin/gpo/compliance`) affiche exactement le même état :
résumé du parc, tableau trié dans le même ordre, détail d'une machine au clic, et
un filtre « écarts seulement » équivalent à `gpo drift`.

Le tri, les états de fraîcheur et les libellés viennent du **même code** que la
ligne de commande — c'est délibéré. Deux vues qui les recalculeraient séparément
finiraient par ne plus dire la même chose, et personne ne remarquerait l'écart
tant qu'il serait petit. Un test refuse que l'une des deux les réécrive.

Droit : `read:get:gpo`, comme en ligne de commande. La vue est réduite au
périmètre de l'appelant, et le nombre de lignes masquées est annoncé.

Le tri place devant ce dont on ne sait rien — les muettes —, puis les modules en
échec, puis les écarts. Un échec est visible et chiffré ; un silence ne dit rien,
et c’est pour cela qu’il passe en premier.

`gpo drift` ne masque **pas** les machines muettes : elles ont zéro écart
constaté parce que plus personne ne regarde, pas parce qu’elles sont saines.

La création et l’édition des GPO restent en [§5.6](#56-gpo) et dans l’interface web.

---

## 21. cluster — Nœuds du parc

```bash
cluster list                  # tous les nœuds enregistrés
cluster list <role>           # nœuds actifs d'un rôle
cluster purge-delay           # délai avant suppression d'un service parti
cluster purge-delay <heures>  # règle ce délai (0 désactive la purge)
```

## 22. settings — Durées d'exploitation

Les périodes des boucles du serveur : vérification des machines, purge des
sessions, battement et nettoyage du cluster, balayage des services, durée d'une
session web, synchronisation des groupes.

```bash
settings list                  # les durées, leur valeur et leur défaut
settings set <clé> <valeur>    # règle une durée
settings reset <clé>           # la ramène à son défaut codé
```

| Clé | Unité | Défaut | Ce qu'elle gouverne |
|---|---|---|---|
| `check_online_minutes` | min | 2 | vérification des machines en ligne |
| `ducky_session_purge_minutes` | min | 5 | purge des sessions Ducky expirées |
| `cluster_heartbeat_seconds` | s | 30 | battement du nœud vers le cluster |
| `cluster_cleanup_seconds` | s | 30 | mise hors ligne des nœuds silencieux |
| `service_sweep_seconds` | s | 60 | balayage des services hors ligne |
| `web_session_minutes` | min | 30 | durée d'une session du portail |
| `web_session_purge_minutes` | min | 5 | purge des sessions web expirées |
| `group_sync_minutes` | min | 60 | synchronisation des groupes du domaine sur les machines |

**Les valeurs vivent en base ; les défauts sont codés dans le serveur.** Un
changement prend effet au **prochain tour** de la boucle concernée — aucun
redémarrage, donc aucune coupure du parc pour ajuster une cadence.

`settings list` marque d'une étoile les valeurs écartées du défaut : c'est la
question qu'on se pose devant un serveur qu'on ne connaît pas.

**Droits** : `read:log` pour consulter, `write:server` pour régler.

> ⚠️ `web_session_minutes` fixe la fenêtre pendant laquelle un jeton volé reste
> utilisable. Les sessions **déjà ouvertes** gardent leur échéance : raccourcir
> la durée n'écourte pas les sessions en cours. Après un incident, c'est
> `kill -u` qu'il faut, pas ce réglage.

> ⚠️ `service_sweep_seconds` doit rester **inférieur** au seuil de péremption
> d'un battement, et `cluster_heartbeat_seconds` **nettement inférieur** : sinon
> un service tombé reste affiché en ligne, ou un nœud vivant est déclaré hors
> ligne entre deux battements.

### Ce qui n'est pas ici

Les délais de **protocole** et de **sécurité** — échéances de lecture réseau,
fenêtre anti-rejeu de l'API, barème de la limitation de débit — restent des
constantes du serveur. Ce ne sont pas des préférences d'exploitation mais des
propriétés du protocole : une échéance trop longue ouvre un déni de service,
trop courte casse les connexions lentes.

Les durées de l'**agent** vivent sur la machine du parc et relèvent des GPO.

> Le réglage `servercheckonlinetimer` du fichier YAML **n'est plus lu**. Une
> ligne laissée en place produit un avertissement au démarrage.

---

*Ce manuel est conçu pour être copié dans un wiki (sections, ancres, table des matières). En cas de désaccord avec `vlt <commande> -h`, c’est l’aide en ligne qui fait foi.*
