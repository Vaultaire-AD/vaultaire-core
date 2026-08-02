# GPO Vaultaire — fonctionnement et extension

Document de développement. Pour l'usage des commandes, voir
[MAN.md](../Utilisation/MAN.md) §5.6. Pour le protocole réseau, voir
[Tableau_Protocole_Réseau.md](./Tableau_Protocole_Réseau.md), section
« Détail du transport GPO ».

---

## Table des matières

1. [Le principe en une page](#1-le-principe-en-une-page)
2. [Vocabulaire](#2-vocabulaire)
3. [Où vit quoi](#3-où-vit-quoi)
4. [Cycle de vie complet](#4-cycle-de-vie-complet)
5. [Le catalogue de modules](#5-le-catalogue-de-modules)
6. [Les restrictions](#6-les-restrictions)
7. [Les empreintes](#7-les-empreintes)
8. [Garanties de sécurité](#8-garanties-de-sécurité)
9. [Ajouter un module](#9-ajouter-un-module)
10. [Ajouter un champ à un module existant](#10-ajouter-un-champ-à-un-module-existant)
11. [Rendre un champ éditable en base](#11-rendre-un-champ-éditable-en-base)
12. [Ajouter un type de contenu](#12-ajouter-un-type-de-contenu)
13. [Diagnostic](#13-diagnostic)

---

## 1. Le principe en une page

Une GPO Vaultaire **ne contient jamais de code**. Elle est une liste de
**modules** choisis dans un catalogue figé côté serveur, chacun paramétré par
les seuls champs décrits dans son schéma.

C'est la différence de fond avec l'ancien modèle, qui stockait une commande
shell par distribution et la faisait exécuter en root par l'agent. Un
administrateur — même compromis — ne peut désormais pousser que des
combinaisons de briques auditées.

```
        SERVEUR                                    AGENT (client)
┌──────────────────────────┐              ┌───────────────────────────┐
│ catalogue de modules     │              │ registre d'appliqueurs    │
│   (code, core/gpo)       │              │   (code, client/gpo)      │
│                          │              │                           │
│ restrictions             │  05_XX       │ état local                │
│   (base, éditables)      │ ───────────► │   applied_policies.json   │
│                          │              │                           │
│ GPO + modules            │              │ modules appliqués         │
│   (base, par groupe)     │ ◄─────────── │   rapport 05_12           │
└──────────────────────────┘              └───────────────────────────┘
```

Le client **initie toujours** (modèle pull, comme Puppet). Le serveur ne pousse
jamais.

---

## 2. Vocabulaire

| Terme | Sens |
|-------|------|
| **GPO** (`Policy`) | Un nom, un scope, une version, une liste de modules, et des groupes auxquels elle est liée |
| **Module** | Une instance d'un type du catalogue, avec ses paramètres |
| **Scope** | `machine` ou `user` — détermine quand la GPO s'applique et quels modules sont disponibles |
| **Schéma** (`ModuleSchema`) | La description d'un type de module : ses champs, leurs types, son ordre d'application |
| **Restriction** | Ce qu'un champ accepte comme valeur — en base, éditable |
| **Définition** | Une valeur nommée qui porte un contenu (ex. un jeu de commandes sudo) |
| **Empreinte** | SHA-256 identifiant une configuration, au niveau politique ou module |
| **Appliqueur** (`Applier`) | La fonction côté agent qui réalise concrètement un module |

**Une GPO ne se lie qu'à des groupes**, jamais directement à un utilisateur ou à
une machine. Le groupe porte déjà le domaine, les membres et les permissions :
un seul point de vérité pour la portée.

---

## 3. Où vit quoi

### Serveur — `src/vaultaire_serveur/`

| Fichier | Rôle |
|---------|------|
| `core/gpo/types.go` | `Policy`, `Module`, `Scope`, `ModuleSchema`, `FieldSchema` |
| `core/gpo/registry.go` | **Le catalogue** : les types de modules, leurs champs et leur ordre d'application |
| `core/gpo/dynamicfields.go` | Quels champs ont leur domaine en base (structure, pas valeurs) |
| `core/gpo/restrictions.go` | Modèle des restrictions, fournisseur injectable, cache |
| `core/gpo/payload.go` | Types de contenu et leurs validateurs — **point d'extension** |
| `core/gpo/guards.go` | Vérification des chemins, des scopes, des variables d'env |
| `core/gpo/validate.go` | Validation d'un module et d'une politique, forme canonique |
| `core/gpo/resolve.go` | Fusion de plusieurs GPO, détection de conflits |
| `core/gpo/transport.go` | Découpage en fragments, empreintes, document de livraison |
| `core/database/db_gpo/` | Persistance : GPO, modules, groupes, restrictions, définitions |
| `core/database/db_gpo/seed/gpo_seed.sql` | Peuplement initial des restrictions (embarqué) |
| `ducky-network/gpo_manager/` | Trames 05_XX, magasin de transferts, résolution |
| `core/web_serveur/web_admin_gpo*.go` | Pages `/admin/gpo` et `/admin/gpo/restrictions` |
| `core/command/command_*/[a-z]*-gpo.go` | Commandes CLI |

### Agent — `src/vaultaire_client/gpo/`

| Fichier | Rôle |
|---------|------|
| `policy.go` | Types de la charge reçue (miroir du contrat, module Go séparé) |
| `state.go` | `applied_policies.json` — ce qui est réellement appliqué |
| `fetch.go` | Côté client des trames 05_XX, réassemblage des fragments |
| `apply.go` | Moteur : diff par module, ordre, construction du rapport |
| `registry.go` | **Le registre d'appliqueurs** — point d'extension |
| `appliers_machine.go` | ssh, sysctl, sudoers, package, systemd |
| `appliers_sources.go` | répertoires, fichiers à substitution, CA, DNS, dépôts |
| `appliers_firewall.go` | règles de pare-feu (firewalld ou nftables) |
| `appliers_hardening.go` | pam, comptes locaux, modules noyau, known_hosts, audit, SELinux |
| `appliers_system.go` | GRUB, NTP, journaux, mises à jour, environnement, limites, purge |
| `appliers_user_extra.go` | ACL, groupes locaux, shell, mot de passe, ssh client, git, quotas |
| `appliers_user.go` | env, cron, file_deploy |
| `cycle.go` | Cycles complets, rafraîchissement périodique |
| `bootstrap.go` | Amorçage : émetteur de trames et clé de session |

### Base de données

| Table | Contenu |
|-------|---------|
| `gpo` | Métadonnées : nom, scope, version, activation |
| `gpo_module` | Un module par ligne, paramètres en JSON |
| `gpo_group` | Liaison GPO ↔ groupes |
| `gpo_restriction` | Valeurs autorisées, préfixes de chemins, variables interdites |
| `gpo_field_rule` | Mode de validation d'un champ : liste, motif, libre |
| `gpo_value_definition` | Valeurs nommées porteuses d'un contenu |

Schéma détaillé : [DataBase_Struct.md](./DataBase_Struct.md).

---

## 4. Cycle de vie complet

### 4.1 Création

Depuis le CLI ou l'interface web :

```bash
create -gpo durcissement_ssh --scope machine --desc "Baseline SSH"
add -gpo durcissement_ssh -g production
```

Les modules s'ajoutent depuis **Admin → GPO → détail**, avec des formulaires
générés à partir des schémas. L'interface ne peut donc pas proposer un champ ou
une valeur que le serveur refuserait.

### 4.2 Validation à l'écriture

`db_gpo.AddModule` est le point de passage obligé. Il :

1. vérifie que le type existe au catalogue ;
2. vérifie que le module est autorisé dans le scope de la GPO ;
3. **refuse tout paramètre hors schéma** (un champ inconnu est une erreur, pas
   un champ ignoré) ;
4. valide chaque valeur contre son type et contre les restrictions ;
5. revalide la GPO entière, pour détecter un doublon de clé naturelle ;
6. incrémente la version.

### 4.3 Résolution

Quand un client demande sa politique :

| Scope | Groupes retenus |
|-------|-----------------|
| `machine` | **tous** les groupes de la machine |
| `user` | **intersection** des groupes de l'utilisateur et de la machine |

L'intersection en scope user n'est pas un détail : sans elle, un utilisateur
emporterait la configuration d'un groupe sur une machine qui n'en fait pas
partie — il choisirait donc une partie de la configuration d'une machine à
laquelle il ne fait que se connecter.

`gpo.Resolve` fusionne les GPO retenues. **Deux GPO du même scope réglant la
même clé naturelle sont un conflit signalé, pas résolu** : deviner laquelle
gagne produirait un parc dont la configuration réelle est imprévisible. Le
serveur répond alors `resolve_conflict` et ne livre rien.

### 4.4 Transport

Trames `05_01` à `05_14`. Manifeste puis fragments de 32 Kio — la couche de
transport annonce la taille sur 2 octets, ce qui plafonne une trame à ~48 Kio
utiles alors qu'un seul `file_deploy` accepte 256 Kio.

Détail complet dans [Tableau_Protocole_Réseau.md](./Tableau_Protocole_Réseau.md).

### 4.5 Application

Deux moments :

| Moment | Scope | Où |
|--------|-------|-----|
| Démarrage du service, puis toutes les heures | machine | `cycle.go`, `StartMachineRefresh` |
| Après authentification PAM, avant octroi de la connexion | user | `PAM_Handler.go`, `applyUserGPO` |

Le cycle user est lancé depuis la goroutine PAM et **non** depuis le
gestionnaire de trames : ce dernier tourne dans la goroutine qui lit la
connexion, et y attendre une réponse du serveur bloquerait la lecture de cette
même réponse.

L'agent ne réapplique que les modules dont **l'empreinte a changé**. Un module
retiré d'une GPO n'est pas « désappliqué » : le modèle décrit un état voulu, pas
un historique. Retirer une configuration se fait avec un module explicite
`state=absent`.

En scope user, un échec ou un dépassement de délai **n'empêche pas la
connexion**. Aucun module de scope user ne touche aux privilèges ; un annuaire
qui bloque les connexions sur incident GPO serait un incident d'exploitation
majeur.

### 4.6 Rapport

L'agent remonte le résultat module par module (trame `05_12`). Sans ce rapport,
l'interface présenterait la configuration *voulue* comme si c'était la
configuration *réelle*.

---

## 5. Le catalogue de modules

Défini dans `core/gpo/registry.go`, variable `baseCatalog`.

| Ordre | Type | Scope | Ce qu'il fait |
|-------|------|-------|---------------|
| 10 | `directory_manage` | both | Répertoire avec permissions et propriétaire |
| 11 | `file_deploy` | both | Fichier avec contenu, permissions, propriétaire |
| 12 | `templated_file_deploy` | both | Idem, avec `{{hostname}}` `{{fqdn}}` `{{username}}` `{{domain}}` |
| 13 | `file_acl` | both | ACL POSIX (`setfacl`), avec héritage si récursif |
| 14 | `trusted_ca` | machine | CA interne dans le magasin de confiance |
| 20 | `dns_resolver` | machine | Serveurs DNS (`resolved.conf.d/`) |
| 21 | `package_repository` | machine | Dépôt de paquets autorisé |
| 30 | `package` | machine | Présence, absence, version épinglée |
| 40 | `sysctl` | machine | Un fichier par clé dans `/etc/sysctl.d/` |
| 41 | `boot_params` | machine | Ligne de commande noyau (GRUB), effectif au redémarrage |
| 42 | `kernel_module_policy` | machine | Interdit le chargement d'un module noyau |
| 44 | `ssh_server_config` | machine | Fragment `sshd_config.d/99-vaultaire-gpo.conf` |
| 45 | `ssh_known_hosts` | machine | `/etc/ssh/ssh_known_hosts` + StrictHostKeyChecking |
| 46 | `pam_policy` | machine | Complexité mot de passe, verrouillage après échecs |
| 47 | `local_account_policy` | machine | Comptes locaux non-Vaultaire (root et uid<1000 exclus) |
| 48 | `auditd_rule` | machine | Surveillance d'un chemin (`audit/rules.d/`) |
| 49 | `selinux_mode` | machine | Mode SELinux + booléens |
| 50 | `firewall_rule` | machine | Port ouvert ou fermé, zone dédiée |
| 51 | `ntp_config` | machine | Serveurs de temps |
| 52 | `log_policy` | machine | Taille et rétention des journaux |
| 53 | `update_policy` | machine | Mises à jour automatiques |
| 54 | `system_env` | machine | `/etc/environment` |
| 55 | `resource_limits` | machine | `limits.d/` (ulimits) |
| 56 | `sudoers_rule` | machine | `/etc/sudoers.d/` depuis un jeu de commandes |
| 60 | `systemd_service` | machine | Activation, état courant, masquage |
| 70 | `file_retention` | machine | Purge par âge et motif |
| 80 | `user_group_membership` | user | Groupe POSIX local |
| 81 | `user_shell` | user | Shell de connexion |
| 82 | `user_password_policy` | user | Expiration, changement forcé |
| 83 | `user_env` | user | Variable d'environnement |
| 84 | `user_ssh_client_config` | user | Entrée Host dans `~/.ssh/config` |
| 85 | `user_git_config` | user | Clé `.gitconfig` (liste fermée) |
| 86 | `user_resource_limits` | user | Quota CPU/mémoire (slice systemd) |
| 87 | `user_cron` | user | Timer `systemd --user` |

### Modules capables de rendre une machine inaccessible

Quatre modules touchent l'authentification, le démarrage ou le contrôle d'accès
obligatoire. Une politique fautive appliquée à tout un parc rendrait les
machines injoignables **à distance**, donc sans moyen d'y pousser la politique
corrective. Chacun valide son travail et restaure l'état précédent en cas
d'échec :

| Module | Garde-fou |
|--------|-----------|
| `pam_policy` | N'écrit **jamais** dans `/etc/pam.d/`, seulement dans `pwquality.conf.d/` et `faillock.conf` — des fichiers de paramètres, pas des piles d'instructions. Refuse un verrouillage sans déverrouillage automatique. `even_deny_root = no` : sinon N échecs volontaires sur root suppriment le dernier accès de secours. |
| `boot_params` | Régénère et **valide** la configuration GRUB avant de l'installer ; restaure et régénère si la validation échoue. |
| `selinux_mode` | Refuse le passage en `enforcing` sur un système jamais réétiqueté — des étiquettes manquantes empêcheraient sshd de démarrer. |
| `local_account_policy` | root et uid < 1000 exclus par construction. Mode `report_only` par défaut, qui liste sans modifier. |

`file_retention` est le seul module qui **détruit** des données : motif sans
séparateur de chemin, âge minimal d'un jour, liens symboliques jamais suivis,
un seul niveau de récursion, et les règles de chemin des Restrictions
s'appliquent.

## L'ordre d'application

**Imposé par le catalogue, jamais par l'ordre de saisie.** Réordonner les
modules dans l'interface ne change pas le résultat.

L'ordre suit les **dépendances réelles** entre modules, pas un classement
thématique :

| Phase | Plage | Contenu |
|-------|-------|---------|
| 1 | 10-19 | Fichiers et contenus |
| 2 | 20-29 | Sources et résolution (DNS, dépôts) |
| 3 | 30-39 | Paquets |
| 4 | 40-59 | Configuration système |
| 5 | 60-69 | Services |
| 6 | 70-79 | Ménage |
| 7 | 80+ | Environnement utilisateur |

**Pourquoi les fichiers en premier**, alors que la version initiale du catalogue
les plaçait en 30, après les paquets et les services. Trois raisons, chacune
suffisante :

- un dépôt de paquets a besoin de sa clé de signature, qui est un fichier ;
- un service doit démarrer avec sa configuration définitive. L'ancien ordre le
  faisait démarrer sur la configuration par défaut du paquet, puis déposait la
  vraie sans rien relancer : la machine tournait avec une configuration que
  personne n'avait choisie, jusqu'au prochain redémarrage ;
- `file_deploy` crée ses répertoires parents, il n'a donc pas besoin que le
  paquet ait créé `/etc/<produit>/` au préalable.

Exemple, un client VPN — l'enchaînement se lit dans les numéros :

```
10-19  dépose /etc/openvpn/client.conf et la clé GPG du dépôt éditeur
20-29  déclare le dépôt de l'éditeur
30-39  installe le paquet openvpn
40-59  règle le pare-feu et les paramètres noyau
60-69  démarre le service, qui lit une configuration déjà correcte
```

**Conséquence sur l'installation des paquets.** Déployer une configuration avant
d'installer le paquet qui la possède crée un conflit de « conffile ». L'agent
force donc la conservation du fichier déjà présent (`--force-confold` côté dpkg) :
sans cela le comportement dépendrait de la distribution et de son mode
interactif. Sur les distributions RPM c'est déjà le comportement par défaut, le
paquet écrit son fichier en `.rpmnew` à côté.

### Types de champs

Déclarés dans `core/gpo/types.go`, chacun avec son validateur dans
`validate.go` :

| Type | Validation | Widget web |
|------|-----------|------------|
| `string` | longueur, pas de caractère de contrôle | champ texte |
| `text` | longueur, pas de caractère nul | zone de texte |
| `int` | entier, bornes `Min`/`Max` | champ numérique |
| `bool` | `true` / `false` | case à cocher |
| `enum` | valeur dans `Options` | menu déroulant |
| `path` | absolu, canonique, filtré par les règles de chemin | champ texte |
| `mode` | octal à 3 chiffres (setuid non exprimable) | champ texte |
| `ident` | identifiant POSIX | champ texte |
| `cron` | expression à 5 champs | champ texte |
| `env_name` | nom de variable, hors liste interdite | champ texte |

### Ce que le catalogue produit dans l'interface

Les pages `/admin/gpo` sont entièrement dérivées du catalogue : ajouter un module
à `baseCatalog` le rend visible, cherchable et éditable sans écrire une ligne de
HTML. Trois éléments de l'entrée de catalogue se retrouvent directement à
l'écran, ce qui vaut la peine d'être soigné :

| Élément du schéma | Où il apparaît |
|-------------------|----------------|
| `Label` | Titre du module, et clé de tri du catalogue (liste alphabétique) |
| `Category` | Regroupement dans le repli sans JavaScript, et texte de recherche |
| `Description` | Sous le titre du formulaire d'ajout, et texte de recherche |
| `ModuleStateKey` (transport.go) | Colonne **Cible** du tableau des modules |

Le dernier point mérite une note. La colonne « Cible » n'est pas recalculée : elle
est extraite de `ModuleStateKey`, la clé qui sert au suivi d'état côté agent. Un
module dont la clé d'état est mal choisie — deux modules distincts partageant la
même clé, par exemple — se voit donc immédiatement dans le tableau, deux lignes
affichant la même cible. C'est délibéré : recalculer la cible pour l'affichage
aurait produit une colonne jolie et fausse, qui aurait masqué le défaut au lieu
de le montrer.

La page de détail est découpée en quatre onglets (Modules, Ajouter un module,
Groupes, Réglages) et le catalogue est présenté comme une liste filtrable dont un
seul formulaire est monté à la fois. La raison est le passage à une quarantaine
de types de modules : rendre quarante formulaires dans une même page, même
repliés, rendait la page inutilisable. Ce découpage est **du JavaScript
d'agrément** — `web_packet/sso_WEB_page/static/gpo_admin.js`. Sans lui, la classe
`.gpo-js` n'est jamais posée, les onglets restent masqués et toutes les sections
s'affichent à la suite, formulaires d'édition dépliés : la page redevient longue,
jamais inutilisable. Aucune vérification de sécurité ne dépend de ce script — les
contrôles RBAC et de schéma sont côté serveur, comme pour le CLI.

---

## 6. Les restrictions

### 6.1 Ce que c'est

Ce qu'un champ accepte comme valeur. **Aucune liste n'existe en dur dans le
code Go** : tout vit en base, éditable depuis **Admin → GPO → Restrictions**,
réservé aux membres du groupe superadmin `vaultaire`.

Trois modes par champ :

| Mode | Comportement |
|------|--------------|
| `list` | Seules les valeurs énumérées passent |
| `pattern` | Toute valeur conforme à une expression régulière passe |
| `free` | Aucune contrainte de domaine |

Le **motif d'exclusion** (`deny_pattern`) est prioritaire dans les trois modes :
il permet d'ouvrir largement un champ tout en gardant des refus fermes.

### 6.2 Peuplement initial

`core/database/db_gpo/seed/gpo_seed.sql`, embarqué dans le binaire via
`go:embed`, exécuté **une seule fois** : au premier démarrage, quand les tables
n'existent pas encore. La détection porte sur l'existence des tables **avant**
leur création, table par table.

Conséquences :

- une valeur supprimée depuis l'interface ne réapparaît **jamais** au
  redémarrage — il n'y a rien pour la réécrire ;
- une base créée par une version antérieure ne reçoit que les tables qui lui
  manquaient ;
- pour revenir au socle, il faut le demander explicitement (bouton
  **Réinitialiser**).

**Exception** : les *règles de champ* (`gpo_field_rule`) sont vérifiées à chaque
démarrage et créées si absentes (`ensureFieldRules`). Une règle n'est pas une
valeur, c'est la définition de la façon dont le champ se valide ; un champ
ajouté au catalogue sans règle refuserait tout sur les bases existantes.

### 6.3 Lecture fail-closed

Si la base ne répond pas, le jeu de restrictions est **vide** : aucune valeur
n'est autorisée, aucune GPO ne valide, un bandeau l'explique dans l'interface.

Il n'y a volontairement **aucun repli** sur un socle interne. Un repli
rétablirait, le temps de la panne, des valeurs que l'administrateur aurait
retirées — un écart silencieux entre configuration voulue et configuration
appliquée.

Le mécanisme est une inversion de dépendance : `core/gpo` définit l'interface
`RestrictionProvider` et `db_gpo` enregistre son implémentation au démarrage.
`core/gpo` reste ainsi un paquet feuille, sans aucun import local, donc testable
sans base.

### 6.4 Définitions à contenu

Certains champs ne se contentent pas d'un nom. Un *jeu de commandes sudo* porte
un nom — utilisé comme valeur dans la GPO — et la liste réelle des commandes
qu'il autorise.

**Le contenu voyage avec le module** (champ `definitions` du document livré).
L'agent n'a aucune table locale de jeux : sinon, créer un jeu custom depuis
l'interface serait sans effet sur le parc.

Le contenu entre dans le calcul des empreintes. Modifier la liste de commandes
d'un jeu ne change aucun paramètre de module, mais change bel et bien ce qui
sera appliqué — sans cela, le serveur répondrait « rien à faire ».

---

## 7. Les empreintes

Trois empreintes distinctes, avec trois rôles. Les confondre est une source de
bugs difficiles.

| Empreinte | Calculée sur | Sert à |
|-----------|--------------|--------|
| **Politique** (`PolicyHash`) | Forme canonique de la politique effective | Décider s'il y a quelque chose à appliquer |
| **Module** (`ModuleFingerprint`) | Type, scope, paramètres, définitions | Décider quels modules réappliquer |
| **Charge** (`PayloadChecksum`) | Octets réellement transmis | Valider le réassemblage des fragments |

L'empreinte de module **n'inclut pas l'ordre d'application** : réordonner le
catalogue ne change rien à ce qui est appliqué sur la machine, et l'inclure
provoquerait une réapplication inutile de tout le parc après une simple
modification de code.

L'agent **ne recalcule ni l'une ni l'autre** : le serveur les transmet
(`state_key`, `fingerprint` par module). Le client étant un module Go séparé,
deux implémentations du même hachage finiraient par diverger et une machine se
croirait à jour sans l'être.

### État local

`/var/lib/vaultaire/applied_policies.json`, en `0600 root:root`. Ce chemin est
refusé à toutes les GPO par les règles de restriction, précisément pour qu'une
politique ne puisse pas réécrire l'état qui décide de son application.

```json
{
  "machine": {
    "fingerprint": "e9f2ceedba71…",
    "version": 11,
    "applied_at": "2026-07-31T07:44:41Z",
    "status": "applied",
    "modules": { "sysctl:net.ipv4.ip_forward": "f3dad3533bb3…" }
  },
  "users": {
    "admin@vaultaire.fr": { "fingerprint": "3c719ab75513…", "modules": { } }
  }
}
```

L'empreinte de politique n'est enregistrée **que si tout est appliqué**. Sinon
le prochain cycle croirait la machine à jour et n'y reviendrait pas. Les modules
en échec sont retirés de l'état, donc retentés au cycle suivant.

---

## 8. Garanties de sécurité

### Garanti par construction

**Pas de code arbitraire dans une politique.** Les commandes exécutées par les
appliqueurs sont écrites en dur ; la politique ne fournit que des valeurs,
passées en arguments distincts, jamais interprétées par un shell.

**Séparation des scopes.** Un module machine-only ne peut pas figurer dans une
GPO user, vérifié à l'écriture, à la résolution et à la livraison. Tous les
modules touchant aux privilèges (SSH, sudo, sysctl, paquets, services) sont
machine-only : aucune politique utilisateur ne peut les surcharger.

**Validation stricte à l'écriture.** Un paramètre hors schéma est refusé, pas
ignoré. Une valeur hors domaine est refusée.

**Refus prioritaire.** Un `deny_pattern` ou un refus de chemin l'emporte
toujours sur une autorisation.

**Retour arrière sur les fichiers critiques.** `sshd -t` valide avant
rechargement et restaure le fragment précédent en cas d'échec ; `visudo -cf`
fait de même pour sudoers. Sans cela, une directive invalide poussée sur le parc
couperait l'accès SSH partout, sans retour possible.

**Blocs délimités.** Vaultaire écrit dans ses propres fichiers (fragments `.d/`)
et, quand il doit modifier un fichier de l'utilisateur, n'y pose qu'un bloc
encadré par ses marqueurs — jamais un remplacement complet.

### NON garanti — à connaître

**Le groupe `vaultaire` a un pouvoir root de fait sur le parc.** Choix assumé :
toutes les restrictions sont éditables, y compris les chemins protégés et les
variables d'environnement d'injection. Un membre de ce groupe peut autoriser
`/etc/sudoers` comme chemin de déploiement. Les contreparties sont l'audit
`SECURITY` systématique avec l'auteur, la double vérification d'appartenance
(base + interface), et le bouton de réinitialisation.

Le point d'entrée pour poser un plancher non contournable serait `CheckPath`
dans `guards.go`.

**Les politiques ne sont pas signées.** Le tunnel Ducky est authentifié et
chiffré, ce qui couvre l'écoute et l'altération en transit, mais **pas un
serveur central compromis**. Le champ `signature` existe dans le format de
livraison pour ne pas avoir à changer les trames plus tard. Entrée de TO-DO
séparée.

**La validation du contenu d'un jeu sudo porte sur la forme, pas l'intention.**
`/usr/bin/tee /etc/sudoers` est syntaxiquement valide et passe. Ce qui est
bloqué : métacaractères shell, jokers, chemins relatifs — c'est-à-dire ce qui
transformerait une règle bornée en accès complet sans que ce soit visible.

---

## 9. Ajouter un module

Exemple fil rouge : un module `hosts_entry` qui force une entrée dans
`/etc/hosts`.

### Étape 1 — Déclarer le type et son schéma

`src/vaultaire_serveur/core/gpo/registry.go` :

```go
// Ajouter la constante avec les autres
const ModuleHostsEntry = "hosts_entry"

// Ajouter l'entrée dans baseCatalog
{
    Type:        ModuleHostsEntry,
    Label:       "Entrée /etc/hosts",
    Category:    CategorySecurity,
    Description: "Force une correspondance nom/adresse dans un bloc délimité de /etc/hosts.",
    Scope:       ScopeMachine,
    ApplyOrder:  13,          // après sudoers (12), avant les paquets (20)
    Fields: []FieldSchema{
        {Name: "hostname", Label: "Nom d'hôte", Type: FieldString, Required: true, MaxLen: 253},
        {Name: "address", Label: "Adresse IP", Type: FieldString, Required: true, MaxLen: 45},
        {Name: "state", Label: "État attendu", Type: FieldEnum, Required: true,
            Options: []string{"present", "absent"}, Default: "present"},
    },
},
```

**Choisir l'ordre avec soin.** Il détermine les dépendances entre modules, pas
seulement l'affichage.

**Choisir le scope avec soin.** `ScopeMachine` le rend automatiquement interdit
en scope user — c'est le garde-fou anti-élévation de privilège, et il se déduit
de cette seule ligne.

### Étape 2 — Clé d'état

`core/gpo/transport.go`, fonction `ModuleStateKey` :

```go
case ModuleHostsEntry:
    suffix = m.Params["hostname"]
```

La clé identifie le module d'un cycle à l'autre. Sans elle, il serait réappliqué
à chaque fois ou considéré comme un module différent après chaque modification.

### Étape 3 — Identité naturelle

`core/gpo/validate.go`, fonction `moduleIdentity` :

```go
case ModuleHostsEntry:
    return "l'entrée hosts " + m.Params["hostname"]
```

Sert à deux choses : refuser deux modules réglant la même entrée dans une même
GPO, et signaler un conflit entre deux GPO. Retourner `""` si le module peut
légitimement apparaître plusieurs fois.

### Étape 4 — Règles de cohérence (facultatif)

`core/gpo/validate.go`, fonction `validateModuleSemantics` :

```go
case ModuleHostsEntry:
    if p["state"] == "present" && net.ParseIP(p["address"]) == nil {
        return fmt.Errorf("module %s : adresse IP invalide (%q)", moduleType, p["address"])
    }
```

Pour ce que le validateur champ par champ ne peut pas voir : cohérence entre
plusieurs champs.

### Étape 5 — L'appliqueur côté agent

`src/vaultaire_client/gpo/policy.go`, ajouter la constante :

```go
ModuleHostsEntry = "hosts_entry"
```

`src/vaultaire_client/gpo/appliers_machine.go` :

```go
// applyHostsEntry force une entrée dans /etc/hosts.
//
// Bloc délimité par les marqueurs Vaultaire, jamais le fichier entier :
// /etc/hosts contient des entrées posées par la distribution et par
// l'administrateur, les écraser casserait la résolution locale.
func applyHostsEntry(ctx Context, m Module) (string, error) {
    hostname := m.Param("hostname")
    address := m.Param("address")
    if hostname == "" {
        return "", fmt.Errorf("nom d'hote manquant")
    }

    existing, _ := readFileIfExists("/etc/hosts")
    entry := address + " " + hostname

    if m.Param("state") == "absent" {
        // retirer la ligne du bloc géré
        ...
    }

    if err := writeSystemFile("/etc/hosts", replaceManagedBlock(existing, entry), 0o644); err != nil {
        return "", err
    }
    return fmt.Sprintf("%s -> %s", hostname, address), nil
}
```

`src/vaultaire_client/gpo/registry.go`, enregistrer :

```go
var appliers = map[string]Applier{
    ...
    ModuleHostsEntry: applyHostsEntry,
}
```

**C'est tout côté agent.** Le moteur (`apply.go`) n'a pas à changer : il itère
sur le registre. Un module envoyé par un serveur plus récent que l'agent est
rapporté `skipped` avec sa raison — jamais ignoré en silence.

### Étape 6 — Vérifier

L'interface web et le CLI se mettent à jour **automatiquement** : les formulaires
sont générés depuis le schéma, la commande `get -gpo` affiche le module avec le
libellé du catalogue.

Ajouter un test dans `core/testrunner/run_gpo.go` :

```go
_, err := gpo.ValidateModule(gpo.ScopeUser, gpo.Module{
    Type:   gpo.ModuleHostsEntry,
    Params: map[string]string{"hostname": "x", "address": "1.2.3.4", "state": "present"},
})
out = append(out, Result{"GPO/scope: hosts_entry refuse en scope user", err != nil, "devrait refuser"})
```

**Tester ce qui doit être REFUSÉ**, pas seulement le chemin heureux : les
garanties du modèle reposent entièrement sur des refus.

### Récapitulatif

| Fichier | Modification |
|---------|-------------|
| `core/gpo/registry.go` | Constante + entrée dans `baseCatalog` |
| `core/gpo/transport.go` | `ModuleStateKey` |
| `core/gpo/validate.go` | `moduleIdentity`, éventuellement `validateModuleSemantics` |
| `client/gpo/policy.go` | Constante |
| `client/gpo/appliers_*.go` | La fonction d'application |
| `client/gpo/registry.go` | Enregistrement dans `appliers` |
| `core/testrunner/run_gpo.go` | Tests de refus |

**Rien à modifier** dans : la couche base, l'interface web, le CLI, le
transport, le moteur d'application.

---

## 10. Ajouter un champ à un module existant

Une seule modification suffit, dans `baseCatalog` :

```go
{Name: "comment", Label: "Commentaire", Type: FieldString, MaxLen: 128,
    Help: "Ajouté en commentaire dans le fichier généré."},
```

Puis l'utiliser dans l'appliqueur : `m.Param("comment")`.

**Attention aux champs requis.** Ajouter un champ `Required` sans `Default` fait
échouer la validation des modules déjà en base, qui ne l'ont pas. Deux options :

- donner un `Default`, appliqué automatiquement aux modules existants ;
- laisser le champ facultatif.

L'empreinte des modules concernés change, donc ils seront réappliqués sur tout
le parc au prochain cycle. Sans danger — les appliqueurs sont idempotents — mais
attendez-vous à voir des `applique` là où vous verriez normalement `inchange`.

---

## 11. Rendre un champ éditable en base

Pour qu'un champ ait un domaine de valeurs éditable depuis l'interface plutôt
qu'une liste figée dans le code.

### Étape 1 — Marquer le champ comme dynamique

`core/gpo/registry.go`, dans le schéma :

```go
{Name: "hostname", Label: "Nom d'hôte", Type: FieldEnum, Required: true,
    Dynamic: true, MaxLen: 253},
```

`Options` reste vide : les valeurs viendront de la base.

### Étape 2 — Déclarer la structure

`core/gpo/dynamicfields.go`, dans `dynamicFields` :

```go
{
    ModuleType: ModuleHostsEntry, FieldName: "hostname",
    Label: "Noms d'hôtes forçables",
    Help:  "Nom d'hôte pleinement qualifié. Passez ce champ en mode motif pour accepter tout un domaine.",
},
```

Ce fichier ne contient **aucune valeur** : uniquement quels champs sont
dynamiques, leur libellé et leur aide. C'est du catalogue, pas de la donnée.

### Étape 3 — Peuplement initial

`core/database/db_gpo/seed/gpo_seed.sql` :

```sql
INSERT IGNORE INTO gpo_field_rule (module_type, field_name, mode, allow_pattern, deny_pattern, updated_by) VALUES
  ('hosts_entry', 'hostname', 'pattern', '^[a-z0-9.-]+$', NULL, 'system');
```

**La règle est obligatoire.** Un champ dynamique sans règle retombe en mode
liste avec une liste vide, donc refuse tout. `ensureFieldRules` la crée sur les
bases existantes au démarrage suivant, et `checkDeclaredFieldsHaveRules` avertit
dans les journaux si elle manque.

Éventuellement, des valeurs initiales :

```sql
INSERT IGNORE INTO gpo_restriction (kind, module_type, field_name, scope, value, updated_by) VALUES
  ('allow_value', 'hosts_entry', 'hostname', 'any', 'depot.interne', 'system');
```

### Résultat

Le champ apparaît dans **Admin → GPO → Restrictions**, avec son sélecteur de
mode, ses motifs et sa liste de valeurs. Le formulaire du module affiche un menu
déroulant en mode liste, un champ texte libre en mode motif ou libre.

---

## 12. Ajouter un type de contenu

Pour un champ dont la valeur est un **nom** renvoyant à un **contenu**, comme
les jeux de commandes sudo.

### Étape 1 — Déclarer le kind

`core/gpo/restrictions.go` :

```go
const PayloadFirewallRules PayloadKind = "firewall_rules"
```

### Étape 2 — Descripteur et validateur

`core/gpo/payload.go` :

```go
// dans payloadDescriptors
PayloadFirewallRules: {
    Kind:        PayloadFirewallRules,
    Label:       "Règles de pare-feu",
    Placeholder: "tcp 22 accept\ntcp 443 accept",
    Help:        "Une règle par ligne : protocole, port, action.",
    Multiline:   true,
},

// dans payloadValidators
PayloadFirewallRules: validateFirewallRulesPayload,

func validateFirewallRulesPayload(payload string) error {
    // Valider la FORME de chaque ligne. Ce validateur est la seule barrière
    // avant que le contenu ne soit rendu dans un fichier système.
    ...
}
```

### Étape 3 — Rattacher au champ

`core/gpo/dynamicfields.go` :

```go
{
    ModuleType: ModuleFirewall, FieldName: "rule_set",
    Label:       "Jeux de règles de pare-feu",
    PayloadKind: PayloadFirewallRules,
    Help:        "Un jeu porte un nom et la liste des règles qu'il applique.",
},
```

### Étape 4 — Consommer côté agent

`client/gpo/appliers_machine.go` :

```go
definition, ok := m.Definition("rule_set")
if !ok {
    return "", fmt.Errorf("jeu %q non transmis : agent trop ancien pour cette politique", name)
}
rules := definition.Lines()
```

**Revalider la forme côté agent.** Le contenu vient d'un serveur authentifié,
mais il finit dans un fichier système : le coût de la revérification est nul
comparé à celui de l'erreur.

### Ce qui se met à jour tout seul

La couche base stocke le contenu, l'interface Restrictions affiche un éditeur de
contenu, les empreintes intègrent le contenu, la page de détail d'une GPO
affiche le contenu de la valeur sélectionnée.

---

## 13. Diagnostic

### Journaux serveur

Codes d'erreur dans `core/logs/error_codes.go` :

| Code | Domaine |
|------|---------|
| `VLT-GPO001` | Résolution des GPO applicables |
| `VLT-GPO002` | Trames 05_XX, découpage |
| `VLT-GPO003` | Transfert de fragments |
| `VLT-GPO004` | Rapport d'application |
| `VLT-GPO005` | Restrictions indisponibles |

Les traces `DEBUG` n'apparaissent que si `storage.Debug` est vrai
(`update -debug true`).

### Journaux agent

`/var/log/vaultaire/vaultaire_client.log`. Un cycle nominal :

```
GPO: debut du cycle machine
GPO: 05_01 envoyee (empreinte appliquee deda849106cb…)
GPO: politique machine v11 annoncee — 5 module(s), 1 fragment(s), 4331 octets
GPO: 05_09 fragment 0 demande (machine)
GPO: fragment 1/1 recu (4331 octets)
GPO: module sysctl (sysctl:net.ipv4.ip_forward) inchange, non reapplique
GPO: module package (package:telnet) applique — present telnet via dnf
GPO: cycle machine termine en 8.231s — statut=applied applique=4 inchange=1 echec=0
```

### Symptômes courants

| Symptôme | Cause probable |
|----------|----------------|
| `politique machine deja a jour` alors qu'une GPO a changé | Le changement n'affecte pas l'empreinte — vérifier qu'il porte bien sur un paramètre ou une définition |
| `aucun groupe commun` en scope user | Le groupe de la GPO ne contient pas **à la fois** l'utilisateur et la machine |
| `resolve_conflict` | Deux GPO du même scope règlent la même clé — les logs nomment les deux |
| `restrictions_unavailable` | Base injoignable, mode fail-closed |
| Module `skipped` | Type inconnu de l'agent : serveur plus récent que le client |
| `jeu de commandes non transmis` | Agent antérieur à la transmission des définitions |
| Variable d'environnement absente après connexion | Rouvrir une session : les fichiers de démarrage ne sont lus qu'au lancement du shell |

### Fichiers écrits sur l'agent

| Module | Emplacement |
|--------|-------------|
| `ssh_server_config` | `/etc/ssh/sshd_config.d/99-vaultaire-gpo.conf`, `/etc/ssh/vaultaire-banner` |
| `sysctl` | `/etc/sysctl.d/90-vaultaire-<clé>.conf` |
| `sudoers_rule` | `/etc/sudoers.d/90-vaultaire-<groupe>` |
| `file_deploy` | Le chemin du module |
| `user_env` | `~/.vaultaire_env` + bloc dans `.bashrc`, `.bash_profile`, `.profile`, `.zshrc` |
| `user_cron` | `~/.config/systemd/user/vaultaire-<id>.{service,timer}` |
| État | `/var/lib/vaultaire/applied_policies.json` |

### Forcer un cycle

Il n'existe pas encore d'équivalent de `gpupdate /force`. Pour l'instant :
redémarrer le service client, ou attendre le rafraîchissement horaire
(`MachineRefreshInterval` dans `client/gpo/cycle.go`).

---

## Points ouverts

| Sujet | État |
|-------|------|
| Signature des politiques par le serveur central | Champ prévu, non implémenté |
| Forçage d'un cycle depuis le serveur | Non implémenté |
| Cycle déclenché à la reconnexion du tunnel | Non implémenté — attend le tour horaire |
| Retentative rapprochée après un cycle en échec | Non implémenté — attend le tour horaire |
| Intervalle de rafraîchissement configurable | En dur dans le code |
| `user_cron/command_id` en définition à contenu | Reste une liste simple ; une tâche custom exige une implémentation dans l'agent |
| Persistance des rapports d'application en base | Journalisés seulement |
