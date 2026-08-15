# GPO Vaultaire — fonctionnement et extension

> **Public : développeurs.** Modèle déclaratif, catalogue de modules, ajout d'un module.
> Pour l'usage au quotidien, voir [`docs/Utilisation/`](../../Utilisation/).

Document de développement. Pour l'usage des commandes, voir
[MAN.md](../../Utilisation/MAN.md) §5.6. Pour le protocole réseau, voir
[Protocole_Ducky.md](./Protocole_Ducky.md), section
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
| `gpo` | Métadonnées : nom, scope, version, activation, **mode de dérive** |
| `gpo_module` | Un module par ligne, paramètres en JSON |
| `gpo_group` | Liaison GPO ↔ groupes |
| `gpo_restriction` | Valeurs autorisées, préfixes de chemins, variables interdites |
| `gpo_field_rule` | Mode de validation d'un champ : liste, motif, libre |
| `gpo_value_definition` | Valeurs nommées porteuses d'un contenu |

Schéma détaillé : [Base_de_donnees.md](./Base_de_donnees.md).

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

Détail complet dans [Protocole_Ducky.md](./Protocole_Ducky.md).

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


---

## Ce que le scan de conformité surveille

Trois inventaires, tenus pendant l'application et relus à chaque scan.

| Inventaire | Ce qu'il contient | Écart détecté |
|---|---|---|
| Fichiers **déposés** | chemin, SHA-256, mode | `modified`, `missing`, `unreadable`, `permissions` |
| Fichiers **retirés** | chemin, drapeau `absent` | `reappeared` |
| **États système** | type, cible, attendu | `system_state`, `unverifiable` |

Les deux derniers sont récents : le scan ne comparait que des fichiers déposés.

### Ce qui doit être ABSENT

Un module dont l'effet est « ce fichier ne doit pas exister » — `state=absent` —
ne laissait **aucune trace**. Le recréer ne produisait donc aucun écart : le scan
ne compare que ce qu'il connaît, et il ne connaissait que des écritures.

Concrètement : une GPO pose `/etc/modprobe.d/vaultaire-usb-storage.conf` pour
interdire un module noyau, une autre le retire pour lever l'interdiction.
Quelqu'un défait le geste, et la machine reste conforme indéfiniment.

`removeSystemFile` est l'entonnoir, jumeau de `writeSystemFile`. La dérive s'y
lit **à l'envers** : ce n'est pas la disparition qui compte, c'est la
réapparition.

**Toutes les suppressions n'y passent pas**, et c'est délibéré :

| Famille | Exemple | Notée ? |
|---|---|---|
| politique | `state=absent` | oui |
| nettoyage d'un temporaire | `writeSystemFile` | non — il n'a jamais eu d'existence visible |
| retour arrière après échec | `restoreOrRemove` | non — le module n'a pas abouti, il ne déclare rien |
| balayage périodique | `file_retention` | non — ces fichiers ont vocation à réapparaître |

La distinction : « ce fichier ne doit pas exister » se note ; « ce fichier n'a
pas à exister maintenant » ne se note pas.

### Les effets NON-fichier

55 appels de commandes dans les appliqueurs — `systemctl`, `nft`, `chage`,
`usermod`, `gpasswd`, `setsebool`, `sysctl`. Un service réactivé, une table
nftables vidée, un compte remis dans `sudo` : invisibles.

Le déséquilibre était complet. Le fichier qui *décrit* l'état voulu était
surveillé, l'état lui-même ne l'était pas — un `sshd_config.d/99-vaultaire.conf`
intact au hachage près ne dit rien si sshd a été arrêté.

**On ne devine pas l'état d'un service depuis un fichier.** Chaque module sait ce
qu'il a fait, et lui seul : c'est donc lui qui déclare ce qu'il faudra
revérifier, par `recordCheck`, au moment où il l'applique. Un module écrit demain
sans `recordCheck` n'est simplement pas vérifié — silence, pas fausse conformité.

Premier lot — les modules dont la dérive **donne un droit** :

| Type | Cible | Ce qui est constaté |
|---|---|---|
| `systemd_unit` | nom d'unité | `is-enabled`, `is-active` — seules les facettes que la politique a fixées |
| `nft_rule` | commentaire de règle | présence dans la table `vaultaire_gpo` |
| `group_member` | `utilisateur:groupe` | appartenance via NSS, pas `/etc/group` |
| `selinux` | `mode` ou `bool:<nom>` | mode courant, valeur du booléen |
| `account_lock` | compte local | verrou dans shadow, `chage -l` |

Second lot — les modules dont la dérive coûte de la **cohérence** :

| Type | Cible | Ce qui est constaté |
|---|---|---|
| `sysctl` | clé du noyau | valeur courante par `sysctl -n`, espaces normalisés |
| `package` | nom du paquet | présence par `dpkg-query` ou `rpm -q` — **pas la version** |
| `user_shell` | compte | septième champ de `getent passwd`, pas `/etc/passwd` |
| `file_acl` | `<chemin>\|<u\|g>:<bénéficiaire>` | entrée `getfacl` **et droits effectifs** |

Troisième lot — les modules dont la dérive coûte la **capacité à savoir** :

| Type | Cible | Ce qui est constaté |
|---|---|---|
| `ntp_servers` | `system` | serveurs réellement chargés par timesyncd, ordre indifférent |
| `audit_rule` | étiquette | règle réellement chargée dans le noyau, par son `-k` |

Ces deux-là ne rendent rien de plus permissif. Mais une horloge qui suit d'autres
serveurs que ceux de la politique rend tous les horodatages du parc
incomparables ; une règle d'audit qui n'est plus chargée ne produit plus la trace
qu'on ira chercher après coup. `auditctl -D` vide toutes les règles du noyau
**sans toucher à un seul fichier** — une commande d'une ligne, aucune trace, et
le scan des fichiers déclare la machine conforme.

Quatrième lot — les modules dont l'effet est un état **compilé** :

| Type | Cible | Ce qui est constaté |
|---|---|---|
| `ca_trust` | nom de la CA | empreinte SHA-256 dans le bundle compilé, pas dans le fichier déposé |
| `dns_servers` | `global` | serveurs globaux de `resolvectl`, ordre indifférent |

L'appliqueur dépose une **source**, puis un outil en tire un état compilé — et
c'est celui-ci qui sert. Le scan des fichiers surveille la source ; ce lot
surveille le résultat.

Trois écarts échappaient au fichier pour `trusted_ca` : une CA mise en **liste
noire**, une CA retirée de `/etc/ca-certificates.conf` sur Debian, ou un magasin
régénéré avant que le fichier n'arrive puis plus jamais. Dans les trois cas la
source est intacte et **aucune connexion TLS ne fait confiance à cette autorité**.

L'empreinte porte sur le **DER**, pas sur le texte : `update-ca-trust` réécrit ce
qu'il agrège — longueur de ligne, ordre, en-têtes — et chercher le texte déposé
échouerait sur une machine parfaitement conforme.

Deux précautions, dans les deux cas :

- **L'ordre des serveurs NTP ne compte pas.** timesyncd bascule d'un serveur à
  l'autre selon leur disponibilité et peut réordonner ce qu'il rend. Le *nombre*
  compte : un serveur en trop est un serveur de temps que personne n'a demandé.
- **Une règle d'audit se retrouve par son étiquette, jamais par sa ligne.**
  `auditctl -l` normalise ce qu'il rend. Et la comparaison porte sur le champ qui
  suit `-k`, pas sur une sous-chaîne : une étiquette « vaultaire » se retrouve
  dans le chemin surveillé `/opt/vaultaire/config`, et une recherche naïve
  conclurait qu'une règle est chargée en lisant celle d'un autre.

#### Trois choses que ce lot refuse d'affirmer

**La version d'un paquet.** Chaque gestionnaire écrit ses versions à sa façon —
rpm préfixe d'une époque et suffixe d'une révision, dpkg fait autrement, et la
politique porte le plus souvent la version amont seule. Un comparateur qui se
tromperait déclarerait conforme une version qui ne l'est pas. Le vérificateur
affirme donc uniquement ce qu'il constate : le paquet est là, ou il n'y est pas.

**Une ACL récursive.** `getfacl` ne constate que le chemin de tête. Une entrée
retirée sur un sous-répertoire y échapperait. `applyFileACL` ne déclare donc
**aucune attente** quand la politique est récursive. Le silence est un défaut de
couverture, connu ; la fausse conformité est un défaut de confiance, et elle
contamine tout le rapport.

**Ce qui dépend d'un redémarrage.** `boot_params` et `kernel_module_policy`
écrivent une configuration qui ne prend effet qu'au prochain démarrage —
l'appliqueur le dit lui-même, « effectif au redemarrage ». Constater
`/proc/cmdline` ou `lsmod` signalerait une dérive sur toute machine en attente de
redémarrage : une alerte permanente que personne ne peut lever. Ils deviendront
vérifiables le jour où l'état saura porter « en attente de redémarrage ».

**Ce qui dépend d'une session.** `system_env` et `resource_limits` étaient
candidats, et paraissaient faciles.

Ce que `system_env` fixe, c'est ce qu'un *shell de connexion* recevra. L'agent
est un service : son environnement est celui de systemd au démarrage de la
machine. Lire `os.Getenv` constaterait quelque chose de vrai et de sans rapport.
Lancer un shell de connexion ne marche pas davantage — il faudrait le lancer
**pour chaque utilisateur**, puisque `~/.profile` et `/etc/profile.d/` peuvent
redéfinir la variable selon le compte.

`resource_limits` : l'appliqueur le dit dans son propre message, « nouvelles
sessions ». PAM lit `/etc/security/limits.d/` à l'*ouverture* d'une session.
Constater les limites du processus de l'agent, c'est constater celles de la
session sous laquelle il a été lancé — au démarrage de la machine, avant que la
politique n'ait été appliquée. Ce n'est pas une approximation, c'est une autre
mesure.

**Ce que le scan des fichiers couvre déjà.** `package_repo` paraissait un bon
candidat — « un dépôt désactivé à la main n'est vu par rien ». C'est faux :
`dnf config-manager --set-disabled` écrit `enabled=0` **dans le fichier `.repo`
de la GPO**, que le hachage voit ; côté apt, désactiver revient à retirer le
fichier, que le scan voit disparaître. Un vérificateur n'ajouterait qu'un cas
marginal, au prix d'une analyse de `dnf repolist` dont le format diffère entre
dnf4 et dnf5.

`ssh_known_hosts` est plus court encore : pas d'état compilé, pas de service à
recharger, pas de second fichier qui prendrait le dessus. L'idée d'un « fichier
qui le masque » venait d'une analogie avec les fragments de configuration, et
elle ne s'applique pas.

**Un vérificateur n'est pas déclaré quand rien n'a été chargé.** Quand le
redémarrage de timesyncd échoue, la machine utilise probablement chrony ou ntpd :
`applyNTPConfig` ne déclare alors aucune attente, sans quoi le vérificateur
lirait les serveurs d'un autre démon. Un test garde l'ordre des deux gestes, et
un autre garde celui de `trusted_ca` — déclarer l'attente avant la régénération
du magasin ferait signaler une dérive sur une machine que l'appliqueur vient de
mettre en conformité.

**Ce que `dns_servers` ne constate pas.** Qu'un DNS posé sur une **interface** —
par DHCP — prime sur le global pour les requêtes de cette interface. Ce n'est pas
une dérive de ce module : il fixe le global, et le global est bien celui qu'il a
fixé. Le couvrir demanderait un module qui décide par interface, ce qui n'existe
pas.

Restent 23 modules sans vérificateur. Ils suivront, un par un : **une
vérification approximative est pire qu'aucune**, parce qu'elle déclare conforme
ce qui ne l'est pas et que personne ne va plus regarder.

#### Les garde-fous du registre

Trois tests, qui lisent les **sources** plutôt qu'une liste tenue à la main :

| Test | Ce qu'il empêche |
|---|---|
| `TestChaqueConstanteDAttenteAUnVerificateur` | une constante `Check…` sans vérificateur enregistré — l'attente serait ignorée en silence |
| `TestChaqueAttenteDeclareeSaitEtreVerifiee` | un `recordCheck` sans vérificateur — silence permanent, donc fausse conformité |
| `TestAucunVerificateurEnTrop` | un vérificateur que plus aucun appliqueur ne déclare — la déclaration a été retirée par mégarde |

La liste des constantes est **extraite de `verifiers*.go`**. Elle était écrite à
la main : juste pour cinq vérificateurs, fausse à trente-six, et fausse en
silence — un vérificateur oublié dans la liste n'est pas signalé, il n'est
simplement pas contrôlé. C'est le défaut même que ces tests existent pour
empêcher, reproduit dans les tests.

### `system_state` et `unverifiable` ne se confondent pas

Une commande absente, un délai dépassé : on ne sait pas, on ne constate pas.
C'est `unverifiable`, et rien n'est réappliqué. La distinction est celle
d'`unreadable` pour les fichiers — confondre les deux ferait relancer un service
sur une simple incertitude.

Une attente dont le vérificateur est **inconnu** — état écrit par un agent plus
récent — est ignorée en silence, pour la même raison.

### En enforce

Comme pour les fichiers : l'empreinte du module est oubliée, le cycle suivant le
réapplique. La correction n'est jamais immédiate — réappliquer peut relancer un
service, et le faire à l'instant de la détection reviendrait à redémarrer sshd
pendant qu'un administrateur débogue.

---

## Le mode de dérive — enforce ou audit

> **La détection ne change jamais. Seul change ce qu'on fait de ce qu'on a
> détecté.**

Un écart est constaté, journalisé et remonté au core dans les deux modes. Ce que
le mode décide, c'est la suite :

| Mode | Ce que l'agent fait de l'écart |
|---|---|
| `enforce` | oublie l'empreinte du module — le cycle suivant le réapplique |
| `audit` | rien. L'écart reste, et reste visible |

### Où il est réglé

Sur la **GPO**, colonne `gpo.drift_mode`. Les modules en héritent à la
résolution.

```bash
vlt gpo mode <nom_gpo> audit      # ou enforce
```

Également dans **Admin → GPO → une GPO → Réglages**. Les deux passent par
l'action `gpo.set_drift_mode`, qui exige `write:update:gpo` sur **chaque**
domaine couvert par la GPO — comme toute écriture de ce fichier.

### Pourquoi sur la GPO, et pas ailleurs

**Pas dans le binaire de l'agent.** C'est d'où le mode vient : une variable
`CurrentDriftMode` que personne ne renseignait. Le mode audit était donc
inatteignable en production, et un parc qui l'aurait voulu aurait eu besoin d'un
second binaire.

**Pas dans `client_software.yaml`.** Moins cher, et faux : cela remet la décision
sur la machine, c'est-à-dire sur la partie qui dérive. Un poste dont quelqu'un
édite le fichier se déclarerait en audit et ne serait plus jamais corrigé, sans
que rien ne le signale côté serveur.

**Pas un réglage global du parc.** Un parc n'est pas homogène : un groupe
« laboratoire » où les interventions manuelles sont légitimes veut du
signalement, le reste veut de la correction.

**Pas un mode effectif par scope non plus.** Une machine reçoit les GPO de tous
ses groupes. Si la fusion devait trancher, la machine du laboratoire qui reçoit
aussi une GPO du parc repasserait entièrement en enforce — ou, dans l'autre sens,
une seule GPO en audit désarmerait la correction de toutes les autres. Le mode
suit donc le **module**, hérité de sa GPO d'origine, et chaque règle s'applique à
ses propres modules.

### Comment il atteint le parc

C'est le point qui a décidé de l'implémentation. Le serveur ne livre une
politique que si son empreinte diffère de celle que l'agent annonce ; sinon il
répond `05_03` / `05_07`, qui ne transportent rien. Un mode livré uniquement dans
le document JSON n'aurait donc atteint que les machines dont la politique change
**par ailleurs** — c'est-à-dire peut-être jamais.

Deux empreintes, deux traitements opposés, et c'est délibéré :

| Empreinte | Le mode y entre ? | Conséquence |
|---|---|---|
| **politique** (`CanonicalJSON`) | oui | changer le mode fait retélécharger le document |
| **module** (`ModuleFingerprint`) | non | aucun module n'est réappliqué pour autant |

Le changement de mode coûte donc un transfert de politique et zéro
réapplication : tous les modules ressortent `unchanged`. Aucun service relancé,
aucun paquet réinstallé.

### Le défaut est silencieux

`enforce` n'est écrit **nulle part** — ni dans le champ `drift_mode` du module
livré, ni dans `applied_policies.json`. C'est ce qui rend la migration gratuite :

- une GPO dont la colonne vaut `enforce` produit exactement l'empreinte qu'elle
  produisait avant l'existence de la colonne. Aucun parc ne retélécharge quoi que
  ce soit à la mise à jour ;
- un état local écrit par un agent antérieur n'a pas de clé `modes`, se relit
  sans erreur, et vaut « tout en enforce » — l'ancien comportement à l'identique ;
- un agent récent parlant à un core ancien ne reçoit aucun mode, et applique
  enforce.

Le défaut ne peut pas être `audit`. Chaque trou d'information — core plus ancien,
état tronqué, valeur inconnue, faute de frappe en base — deviendrait sinon une
machine qui cesse d'être corrigée sans que personne ne le sache.

### Ce que l'agent mémorise, et pourquoi

`applied_policies.json` porte une carte `modes` : clé d'état → mode, pour les
seuls modules qui s'écartent du défaut.

Le scan tourne **avant** le cycle et sans avoir parlé au serveur : il n'a aucune
politique fraîche sous la main, donc la seule façon pour lui de connaître le mode
d'un module est de le trouver écrit là où l'application l'a laissé. C'est aussi
ce qui fait tenir le mode quand le core est injoignable — sinon une machine
coupée du serveur se rabattrait sur enforce et corrigerait des écarts
délibérément placés sur un poste déclaré en audit.

Le mode enregistré vient toujours de la politique **courante**, jamais de l'état
précédent : hériter de l'ancien laisserait la machine en audit après un retour en
enforce, c'est-à-dire exactement au moment où l'administrateur vient de décider
le contraire.

`ForgetModule` efface l'empreinte du module, **pas** son mode : le mode décrit ce
qu'il faut faire du module, pas le fait qu'il soit appliqué.

### Ce qu'audit ne fait pas

Une GPO en audit reste **appliquée** normalement à chaque cycle. Le mode ne
touche qu'à la correction d'un écart constaté entre deux cycles.

Une machine durablement dérivée en audit n'écrit rien dans son état local, et
n'efface donc pas son empreinte de politique. Sans cela elle retéléchargerait et
recomparerait toute sa politique à chaque tour, une fois par heure, pour aboutir
à « rien à faire » à tous les coups.

### Où le voir

| Question | Où |
|---|---|
| Quel mode porte cette GPO ? | Admin → GPO → Réglages |
| Qui l'a changé, et quand ? | journal `SECURITY` — la trace est écrite au même titre que l'activation |
| Cette machine est-elle dérivée ? | `vlt gpo drift` — indépendant du mode, un écart est un écart |

---

## Où la conformité s'affiche

Deux façades, **un seul code de décision**.

| | |
|---|---|
| `vlt gpo status` / `drift` / `status <id>` | `core/command/command_gpo` |
| **Admin → Conformité** (`/admin/gpo/compliance`) | `core/web_serveur/web_admin_conformite.go` |

Ni l'une ni l'autre ne trie, ne décide d'un état ni ne compose un libellé. Tout
cela vit dans `db_gpo` :

| Fonction | Ce qu'elle décide |
|---|---|
| `TrierConformite` | l'ordre — silence, puis échecs, puis écarts |
| `ComplianceRow.Fraicheur` | « à jour », « en retard », « jamais » |
| `ComplianceRow.EtatConformite` | « non vérifié », « ok (N) », « N écart(s) » |
| `ComplianceRow.ModulesAppliques` | « N/M », ou « - » si rien n'a été dit |
| `ComplianceRow.ARetenirDansLaVueDesEcarts` | ce que `drift` montre |
| `ResumerParc` / `ResumeParc.Lisible` | le résumé, compté en **machines** |
| `AgeRelatif` | « il y a 2h » |

Ces fonctions ont d'abord vécu en privé dans `commandgpo`. Tant qu'il n'y avait
qu'une façade, cela n'avait aucune conséquence ; le jour où le portail a eu sa
page, il n'avait que deux choix — les recopier ou les remonter.

**Recopier aurait produit deux vues qui disent *presque* la même chose.** Presque
est le pire cas : personne ne remarque l'écart tant qu'il est petit, et quand il
grandit, on ne sait plus laquelle des deux avait raison. C'est justement la vue
qu'on consulte quand quelque chose ne va pas.

`conformite_sans_divergence_test.go` inspecte la page web et refuse qu'elle
recalcule un seuil, trie, ou recompose un compteur — et vérifie l'inverse, qu'elle
appelle bien les fonctions partagées. Une inspection du texte, parce que rendre
la page pour la comparer demanderait une base peuplée, un serveur HTTP et un
agent qui rapporte : ce test-là n'existerait pas.

Aucune de ces fonctions n'appelle `time.Now()` : l'instant est un paramètre. Un
rendu qui prend l'heure lui-même ne se teste qu'en attendant trois heures.
