# README pour agents IA — où trouver l'information

**Public : un agent IA (ou un développeur nouveau) qui doit modifier ce dépôt.**

Ce fichier ne décrit aucun mécanisme. Il dit **où chercher**, et rien d'autre.
Chaque mécanisme a sa page dans ce dossier ; le code fait foi quand la page
manque.

---

## 1. La règle du dossier

> **Toute information utile au développement s'écrit dans
> `docs/Developement/how it work/`.**

Pas dans un commentaire de commit, pas dans une issue, pas en tête de fichier Go.
Une décision de conception, un piège rencontré, un invariant à ne pas casser :
ça va ici, dans la page du module concerné, ou dans une nouvelle page si le sujet
n'en a pas.

Le critère de rangement est **le lecteur, pas le sujet** :

| Dossier | Répond à | Lecteur |
| --- | --- | --- |
| `docs/Developement/how it work/` | *comment ça marche, comment y toucher* | qui modifie le code |
| `docs/Utilisation/` | *quoi taper, quel droit accorder* | qui exploite Vaultaire |
| `docs/Installation/` | *comment installer* | qui déploie |
| `docs/exploitation/` | *pourquoi ça casse en production* | qui exploite le parc |

Le même sujet peut avoir une page dans deux dossiers. GPO en a deux : le
mécanisme ici, les commandes dans `Utilisation/MAN.md`.

---

## 2. Le dépôt en une page

Sept modules Go **indépendants** sous `src/`. **Pas de `go.mod` à la racine** :
chacun a le sien, en `go 1.26.1` / `toolchain go1.26.5`.

| Module | Chemin | Ce que c'est |
| --- | --- | --- |
| `vaultaire` | `src/vaultaire_serveur/` | Le serveur central (core). L'essentiel du code. |
| `vaultaire_client` | `src/vaultaire_client/` | L'agent installé sur les postes Linux + les modules PAM/NSS en C |
| `vaultaire_proxy` | `src/vaultaire_proxy/` | Relais Ducky entre un site distant et le core |
| `vaultairectl` | `src/vaultaire_ctl/` | CLI d'administration distante, via l'API REST signée |
| `vaultaire_cli` | `src/vaultaire_cli/` | CLI locale du serveur |
| `duckynetworkclient/V1` | `src/ducky-network-sdk-service/` | SDK Ducky commun aux clients services |
| `vaultaire_api_client` | `src/api_client_package/` | Paquet client de l'API REST |

Ailleurs :

| Chemin | Rôle |
| --- | --- |
| `web_packet/sso_WEB_page/` | **Sources** du portail web (templates, JS, CSS) |
| `cmd/` | **Sortie de compilation.** Produit par `auto-compil.sh`. Ne jamais y éditer. |
| `deployments/` | Docker dev & préprod, SELinux, configuration de référence |
| `auto-compil.sh` | Compile les sept modules + les modules PAM/NSS |
| `repo_manage.sh` | Création/fusion de branches selon le modèle Gitflow du dépôt |

---

## 3. Quel module, quelle doc

Colonne « doc » = la page à lire **avant** de toucher au code.

### Serveur central — `src/vaultaire_serveur/`

| Paquet | Chemin | Doc |
| --- | --- | --- |
| Registre d'actions | `core/action/` | [`Actions.md`](./Actions.md) |
| Permissions RBAC | `core/permission/` | [`Permissions_RBAC.md`](./Permissions_RBAC.md) |
| Base de données | `core/database/` (un sous-paquet `db_*` par table) | [`Base_de_donnees.md`](./Base_de_donnees.md) |
| GPO (côté serveur) | `core/gpo/`, `core/database/db_gpo/`, `ducky-network/gpo_manager/` | [`GPO.md`](./GPO.md) |
| MFA / TOTP / expiration | `core/global/security/totp/`, `core/auth/passwordpolicy/`, `core/database/db_authpolicy/` | [`MFA_et_Expiration.md`](./MFA_et_Expiration.md) |
| Journalisation | `core/logs/` | [`Journalisation.md`](./Journalisation.md) |
| Durées de boucle | `core/reglages/`, `core/database/db_settings/` | [`Reglages_de_duree.md`](./Reglages_de_duree.md) |
| Versions | `core/version/` | [`Versions.md`](./Versions.md) |
| Protocole réseau | `ducky-network/` (trames, sessions, clés) | [`Protocole_Ducky.md`](./Protocole_Ducky.md) |
| Révocation / kill switch | `core/revocation/`, `ducky-network/revocation_manager/` | [`Protocole_Ducky.md`](./Protocole_Ducky.md) § catégorie 06 |
| Commandes `vlt` | `core/command/command_*/` | [`../../Utilisation/MAN.md`](../../Utilisation/MAN.md) |
| Portail web | `core/web_serveur/` + `web_packet/sso_WEB_page/` | — *(pas de page ; lire `startWEBserver.go`)* |
| API REST | `core/api/` | [`../../Utilisation/vaultairectl.md`](../../Utilisation/vaultairectl.md) *(vue client)* |
| LDAP / LDAPS | `core/ldap/` | [`../../Utilisation/vaultaireLDAP.md`](../../Utilisation/vaultaireLDAP.md), [`../../exploitation/ldaps_keycloak.md`](../../exploitation/ldaps_keycloak.md) |
| DNS | `core/dns/` | — *(pas de page ; lire `DNS_Parser/`)* |
| Cluster | `cluster/` | [`Protocole_Ducky.md`](./Protocole_Ducky.md) § catégorie 04 — *détail dans le tableau ci-dessous* |
| Types de client | `core/clienttype/` | [`../../migrations/clienttype_catalogue.md`](../../migrations/clienttype_catalogue.md) |
| Anti-abus réseau | `core/netguard/`, `core/auth/ratelimit/` | — *(pas de page)* |
| Tests intégrés | `core/testrunner/` | — *(pas de page ; un `run_*.go` par domaine)* |
| Structures partagées | `core/storage/` | — |

Le **cluster** a sa propre ligne parce qu'il se lit en trois endroits :

| Sujet | Chemin | Doc |
| --- | --- | --- |
| Nœuds, enregistrement, battement | `cluster/cluster_database/` | [`Protocole_Ducky.md`](./Protocole_Ducky.md) § catégorie 04 |
| Adresse et port **exposés** aux agents | `cluster/cluster_storage/exposition.go`, `cluster_database/exposition_noeud.go` | [`Protocole_Ducky.md`](./Protocole_Ducky.md) § « L'adresse annoncée en 04_04 » |
| **Affinité** nœud ↔ groupe | `cluster/cluster_database/affinite_noeud.go` | [`Protocole_Ducky.md`](./Protocole_Ducky.md) § arbitrage 5 |
| Ordre servi à un agent | `cluster/cluster_database/noeuds_pour_agents.go` | idem |
| « Qui cette machine joindra-t-elle ? » | `cluster/cluster_database/cibles_du_client.go` | idem |

> **Le tri de `noeuds_pour_agents.go` est ce sur quoi tout le parc s'appuie.** Un
> défaut n'y produit aucune erreur : les agents se connectent quand même, au
> mauvais endroit. Ses quatre critères — rôle, affinité, priorité, nom — sont
> ordonnés pour des raisons écrites dans la fonction. Ne pas les réordonner sans
> lire ces raisons.

Point d'entrée du serveur : `src/vaultaire_serveur/main/main.go`.

### Agent client — `src/vaultaire_client/`

| Paquet | Chemin | Doc |
| --- | --- | --- |
| Modules PAM & NSS (C) | `pam_module/` | [`../../exploitation/selinux.md`](../../exploitation/selinux.md) |
| Dialogue avec PAM | `pam_communication/` | [`Protocole_Ducky.md`](./Protocole_Ducky.md) § catégorie 03 |
| Authentification SSH | `sshauth/` | [`Protocole_Ducky.md`](./Protocole_Ducky.md) § catégorie 03 |
| Application des GPO | `gpo/` (`appliers_*.go`, `verifiers*.go`, `drift.go`) | [`GPO.md`](./GPO.md) |
| Comptes locaux, UID/GID | `tools/local_user_management/` | [`GPO.md`](./GPO.md), [`../../exploitation/selinux.md`](../../exploitation/selinux.md) |
| Lien avec le serveur | `serveur_communication/` | [`Protocole_Ducky.md`](./Protocole_Ducky.md) |
| Révocation | `revocation/` | [`Protocole_Ducky.md`](./Protocole_Ducky.md) § catégorie 06 |

Point d'entrée : `src/vaultaire_client/main.go`.

### SDK Ducky — `src/ducky-network-sdk-service/`

| Sujet | Chemin | Doc |
| --- | --- | --- |
| Utilisation du paquet | `ducky/` | `doc/UTILISATION.md` (dans le module) |
| État d'avancement | — | `doc/RECAP.MD` (dans le module) |
| Trames, chiffrement | `duckynetwork/` | [`Protocole_Ducky.md`](./Protocole_Ducky.md) |

### Autres modules

| Module | Doc |
| --- | --- |
| `vaultaire_proxy` | `src/vaultaire_proxy/config.example.yaml` ; protocole → [`Protocole_Ducky.md`](./Protocole_Ducky.md) |
| `vaultairectl` | `src/vaultaire_ctl/README.md`, [`../../Utilisation/vaultairectl.md`](../../Utilisation/vaultairectl.md) |
| `api_client_package` | `src/api_client_package/README.md` |

---

## 4. Par où commencer selon la tâche

| La demande | À lire d'abord |
| --- | --- |
| Ajouter une commande ou une opération | [`Actions.md`](./Actions.md) § 6, puis `core/command/` — **et § 6 ci-dessous** |
| Ajouter un droit, un objet RBAC | [`Permissions_RBAC.md`](./Permissions_RBAC.md) § 4 |
| Ajouter / modifier un module GPO | [`GPO.md`](./GPO.md) § 9 à 12 |
| Régler le comportement d'un nœud | `cluster/cluster_database/exposition_noeud.go` — adresse, port, priorité, rotation |
| Toucher à l'ordre servi aux agents | `cluster/cluster_database/noeuds_pour_agents.go` — lire les raisons AVANT |
| Ajouter une trame réseau | [`Protocole_Ducky.md`](./Protocole_Ducky.md) — la numérotation `MM_SS` n'est pas libre |
| Ajouter une colonne SQL | [`Base_de_donnees.md`](./Base_de_donnees.md), puis **§ 6.3 ci-dessous** — le `CREATE` ne suffit jamais |
| Changer une cadence de boucle | [`Reglages_de_duree.md`](./Reglages_de_duree.md) § 7 |
| Ajouter un journal | [`Journalisation.md`](./Journalisation.md) — *une consultation n'écrit rien* |
| Ajouter un formulaire web | **§ 6.4 ci-dessous** — trois pièges qui échouent en silence |
| Comprendre un mot du domaine | [`../../Utilisation/Lexique.md`](../../Utilisation/Lexique.md) |
| Savoir ce qui reste à faire | [`../TO-DO.md`](../TO-DO.md) |
| Savoir ce qui a changé | [`../../Version_History.md`](../../Version_History.md), détail dans [`../../Version/`](../../Version/) |
| Savoir ce qui reste à ÉPROUVER à la main | [`../../exploitation/A_TESTER.md`](../../exploitation/A_TESTER.md) |

---

## 5. Les pièges à connaître avant d'écrire

1. **`cmd/` est une sortie, pas du code.** Modifier `cmd/web_packet/` est perdu à
   la compilation suivante — les sources du portail sont dans `web_packet/`.
2. **Pas de `go.mod` racine.** Une commande `go` se lance depuis le répertoire du
   module. `auto-compil.sh` les enchaîne, et refuse tout `replace` vers un chemin
   absolu.
3. **Fins de ligne en LF**, y compris sous Windows (`.gitattributes`). Un `\r`
   dans un shebang casse un entrypoint Docker. Seuls les `*.ps1` sont en CRLF.
4. **Pas de binaire dans Git.**
5. **Branches protégées** : `main`, `preprod`, `dev`. Travailler sur
   `feature/<description>-<numéro-issue>` ou `hotfix/...` — voir
   [`../../../CONTRIBUTING.MD`](../../../CONTRIBUTING.MD).
6. **Toute nouvelle fonctionnalité vit dans `src/`, avec ses tests.**
7. **Consigner le changement** dans `docs/Version/<majeure>/<mineure>.md`,
   nouvelles entrées **en haut**. Une tâche terminée passe de
   [`../TO-DO.md`](../TO-DO.md) à `../DO/<version>/` — et si une partie n'est pas
   traitée, elle revient en TO-DO sous un **numéro neuf**, jamais l'ancien.
8. **Toute fonctionnalité se pilote en CLI *et* en web.** Voir § 6.1.

---

## 6. Les invariants — ce qui casse si on les oublie

Cette section existe parce que chacun de ces points a déjà été oublié, et parce
qu'aucun ne se voit à la lecture du code qu'on vient d'écrire.

### 6.1 CLI et web, en lecture comme en écriture

> **Une fonctionnalité qui n'existe que d'un côté est une fonctionnalité à
> moitié livrée.** La règle vaut pour toutes, sans exception.

Et elle vaut **dans les deux sens** : un réglage qu'on pose sans pouvoir le
relire là où on l'a posé est un réglage qu'on repose « au cas où », et dont
personne ne sait dire l'état. Le mode de dérive d'une GPO se réglait en ligne de
commande et ne se relisait qu'en web ; les groupes d'une clé d'enrôlement ne se
relisaient nulle part. Les deux ont dû être rattrapés après coup.

La logique, elle, ne se duplique **jamais** : les deux façades appellent la même
action du registre. Voir [`Actions.md`](./Actions.md).

### 6.2 RBAC — deux tables à compléter, sinon les tests échouent

Ajouter une action au registre **oblige** à l'inscrire dans les deux tables de
`core/action/portees_declarees_test.go` :

| Table | Ce qu'elle fige |
| --- | --- |
| `porteesAttendues` | la fonction de portée déclarée |
| `clesAttendues` | la clé RBAC exigée |

Le test vérifie la **couverture** : une action absente le fait échouer, une
entrée morte aussi. Ce n'est pas une formalité — c'est ce qui empêche qu'une
portée soit relâchée sans que personne le voie.

Deux invariants de plus, tenus par `core/testrunner/run_rbac.go` :

- **toute lecture déclare `UnDomaineSuffit`**, même sous `PorteeGlobale` où le
  champ est inerte. Une règle sans exception se relit sans réfléchir ;
- **aucune écriture ne le déclare** — sinon un délégué d'un domaine agirait sur
  une entité qui en touche deux.

> ⚠️ Cet invariant est aujourd'hui en **défaut connu** sur les actions `.list`
> passées en `PorteeOuverte`, qui ne le déclarent pas. Voir
> [`../../exploitation/A_TESTER.md`](../../exploitation/A_TESTER.md) § 10d avant
> de « corriger » quoi que ce soit.

### 6.3 Une colonne SQL s'ajoute à DEUX endroits

`CREATE TABLE IF NOT EXISTS` **ne compare pas les colonnes** : sur une base en
service, il ne fait rien. Le serveur démarre normalement et échoue à la première
requête qui nomme la colonne — loin du fichier de schéma, en exploitation, sur un
chemin qui marchait la veille.

Il faut donc, systématiquement :

1. la colonne dans le texte du `CREATE TABLE` — pour les bases neuves ;
2. `schematools.EnsureColumn` au démarrage — pour les bases existantes.

Et les deux définitions doivent être **identiques au caractère près**, sans quoi
l'installation aurait un schéma différent selon son âge. `db_schema` le vérifie
par un test qui lit la table `colonnesAjoutees` du code, jamais une liste
recopiée.

### 6.4 Trois pièges de formulaire web, tous silencieux

Le pont `core/web_serveur/web_action.go` recopie les champs d'un formulaire vers
les paramètres d'une action. Trois cas s'y perdent sans erreur :

| Cas | Ce qui se passe | Ce qu'il faut faire |
| --- | --- | --- |
| **Case à cocher décochée** | le navigateur n'envoie RIEN — lu comme « ne pas toucher » | employer un `<select>` à deux options |
| **`<select multiple>` vide** | n'envoie rien — impossible de tout retirer | ajouter un `<input type="hidden">` du même nom, valeur vide |
| **`<select multiple>` garni** | seule la **première** valeur est retenue | joindre les valeurs avant l'appel, ou déclarer `bulk_field` |

`bulk_field` exécute l'action **une fois par valeur** : c'est juste pour ajouter
des liens, faux pour un réglage qui *remplace*.

Toute action de formulaire doit par ailleurs figurer dans `actionsFormulaire` :
une action inconnue est **refusée**, jamais exécutée sans contrôle.

### 6.5 Il n'y a pas toujours de compilateur

Les agents IA travaillent souvent sans toolchain Go. Dans ce cas :

- **ne pas prétendre** que le code compile ou que les tests passent ;
- vérifier ce qui est vérifiable — délimiteurs, imports, cycles, cohérence
  d'une colonne entre DDL, `SELECT` et `Scan` — et le **dire** ;
- terminer l'entrée `DO/` par un bloc `VERIFICATION :` qui énonce ce qui a été
  contrôlé et ce qui ne l'a pas été. C'est la convention du fichier ;
- inscrire ce qui doit être éprouvé à la main dans
  [`../../exploitation/A_TESTER.md`](../../exploitation/A_TESTER.md).

---

## 7. Compiler et lancer

```bash
./auto-compil.sh                             # les 7 modules + PAM/NSS -> cmd/
./deployments/dev/up.sh                      # environnement de développement
./deployments/pre-prod/docker-build-and-up.sh  # pile préprod complète
```

Ports du serveur central : `6666` Ducky · `4443` portail web · `6643` API REST ·
`389`/`636` LDAP/LDAPS. Configuration de référence :
`deployments/configs/serveur_conf.yaml`.

Prérequis : Go 1.26, GCC + `libpam0g-dev`, Docker ≥ 24, MariaDB. Cible Linux ;
depuis Windows, passer par WSL.

---

## 8. Ce qui n'est pas encore documenté

Ces sujets n'ont **pas** de page dans ce dossier. Y toucher veut dire lire le
code — et, une fois compris, **écrire la page ici**.

- Portail web (`core/web_serveur/` + `web_packet/`) — le pont vers les actions
  est commenté dans `web_action.go`, le reste ne l'est pas
- API REST côté serveur (`core/api/`)
- DNS (`core/dns/`)
- Anti-abus réseau (`core/netguard/`, `core/auth/ratelimit/`)
- Tests intégrés (`core/testrunner/`) — pourtant ce sont eux qui tiennent les
  invariants du § 6.2
- Le proxy (`src/vaultaire_proxy/`) — le **relais** n'est pas écrit : c'est ce
  qui reste du point 38, lots 4 et 5

Le **cluster** n'est plus dans cette liste : son fonctionnement est décrit dans
[`Protocole_Ducky.md`](./Protocole_Ducky.md), catégorie 04 et section « Ce qui
reste du sujet 04 ».

---

## Voir aussi

- [`../../README.md`](../../README.md) — index général de la documentation
- [`../../../README.md`](../../../README.md) — README racine : structure, build, workflow Git
- [`../../../CONTRIBUTING.MD`](../../../CONTRIBUTING.MD) — conventions de contribution
