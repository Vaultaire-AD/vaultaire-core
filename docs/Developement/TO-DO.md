# TO-DO — Vaultaire

> **Ce fichier ne contient que ce qui reste à faire.** Une tâche terminée le quitte.

## Convention

Trois gestes, dans le même passage que le code :

1. **Supprimer** l'entrée d'ici et l'écrire dans `DO/<version en cours>/<version>.md`, avec ce qui a été fait, ce qui a été mesuré, et ce qui n'a pas été traité.
2. **Re-numéroter le reste** : une partie non traitée revient ici sous un numéro **neuf** — jamais l'ancien, qui se lirait comme une tâche entière non commencée.
3. **Consigner** le changement en haut de `docs/Version/<majeure>/<mineure>.md`.

`DO/` est l'archive, `Version/` le compte rendu, ce fichier la liste de courses.

**Numérotation.** Les numéros sont uniques et croissants : le prochain libre est **202**. Avant la 49, des numéros ont servi plusieurs fois (par exemple trois « 12 » dans `DO/2.1/2.1.md`) ; pour les citer sans ambiguïté, écrire la version et le titre : « 2.1 #12 — create permission ».


**Statut.** « FAIT-IA » veut dire *écrit*, pas *validé*. Tant qu'un point figure dans `docs/exploitation/A_TESTER.md`, il n'a pas été compilé ni exécuté sur une vraie machine.

---

## Vue d'ensemble

| #   | Domaine      | Sujet                                                      | État                                    |
| --- | ------------ | ---------------------------------------------------------- | --------------------------------------- |
| 98  | SÉCURITÉ     | Chiffrer les secrets au repos (clés privées, secrets TOTP)  | À faire — **critique**, à cadrer        |
| 201 | AGENT        | `SystemCallFilter` de l'agent, d'après le relevé sur un poste | À faire — relevé du 181 d'abord, sur un poste |
| 189 | LDAP         | `entryUUID` (point 129) : recette NON, à reproduire         | À faire — détails à relever             |
| 194 | WINDOWS      | La connexion par RDP ne marche pas                          | À faire — à diagnostiquer               |
| 79  | WINDOWS      | GPO et révocations sur les postes Windows                  | À faire — gros chantier                 |
| 67  | CLUSTER      | Restreindre les nœuds qu'un client ou un proxy voit        | À faire — gros chantier                 |
| 196 | AGENT        | `--fetch-key` : une session Ducky neuve et 1 s d'attente à chaque appel de sshd | **En pause** (14/10) — plan écrit |
| 182 | GPO          | Audit : un `sshd_config` non conforme n'est pas signalé     | À faire — à reproduire                  |
| 183 | GPO          | Deux GPO : l'écart signalé disparaît quand une autre GPO s'applique | À faire — à reproduire          |
| 111 | AGENT-UPDATE | Version attendue par groupe, et la vue « constaté vs attendu » | À faire — socle                      |
| 113 | AGENT-UPDATE | Clé `pkg_signing` et format du manifeste signé              | À faire                                 |
| 114 | AGENT-UPDATE | Dépôt Nexus en lecture anonyme, découvert par `04_15`       | À faire                                 |
| 115 | AGENT-UPDATE | Ordre de mise à jour : catégorie de trames `09`             | À faire                                 |
| 116 | AGENT-UPDATE | Basculement survivable et retour arrière automatique        | À faire — **cœur du lot**, après 112    |
| 117 | AGENT-UPDATE | Configuration système réconciliée avec la version           | À faire                                 |
| 118 | AGENT-UPDATE | Mise à jour du client Windows                               | À faire — après la mise en production   |
| 180 | SELINUX      | Confiner l'agent : règles des GPO, puis enforcing          | À faire — sur un poste, voir le 22      |
| 200 | WINDOWS      | Pourquoi le Credential Provider V2 vide l'écran de connexion | Idée — utile seulement pour énumérer les comptes |
| 8   | LDAP         | Mode synchro avec un annuaire existant                     | Idée                                    |
| 40  | AGENT-UPDATE | Mettre à jour le parc de clients                           | Idée — à trancher                       |

---

## Réseau Ducky

### 67. [CLUSTER] [DUCKY] Restreindre les nœuds qu'un client ou un proxy voit

**Demande de Lorens** (point 15 de la liste du 21/09) : « la liste des services
joignables doit être écrite quelque part, et on doit pouvoir filtrer : qu'un
client ne voie que X proxies ou X cores ; et même un proxy, qu'il ne voie pas
tous les cores mais seulement une liste ».

**Aujourd'hui.** La trame `04_04` sert à chaque agent **tous** les nœuds exposés
(`cluster_nodes.expose_aux_agents`), triés par rôle, affinité (TO-DO 38, lot 6)
puis priorité. L'affinité est une **préférence**, jamais une exclusion : c'est
voulu, pour qu'un site dont le proxy tombe se rabatte sur un core. Un proxy, lui,
connaît ses cores par sa configuration.

**Ce qu'il faut trancher avant d'écrire.**

- Un filtre est une **exclusion** : un client limité à « proxy-lyon » n'a plus
  de repli. Faut-il garder toujours au moins un core en queue, ou laisser
  l'administrateur couper délibérément ?
- Où se pose la règle : sur le **groupe** du client (comme l'affinité), sur la
  **clé d'enrôlement**, ou sur le nœud (« ne me sers qu'à ces groupes ») ?
- Pour un proxy, la liste de cores doit-elle venir du core (trame dédiée) ou
  rester dans sa configuration, le core ne faisant que la valider ?
- « Écrite quelque part » : la liste reçue doit-elle être persistée côté agent —
  la liste reçue est déjà persistée (point 61, fait en 2.2 : section `learned`
  de `client_conf.json`) ; un filtre devra s'y appliquer aussi.

**Dépendances.** Le relais (points 38 et 72, faits : Ducky, HTTPS, LDAPS) change ce qu'un proxy
fait pour un client ; le filtrage change qui il sert. Le 72 a déjà donné au proxy une vue
qui lui est propre — les services d'un type, par la `04_15` réservée aux proxies : un filtre
des nœuds servis à un proxy pourrait passer par une trame de la même famille.

**Spécification à écrire** dans `how it work/ducky-network/04-cluster/`.

### 79. [WINDOWS] [GPO] Appliquer les politiques et les révocations sur un poste Windows

**Contexte.** La V1 Windows (voir `DO/2.2/2.2.md`, entrée 77) reçoit les trames `05` (GPO) et `06` (révocation) et les journalise **sans les appliquer**. C'est assumé : les modules GPO existants posent des fichiers, des unités systemd et des réglages PAM, dont aucun n'a d'équivalent direct.

**Ce qu'il faut trancher avant d'écrire.**

- Quel est l'équivalent Windows d'un module GPO : stratégie locale (`secedit`), clé de registre, script ? Le catalogue doit-il être commun aux deux systèmes, avec des modules marqués par plateforme, ou séparé ?
- La conformité et la dérive (`05_15` à `05_17`) supposent de pouvoir RELIRE l'état posé. Le registre s'y prête, un réglage d'interface moins.
- **Révocation** : que fait-on d'une session ouverte ? Fermer une session interactive fait perdre le travail en cours ; ne rien faire laisse un compte révoqué travailler jusqu'à sa déconnexion. Et le mot de passe du compte local reste valable tant qu'il n'est pas changé — la révocation devrait au minimum le rendre inutilisable.
- Les groupes du domaine n'ont pas d'équivalent local posé par l'agent : faut-il créer des groupes Windows locaux, comme on crée les comptes ?

**Dépendance.** À concevoir avec le point 78 : les deux touchent au même agent, et un module GPO qui décrit une machine a besoin de l'inventaire.

**Recette du 12/10.** `kill` ne ferme pas la session d'un compte sur un poste
Windows — c'est l'état attendu tant que ce point n'est pas fait (le 167 dit
« non pris en charge »), mais c'est ce qu'un administrateur remarque en premier.

### 194. [WINDOWS] La connexion par RDP ne marche pas

**Constat** (recette du 12/10, `A_TESTER.md`). La connexion d'un compte du domaine par le Bureau à
distance échoue ; seule la connexion à la console a été validée (avec
`ModeV1`, devenu le comportement par défaut au 179).

**À faire.** Un fournisseur doit accepter
`CPUS_LOGON` **et** `CPUS_CREDUI` (l'invite du client RDP avec la NLA), et le
sérialiser pour `CredUIPromptForWindowsCredentials` ; sans NLA, c'est LogonUI
sur le poste distant, comme à la console. Relever avec le témoin de trace quel
scénario `SetUsageScenario` reçoit, et ce que rend `GetSerialization`.
Vérifier aussi que le compte local créé par l'agent est dans « Utilisateurs du
Bureau à distance ».

---

## Agent

### 201. [AGENT] Poser `SystemCallFilter` sur l'unité de l'agent

**Origine** (reste du **181**). L'outil du relevé existe :
`automatisation/releve-appels-agent.sh` (voir
`docs/exploitation/Agent_configuration_et_debug.md`, « Relever les appels
système »). Il rend les appels que l'agent et ses commandes font hors de
`@system-service`.

**À faire.**

1. Faire le relevé sur un poste de chaque famille (Rocky 9, Debian/Ubuntu),
   pendant la suite de GPO de la formation et des ouvertures de session SSH.
2. Poser `SystemCallFilter=@system-service <ajouts>` et
   `SystemCallErrorNumber=EPERM` dans `unite.Cloisonnement` (un refus qui se
   lit, plutôt qu'un processus tué), retirer l'entrée de `unite.Exclues`.
3. Rejouer la suite de GPO avec le filtre posé ; tout « Operation not
   permitted » nouveau est un appel oublié.
4. Rocky 8 (systemd 239) : le relevé passe par `strace` ; le filtre, lui,
   y est connu.


### 182. [GPO] Audit : un `sshd_config` non conforme n'est pas signalé

**Constat** (recette du 12/10, `A_TESTER.md`), § 7d. Le mode audit ne corrige pas — c'est validé —,
mais un `sshd_config` rendu non conforme à la main n'est **pas** remonté en
écart, malgré plusieurs cycles et rafraîchissements.

**À faire.** Reproduire avec le module SSH de la formation ; regarder si son
contrôle relit vraiment le fichier (ou seulement l'empreinte de ce qu'il a
posé), et si l'écart est perdu à l'agent ou au core (`gpo drift`). Un test qui
casse le fichier et attend l'écart.

### 183. [GPO] Deux GPO : l'écart signalé disparaît quand une autre GPO s'applique

**Constat** (recette du 12/10, `A_TESTER.md`), § 7e. Une GPO en audit, une autre en enforce sur la
même machine : l'écart signalé de la première **disparaît** quand la seconde,
modifiée, est appliquée. On ne sait pas si c'est l'application d'une GPO ou de
deux dans le même cycle.

**À faire.** Reproduire les deux cas séparément. Piste : le rapport de
conformité d'un cycle remplace celui de la machine entière au lieu de ne
remplacer que les GPO appliquées. Le mode doit suivre le module (`A_TESTER.md`
§ 7e).

### 196. [AGENT] [SSH] `--fetch-key` : une session Ducky neuve à chaque appel de sshd

**Origine** (rapport du **190**, [`Analyse_ouverture_session_ssh_2026-10-14.md`](./Analyse_ouverture_session_ssh_2026-10-14.md), § 2.1). À chaque appel,
`sshd` lance un processus `vaultaire_client --fetch-key` qui refait toute la
connexion — TCP, poignée de main, authentification machine, inventaire `02_12`
— puis **attend une seconde sans condition** (`time.Sleep` dans
`WaitForSSHFetch`) avant de demander les clés. Soit **≈ 1,2 s par appel au
minimum**, et `sshd` appelle d'ordinaire deux fois pour la clé acceptée, plus
une fois par clé refusée présentée avant elle.

**À faire.**

1. Que `--fetch-key` demande les clés **au démon**, par son socket local (une
   requête de plus à côté de `AUTH` et `CHECK`), qui les obtient par le tunnel
   machine déjà ouvert. Plus de session Ducky par appel, plus de `02_05`.
2. Retirer l'attente fixe ; garder une borne totale courte (sshd attend).
3. Démon arrêté : ne rien rendre, vite — c'est le comportement d'aujourd'hui
   quand le core est injoignable.
4. Mesurer avant et après (`A_TESTER.md`, § 86 et 89 — le journal de debug
   des connexions du 199 donne la ligne `fetch-key` de chaque appel).

**Mis en pause le 14/10**, au profit de 197, 198 et 199. Le plan proposé, à
reprendre tel quel ou à revoir :

- une requête `{"fetch":{"user":…}}` sur le socket du démon, à côté de `auth`
  et `check` ; le démon envoie `03_06` par son tunnel et attend `03_07` 3 s au
  plus (le core ne répond **rien** sur un refus : c'est l'attente de 10 s
  d'aujourd'hui) ; il rend `{"status":"success","ssh_keys":[…]}` ou un refus ;
- `--fetch-key` ne fait plus que vérifier le domaine, joindre le socket, lire
  la réponse 4 s au plus et écrire les clés — plus de configuration, d'identité
  ni de réseau ; démon arrêté : rien, tout de suite ;
- **défaut à corriger au passage** : `sshreq` n'a qu'une entrée par compte,
  partagée par `auth` et `fetch` — une demande de clés et une authentification
  du même compte qui se croisent prennent la réponse l'une de l'autre. Deux
  registres, et les demandes de clés simultanées d'un même compte attendent la
  même réponse ;
- `WaitForSSHFetch.go` disparaît ; SELinux n'a rien à accorder (sshd joint
  déjà le socket de l'agent).

**À trancher à la reprise : une mémoire de 5 s** des clés rendues, par compte,
pour que le second appel de sshd (la signature) ne refasse pas l'aller-retour —
effacée dès qu'un ordre de révocation arrive pour ce compte. Laissée en
suspens le 14/10.

## Sécurité et authentification

### 98. [SÉCURITÉ] Les secrets sont en clair dans la base

**Constat** (audit du 25/09). `certificates.private_key_data` porte du PEM brut : clés TLS du **portail** et de l'**API**, clé LDAPS, clés du réseau Ducky — dont celle qui chiffre les poignées de main `01_02`. `users.mfa_secret` est un `VARCHAR(64)` qui porte le secret TOTP en base32, en clair (`db_authpolicy/create_schema.go:28`).

Aucun chiffrement de colonne nulle part : la seule AES-GCM du produit sert le **transport** des trames.

Une sauvegarde qui traîne, un réplica mal protégé, une lecture SQL, ou le compte `root@localhost` (dont le mot de passe livré est `root`, voir le point 99) donnent : l'usurpation TLS du portail et de l'API, le déchiffrement des poignées de main Ducky capturées, et les codes TOTP de tout le monde — sans que rien ne le signale, puisque les codes produits sont valides.

**À faire — à cadrer avant d'écrire.** La question qui décide de tout est **où vit la clé maîtresse** :

- un fichier `0600` à côté de la configuration : simple, et perdu avec la machine ;
- une variable d'environnement : convient aux conteneurs, et se lit dans `/proc` ;
- un module matériel ou un coffre externe : le bon choix, et une dépendance d'exploitation de plus.

Une fois tranché : chiffrement d'enveloppe des colonnes `private_key_data` et `mfa_secret`, migration des lignes existantes, et surtout une procédure de **rotation** et de **restauration** — une base dont on a perdu la clé maîtresse est une base perdue.

**Ne pas commencer par le code.** Ce point demande une décision d'exploitation, pas une implémentation.

### 180. [SELINUX] Confiner l'agent : règles des GPO, puis enforcing

**Origine** (reste du **22**). L'agent a son domaine, `vaultaire_t`, mais il est
installé **permissif** : ses règles sont écrites d'après le code et n'ont jamais
tourné, et celles des appliers de GPO ne sont pas écrites du tout — ils écrivent
dans des fichiers de types très variés (`sshd_config.d`, `sudoers.d`,
`sysctl.d`, dépôts, ancres de certificats, règles d'audit, journald, resolved,
grub…). En enforcing, un refus couperait une GPO ou une révocation sans bruit.

**À faire, sur une Rocky de test** (`A_TESTER.md`, § 81) :

1. `deployments/selinux/install.sh`, puis faire vivre l'agent : la suite de GPO
   de la formation, une révocation, un provisionnement de compte.
2. `collect.sh --agent` : chaque couple (type, classe, permissions) refusé.
   Ajouter à `vaultaire.te`, type par type, ceux qu'une GPO du produit
   justifie ; un refus qu'aucune ne justifie désigne une action inattendue de
   l'agent — à comprendre, pas à accorder. `/etc/selinux/config` reste refusé.
3. Quand une collecte complète ne rend plus rien : `install.sh
   --agent-enforcing`, puis la même suite, en enforcing.

---

## Annuaire LDAP

> Constats détaillés : [`Audit_LDAP_2026-09-28.md`](./Audit_LDAP_2026-09-28.md).
> Chaque entrée renvoie à la section qui porte le fichier, la ligne et le
> scénario.
>
> **Tous les points de l'audit sont traités dans la 2.2** : 119 à 132. Ce qui
> reste ici en est sorti en chemin.

---

### 189. [LDAP] `entryUUID` : recette NON, à reproduire

**Constat** (recette du 12/10, `A_TESTER.md`), § 39. Le point 129 (identifiant stable des entrées)
est en échec, sans détail relevé.

**À faire.** Relever la sortie exacte (Directory Studio, sous-schéma,
`entryUUID` d'un compte et d'un groupe), puis Keycloak, qui n'a jamais été
éprouvé ; ouvrir le correctif selon ce qui manque.

---

## Portail et outillage

---

## Idées à cadrer

### 200. [WINDOWS] Pourquoi le Credential Provider V2 vide l'écran de connexion

**Origine** (reste du **179**). Le 179 a fait de la DLL un fournisseur V1 :
c'est ce qui rétablit l'écran, constaté à la recette du 12/10. Le V2
(`ICredentialProviderCredential2`, `ICredentialProviderSetUserArray`) le vide,
sans que l'on sache pourquoi — toutes les méthodes répondent juste sous le faux
LogonUI.

**À cadrer, seulement si** l'on veut un jour que la tuile Vaultaire s'attache
aux comptes déjà affichés (énumération, `GetUserSid`). Le code V2 est toujours
là, derrière la variante d'essai `ModeV2` (README du client Windows) : poser
la valeur, le témoin de trace, et lire où LogonUI s'arrête.

### 8. [LDAP] Mode synchro avec un annuaire existant

Relier Vaultaire à un AD déjà en place pour bénéficier de ses fonctionnalités sans migrer l'annuaire.

### 40. [AGENT-UPDATE] Mettre à jour le parc de clients

**Cadré le 28/09/2026.** La question est tranchée, la stratégie est écrite dans
[`Mise_a_jour_du_parc.md`](./Mise_a_jour_du_parc.md), et le travail est découpé
en **points 111 à 118** (section « Mise à jour du parc » ci-dessous).

Ce qui a été décidé, en quatre lignes :

- **Nexus** sert les artefacts, en **lecture anonyme** — l'intégrité vient de la
  signature, pas du transport. `vlt-upm` disparaît : un site sans Internet verse
  les archives dans son Nexus local, et la signature rend le canal indifférent ;
- une clé **`pkg_signing`** distincte de celle des GPO, déposée à l'installation
  comme elle, avec son propre domaine de signature ;
- une **version attendue portée par le groupe**, pour un déploiement par anneaux,
  et l'agent qui s'y conforme à son rythme ;
- la mise à jour remplace **le binaire et les modules natifs ensemble**, et la
  **configuration système est réconciliée par l'agent**, versionnée avec le code
  qui en a besoin.

Cette entrée reste pour la trace du cadrage. Le travail est aux points 111 à 118.

---

## Mise à jour du parc

> Découpage du point 40, arrêté le 28/09. La conception, les arbitrages et ce
> qui a été écarté sont dans [`Mise_a_jour_du_parc.md`](./Mise_a_jour_du_parc.md) —
> le lire **avant** d'ouvrir l'un de ces points.
>
> **L'ordre compte.** Le 112 était le préalable de sûreté : il est **traité**
> (voir `DO/2.3/2.3.md`) — l'unité de l'agent a une relance bornée, un contrôle
> avant démarrage (`vaultaire_client --check`), et c'est le binaire qui la pose
> (`--install-unit`). Le 111 est le socle sans lequel rien n'est pilotable ; le
> 116 est le cœur du lot, et s'appuie sur le 112.

### 111. [AGENT-UPDATE] La version attendue, et la vue « constaté vs attendu »

**Le socle.** Sans lui, rien n'est pilotable — et il vaut déjà quelque chose
seul : savoir quelles machines sont en retard.

**Constat.** Le core **stocke** la version d'un agent (`id_logiciels.agent_version`,
remontée par `02_12`) et l'**affiche**. Depuis le **161**, il la compare à un
minimum en un seul endroit — l'avertissement de `check_online_minutes` —, pour
prévenir, jamais pour refuser. Aucune notion de version **attendue** n'existe :
ni table, ni réglage, ni écart calculé.

**À faire.**

1. Trois niveaux de cible : `id_logiciels.agent_target_version` (dérogation par
   machine), `groups.agent_target_version` (**le niveau ordinaire**, les anneaux
   de déploiement), `server_settings.agent_target_version` (défaut du parc).
2. Résolution : machine, sinon **la plus haute** des cibles de ses groupes, sinon
   le défaut global, sinon **vide**. Vide = aucune mise à jour automatique, et
   c'est le défaut : une installation en service ne doit rien voir changer tant
   que personne n'a posé de cible.
3. `vlt agent`, `vlt agent -g <groupe>`, `vlt agent target [-g <groupe>] <version>`,
   `vlt agent pin <machine> <version|--none>`. Droits `read:log` / `write:server`,
   portée globale — mêmes clés que la signature GPO et le second facteur Ducky,
   et pour la même raison.
4. Une colonne **VERSION** dans la liste des machines du portail, qui n'en a
   aucune, avec l'écart mis en évidence.
5. Comparaison de versions sémantiques : **écrite au 161** —
   `core/parcversion` (`Lire`, `Avant`, `Recenser`) et la lecture du parc
   `dbclients.VersionsDuParc`. À reprendre, pas à réécrire : c'est elle qui
   décidera de « la plus haute » et du refus de rétrogradation du point 116. Ce
   qu'elle tranche déjà : seul le triplet de tête compte (`+…` et ` (date)` sont
   ignorés), et une version vide ou illisible n'est **jamais** tenue pour à
   jour.

### 113. [AGENT-UPDATE] [SÉCURITÉ] La clé de signature des paquets et le format signé

**À faire.**

1. Clé **`pkg_signing`** dans la table `certificates`, RSA 4096, amorçage
   idempotent — le calque de `gpo_signing` (`signature_politique.go`). Partagée
   par le cluster sans réplication à écrire, et **jamais régénérée** : le faire
   ferait refuser leurs paquets à toutes les machines portant l'ancienne.
2. Dépôt de la partie publique à l'installation, par le SCP de `--join`, à côté
   de `gpo_signing_key.pem`. **Jamais apprise en route** : faire demander à
   l'agent la clé qui juge ce qu'on lui envoie n'aurait aucun sens (raisonnement
   du point 52).
3. Domaine de signature **`vaultaire-pkg-v1`**, distinct de `vaultaire-gpo-v1` :
   une clé ne doit jamais pouvoir signer quelque chose qui passe pour le rôle de
   l'autre.
4. Le manifeste : version, plateforme, et le SHA-256 de chacun des cinq fichiers.
   **Un manifeste plutôt que cinq signatures** — il lie le JEU, et empêche de
   composer un jeu mixte fait de fichiers authentiques pris dans deux versions.
5. Il ne nomme **aucune machine**, contrairement à la signature d'une politique :
   un paquet est le même pour tout le monde, et le lier obligerait à signer à
   chaque téléchargement. La rétrogradation est fermée ailleurs — voir 116.
6. **Prévoir la rotation dès le format** : l'agent doit pouvoir accepter deux
   clés de confiance, sinon remplacer la clé demandera de repasser sur chaque
   machine.
7. Signature à la release : `auto-compil.sh` et le workflow produisent le
   manifeste signé à côté des archives. La clé privée vit sur le core par défaut ;
   documenter le chemin pour la garder hors ligne, sans l'imposer.

### 114. [AGENT-UPDATE] [NEXUS] Le dépôt de mise à jour, et sa découverte par l'agent

**À faire.**

1. Un dépôt Nexus de type **`vaultaire`** pour les artefacts d'agent, en
   **lecture anonyme**. C'est un choix de sûreté, pas un relâchement : l'intégrité
   vient de la signature, et un dépôt authentifié qui sert des paquets nus est
   moins sûr qu'un dépôt libre qui sert des paquets signés. Cela évite aussi de
   distribuer un jeton Nexus à chaque machine du parc.
2. L'agent **n'a pas d'URL Nexus en configuration** : il la demande au cluster par
   `04_15`/`04_16`, comme le proxy le fait déjà pour relayer en HTTPS (point 72).
   `decouverte.AdressesService` existe ; il faut seulement accorder `04_15` au
   type de client `Client`, qui ne l'a pas.
3. Repli sur une URL de `client_conf.json` si le cluster n'annonce aucun Nexus —
   un parc peut vouloir un miroir local qui n'est pas un service enrôlé.
4. Documenter la procédure du site **sans Internet** : télécharger les archives
   ailleurs, les verser par `/api/v1/repos/{repo}/upload`. C'est ce qui remplace
   `vlt-upm`, et c'est un service de moins à écrire, enrôler, superviser et
   mettre à jour lui-même.

### 115. [AGENT-UPDATE] [DUCKY] L'ordre de mise à jour : catégorie `09`

**Constat.** Les catégories `01` à `08` sont prises, `09` est libre.

**À faire.**

```
09_01  demander l'ordre        client → core   au démarrage et à chaque reconnexion
  09_02  ordre : version, dépôt
  09_03  rien à faire
09_04  compte rendu            client → core   version, résultat, motif
  09_05  accusé
09_06  ordre poussé            core → client
```

1. **Le modèle de la révocation (`06`), repris tel quel** : poussée opportuniste
   vers qui est connecté — un échec d'envoi n'est *pas* une erreur, personne ne
   tient de file — et **rattrapage par demande** à chaque reconnexion. C'est ce
   qui rend la poussée non fiable acceptable, et ce qui fait qu'une machine
   éteinte trois semaines se met à jour à son retour.
2. Droits : `09_01` et `09_04` au type `Client`, dans `core/clienttype`.
3. Le compte rendu `09_04` alimente la vue du point 111 : c'est lui qui distingue
   « pas encore tenté » de « tenté et revenu en arrière ».

### 116. [AGENT-UPDATE] Le basculement survivable et le retour arrière

**Le cœur du lot. À ne pas écrire avant que le 112 ne soit en place.**

**À faire.**

1. **Un programme séparé**, `vaultaire_update`, dans `/usr/libexec/vaultaire/` :
   le programme qui remplace un fichier ne peut pas être ce fichier, et il doit
   survivre au redémarrage du service. Lancé détaché par `systemd-run`. C'est le
   problème que `deployments/pre-prod/docker-update.sh` a déjà résolu en se
   recopiant dans un `mktemp` — **à relire avant d'écrire une ligne**.
2. L'ordre : télécharger → vérifier la signature **puis** chaque SHA-256 →
   **`dlopen()` chaque `.so`** → garder la version en place → basculer → redémarrer
   → porte de santé → retour arrière si elle échoue.
3. Le `dlopen()` est le contrôle qui compte : le mode de défaillance réel d'un
   module PAM est l'édition de liens — glibc trop récente, `-lcrypt` manquant — et
   il se voit là, **avant** que sshd n'ait à le charger.
4. Bascule par **`rename()` dans le répertoire de destination**. `rename()` n'est
   atomique qu'au sein d'un système de fichiers : écrire dans `/var/lib` puis
   déplacer vers `/usr/bin` ne l'est pas. Un `.so` déjà chargé n'est pas affecté,
   l'ancien inode reste projeté.
5. **La porte de santé**, trois conditions sous échéance : le service tient
   au-delà de la fenêtre de relance ; le tunnel est rétabli et authentifié ; **le
   socket PAM répond à une sonde sans identifiants**. La troisième est celle qui
   compte — les deux premières ne disent rien du socket, dont dépendent toutes
   les ouvertures de session.
6. **Refus de toute version inférieure** à celle en place, sauf rétrogradation
   explicitement demandée par l'ordre — journalisée en `SECURITY` des deux côtés.
   C'est ce qui ferme la rejouabilité d'un manifeste non lié à une machine.
7. **Ne jamais toucher**, dans la même opération : la configuration système (voir
   117 — si elle est fausse, le retour arrière du binaire ne la répare pas),
   `/etc/vaultaire_client/` (identité et clés : les perdre oblige à réenrôler),
   `/var/lib/vaultaire/applied_policies.json` (le perdre fait réappliquer toutes
   les GPO au cycle suivant).

### 117. [AGENT-UPDATE] La configuration système réconciliée avec la version

**Le cas qui rend ce point urgent.** L'invite du second facteur (point 95) a
besoin de `KbdInteractiveAuthentication yes` dans `sshd_config`. Seul `rocky.sh`
l'écrit, à l'installation. **Toutes les machines installées avant la 2.2 ne
verront donc jamais l'invite** — et rien ne le signalera : le second facteur sera
absent, en silence, sur un chemin d'authentification.

**À faire.**

1. L'agent porte les gabarits que **sa version** attend, chacun marqué
   `# vaultaire-conf v<N>`. Réconciliation au démarrage, **après** que la porte de
   santé du point 116 a été franchie — jamais dans la même opération.
2. Concernés : `/etc/pam.d/{login,sshd,gdm-password}`, `/etc/ssh/sshd_config`,
   `/etc/nsswitch.conf`, `/etc/dconf/db/gdm.d/10-vaultaire-userlist`. Aucun n'est
   sauvegardé ni écrit de façon atomique aujourd'hui.
3. Sauvegarde `<fichier>.vaultaire-bak-<horodatage>`, écriture atomique, et pour
   `sshd_config` : **`sshd -t -f <candidat>` avant de basculer**. S'il refuse, on
   ne touche à rien et on remonte l'écart.
4. **Il n'existe pas de `pam -t`.** D'où les deux protections du point 112 : le
   `PAM_IGNORE` des comptes locaux, tenu par un test-sentinelle, et la sauvegarde
   horodatée qui rend la réparation possible en une commande.
5. **Pas par GPO**, et c'est délibéré : `/etc/pam.d/` est en `path_deny` dans le
   seed, avec son motif écrit — « pile d'authentification : modifiable =
   contournement de l'auth ». Un module GPO, même typé, rendrait la pile
   d'authentification pilotable par une politique, donc potentiellement par un
   délégué de domaine.
6. Éprouver sur le cas `KbdInteractiveAuthentication` avant tout autre : il est
   réel, il est daté, et son absence est silencieuse.

### 118. [AGENT-UPDATE] [WINDOWS] La mise à jour du client Windows

**Après que le mécanisme Linux aura tourné en production.**

**Constat.** La DLL du Credential Provider est chargée par Winlogon, et Windows
**verrouille le fichier** : elle ne peut pas être remplacée à chaud. Il faut
déposer à côté et basculer au redémarrage, ou au minimum hors session. Le service,
lui, se remplace comme sous Linux — mais `install.ps1` est manuel et interactif,
et il n'y a aucun équivalent de `rocky.sh` côté core.

Mêler les deux systèmes produirait une conception qui ne conviendrait bien à
aucun des deux. Reprendre alors : la version attendue (111), la signature (113),
le dépôt (114) et les trames (115), qui sont communs — seul le basculement change.
