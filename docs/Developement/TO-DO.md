# TO-DO — Vaultaire

> **Ce fichier ne contient que ce qui reste à faire.** Une tâche terminée le quitte.

## Convention

Trois gestes, dans le même passage que le code :

1. **Supprimer** l'entrée d'ici et l'écrire dans `DO/<version en cours>/<version>.md`, avec ce qui a été fait, ce qui a été mesuré, et ce qui n'a pas été traité.
2. **Re-numéroter le reste** : une partie non traitée revient ici sous un numéro **neuf** — jamais l'ancien, qui se lirait comme une tâche entière non commencée.
3. **Consigner** le changement en haut de `docs/Version/<majeure>/<mineure>.md`.

`DO/` est l'archive, `Version/` le compte rendu, ce fichier la liste de courses.

**Numérotation.** Les numéros sont uniques et croissants : le prochain libre est **221**. Avant la 49, des numéros ont servi plusieurs fois (par exemple trois « 12 » dans `DO/2.1/2.1.md`) ; pour les citer sans ambiguïté, écrire la version et le titre : « 2.1 #12 — create permission ».


**Statut.** « FAIT-IA » veut dire *écrit*, pas *validé*. Tant qu'un point figure dans `docs/exploitation/A_TESTER.md`, il n'a pas été compilé ni exécuté sur une vraie machine.

---

## Vue d'ensemble

| #   | Domaine      | Sujet                                                      | État                                    |
| --- | ------------ | ---------------------------------------------------------- | --------------------------------------- |
| 98  | SÉCURITÉ     | Chiffrer les secrets au repos (clés privées, secrets TOTP)  | À faire — **critique**, à cadrer        |
| 210 | SÉCURITÉ     | L'identité d'une machine ne s'exporte qu'à sa création      | À faire — **sécurité**, à cadrer (réinstallation) |
| 220 | GPO          | § 7e à rejouer : le mode d'une GPO en audit déteint-il encore ? | À rejouer — suite du 183            |
| 201 | AGENT        | `SystemCallFilter` de l'agent, d'après le relevé sur un poste | À faire — relevé du 181 d'abord, sur un poste |
| 189 | LDAP         | `entryUUID` (point 129) : recette NON, à reproduire         | À faire — détails à relever             |
| 194 | WINDOWS      | La connexion par RDP ne marche pas                          | À faire — à diagnostiquer               |
| 79  | WINDOWS      | GPO et révocations sur les postes Windows                  | À faire — gros chantier                 |
| 67  | CLUSTER      | Restreindre les nœuds qu'un client ou un proxy voit        | À faire — gros chantier                 |
| 196 | AGENT        | `--fetch-key` : une session Ducky neuve et 1 s d'attente à chaque appel de sshd | **En pause** (14/10) — plan écrit |
| 182 | GPO          | Audit : un `sshd_config` non conforme n'est pas signalé     | À faire — à reproduire                  |
| 211 | GPO          | Modules de compte : une valeur par compte (`%u`)            | À faire                                 |
| 219 | NEXUS        | Import GitHub : accepter un tag sans `v`, dire les tags existants | À faire — petit, cause trouvée     |
| 215 | PORTAIL      | Conformité : le nom d'hôte des machines n'apparaît pas      | À faire                                 |
| 218 | DEV          | `dev-comp.sh --add-proxy` ne publie pas LDAP/LDAPS          | À faire — petit                         |
| 217 | AUTH         | Aucun service Vaultaire joignable : comment se connecter ?  | Idée — à cadrer                         |
| 202 | CI           | Release : produire les manifestes du paquet d'agent      | À faire — bloc prêt, à coller           |
| 118 | AGENT-UPDATE | Mise à jour du client Windows                               | À faire — après la mise en production   |
| 180 | SELINUX      | Confiner l'agent : règles des GPO, puis enforcing          | À faire — § 81 d'abord, sur un poste    |
| 203 | SELINUX      | Règles de `vaultaire_t` pour la mise à jour et la configuration système | À faire — avec le 180, sur un poste |
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
qui lui est propre — les services d'un type, par la `04_15` (proxy, et agent pour les Nexus seulement) : un filtre
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

### 220. [GPO] § 7e à rejouer : le mode d'une GPO en audit déteint-il encore ?

**Origine** (reste du **183**, voir `DO/2.3/2.3.md`). Le chemin complet — mode
posé par GPO au core, livré par module, retenu par module dans l'état de
l'agent, décision de correction module par module — est maintenant éprouvé par
un test qui part de la politique telle que le core la livre pour deux GPO de
modes différents : il donne le bon résultat. Un défaut réel a été trouvé et
corrigé à côté : une **attente d'état partagée** par deux modules (un service,
une règle d'audit) n'était attribuée qu'au dernier déclarant ; s'il était en
audit, l'écart n'était plus corrigé pour l'autre.

**À faire.** Rejouer le § 7e avec l'agent à jour (`A_TESTER.md`, recette M7), et
en relever :

1. les modules de chaque GPO (type et paramètres) ;
2. le fichier cassé pour chacune ;
3. la ligne `GPO: machine — N module(s) sur M en audit : …` du journal de
   l'agent, et la ligne GPO du rapport de debug (`dont N en mode audit : …`) ;
4. les lignes `GPO: mode audit, … signale(s) sans correction` et
   `GPO: … marque(s) pour reapplication` au cycle qui suit la casse.

Si l'écart de la GPO en enforce n'est toujours pas corrigé, ces quatre relevés
désignent le module en cause.

### 211. [GPO] Modules de compte : une valeur par compte

**Demande** (recette du 22/10, § 63). Un `user_git_config` pose la **même**
valeur à tous les comptes visés : `user.name` vaut la même chose pour chaque
membre du groupe, ce qui n'a pas de sens. Il faut des marqueurs remplacés au
moment d'appliquer, pour chaque compte — comme `%h` (le dossier personnel)
l'est déjà dans les chemins (`gpo/registry.go`, `expandHome`).

**À faire.**

1. Trancher la liste et la syntaxe : `%u` (nom du compte, `alice`), et sans
   doute `%U` (`alice@acme.lan`), `%d` (domaine), `%n` (nom complet tiré de
   l'annuaire), `%m` (adresse de messagerie si l'annuaire la porte), `%%`
   (un `%` littéral). Une valeur sans marqueur ne change pas.
2. Où : dans les **valeurs** des modules de compte (`user_git_config` d'abord ;
   regarder `user_env`, `user_cron` et les autres), côté **agent**, qui
   connaît le compte — la politique signée reste la même pour tout le groupe.
3. Le contrôle de dérive compare à la valeur **remplacée** ; un marqueur
   inconnu est refusé à l'enregistrement de la GPO (core), pas découvert sur
   le poste.
4. Docs : la référence des modules, la formation (chapitre 6, GPO de compte),
   un exemple `user.name = %n`, `user.email = %m`.

### 196. [AGENT] [SSH] `--fetch-key` : une session Ducky neuve à chaque appel de sshd

**Origine** (rapport du **190**, [`Analyse_ouverture_session_ssh_2026-10-14.md`](./Analyse_ouverture_session_ssh_2026-10-14.md), § 2.1). À chaque appel,
`sshd` lance un processus `vaultaire_client --fetch-key` qui refait toute la
connexion — TCP, poignée de main, authentification machine, inventaire `02_12`
— puis **attend une seconde sans condition** (`time.Sleep` dans
`WaitForSSHFetch`) avant de demander les clés. Soit **≈ 1,2 s par appel au
minimum**, et `sshd` appelle d'ordinaire deux fois pour la clé acceptée, plus
une fois par clé refusée présentée avant elle.

**Mesuré** (recette du 25/10, `strace`, agent d'avant le 197) : deux appels,
**1,7 s** et **3,0 s** ; `time --fetch-key` à la main : **1,3 s**. Chaque appel
lance aussi `who`, `free -h`, `nproc` et `cat /etc/os-release` — l'inventaire
`02_12` de la session qu'il ouvre. Avec l'agent à jour, la clé est dans
`authorized_keys` et sshd **ne lance plus** `--fetch-key` pour une clé déjà
connue : le coût ne reste que pour une clé nouvelle ou retirée.

**À faire.**

1. Que `--fetch-key` demande les clés **au démon**, par son socket local (une
   requête de plus à côté de `AUTH` et `CHECK`), qui les obtient par le tunnel
   machine déjà ouvert. Plus de session Ducky par appel, plus de `02_05`.
2. Retirer l'attente fixe ; garder une borne totale courte (sshd attend).
3. Démon arrêté : ne rien rendre, vite — c'est le comportement d'aujourd'hui
   quand le core est injoignable.
4. Mesurer avant et après (protocole de `Analyse_ouverture_session_ssh_2026-10-14.md` § 5 — le journal de debug des
   connexions du 199 donne la ligne `fetch-key` de chaque appel).

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

### 210. [SÉCURITÉ] [CLIENT] L'identité d'une machine ne s'exporte qu'à sa création

**Demande** (recette du 22/10). L'archive d'installation porte la **clé privée
de la machine** (`private_key.pem`), qui vaut son identité sur le parc.
Aujourd'hui elle se récupère **à tout moment** : `create -export
<computeur_id> <fichier.zip>`, et le bouton « Identité » de la page *Clients*
du portail (action `client.export`). Le core garde pour cela la clé privée de
chaque machine dans `<Client_Conf_path>/clientsoftware/<id>/` (voir
`ducky-network/new_client/archive.go`) : qui obtient ce droit, ou ce
répertoire, peut se faire passer pour n'importe quelle machine du parc.

**Ce qui est voulu.** L'archive se produit **à la création** seulement
(`create -c … --export`, la création au portail, `-join`). Une fois la
machine créée, **aucun** chemin du serveur central ne rend sa clé privée.

**À faire — à cadrer avant d'écrire.**

1. Retirer `create -export <computeur_id>`, l'action `client.export` sur une
   machine existante, et le bouton « Identité » ; leur permission et leur
   ligne `SECURITY` avec.
2. Ne plus **garder** la clé privée : la jeter du core une fois l'archive
   produite ou le `-join` terminé. Vérifier ce qui la relit ensuite (le
   `-join` d'une machine existante, la composition de l'archive, les tests).
3. Trancher la **réinstallation** d'une machine existante, qui s'appuie
   aujourd'hui sur la clé gardée : `vlt create -c <computeur_id> -join …`
   (procédure du 207 « clé compromise », formation). Proposition : une
   réinstallation tire une **nouvelle paire** (la machine garde son
   identifiant, sa clé publique en base est remplacée, l'ancienne refusée),
   au lieu de renvoyer l'ancienne.
4. Les machines déjà créées : purge des clés privées existantes au premier
   démarrage du core qui porte ce point (migration, journalisée), ou geste
   explicite — à trancher.
5. Docs : MAN § 5.5 (« L'archive d'installation »), `Actions_et_Permissions.md`,
   `Client_Windows.md`, la formation (chapitre 5), `Releases.md` (clé
   compromise).

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

### 203. [SELINUX] [AGENT-UPDATE] Les règles de `vaultaire_t` pour la mise à jour

**Origine** (reste du **116**, complété au **117**). La préparation d'une mise
à jour tourne DANS l'agent, donc dans `vaultaire_t` ; `vaultaire.te` n'en a pas les règles. Sans
effet tant que le domaine est permissif (le défaut d'`install.sh`), mais en
enforcing la mise à jour échouerait en `refuse` ou en `echec` « updater non
lancé ». Pas écrit à l'aveugle : une règle qui ne compile pas casse
`install.sh` sur tout le parc, et `checkmodule` n'était pas disponible.

Ce que le code fait, à couvrir (`vaultaire_client/miseajour`) :

1. **HTTPS vers le dépôt** — port 8843 (déjà : `corenet_tcp_connect_all_unreserved_ports`)
   ou 443 (`http_port_t` : `corenet_tcp_connect_http_port`), et la lecture du
   fichier `update_tls_ca` là où l'exploitant l'a posé.
2. **Exécuter le binaire préparé** pour `--check` :
   `/var/lib/vaultaire/updates/<v>/nouveau/vaultaire_client`, en
   `vaultaire_var_lib_t`. Soit `can_exec(vaultaire_t, vaultaire_var_lib_t)`,
   soit — plus étroit — une ligne `.fc` qui étiquette `nouveau/vaultaire_client`
   en `vaultaire_exec_t` et un `restorecon` après l'extraction.
3. **`ldd`** sur les quatre `.so` préparés : `corecmd_exec_bin` et
   `corecmd_exec_shell` sont déjà là ; vérifier l'exécution de `ld.so` en mode
   liste sur des fichiers `vaultaire_var_lib_t`.
4. **Créer l'updater** : `/usr/libexec/vaultaire/` (répertoire et fichier,
   `bin_t`), puis `restorecon`.
5. **`systemd-run`** : démarrer une unité transitoire —
   `init_start_transient_unit(vaultaire_t)` et le dialogue D-Bus avec systemd.

Et depuis le **117**, la réconciliation de la configuration système, elle aussi
dans `vaultaire_t` (`vaultaire_client/confsys`) :

6. **Écrire dans `/etc/pam.d`, `/etc/ssh`, `/etc/nsswitch.conf`,
   `/etc/dconf/db/gdm.d`** — fichier temporaire, `rename()`, sauvegarde à côté :
   `etc_t` en création, écriture, renommage (le domaine n'a que
   `files_read_etc_files` et les droits de répertoire sur `etc_t`). Vérifier le
   type réel de `sshd_config` (`sshd_config_t` sur certaines politiques) et des
   piles PAM.
7. **`sshd -t -f <candidat>`**, et depuis le **209** **`sshd -T -f
   /etc/ssh/sshd_config`** : exécuter `sshd_exec_t` SANS transition (le
   contrôle doit tourner dans le domaine de l'agent, qui lit le candidat), et
   lire les clés d'hôte qu'il charge ainsi que `sshd_config.d/*.conf`.
8. **`systemctl try-reload-or-restart sshd`** (`ssh` sur Debian) — piloter une
   unité système — et **`dconf update`**.

L'updater lui-même tourne hors de `vaultaire_t` : systemd le lance depuis un
fichier `bin_t`, il entre en `unconfined_service_t` — rien à écrire pour la
bascule. À éprouver avec le **180** : `collect.sh --agent` après une mise à
jour réelle, en permissif, puis en enforcing.

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

### 215. [PORTAIL] La page Conformité ne montre pas le nom d'hôte des machines

**Constat** (recette du 25/10, § 94). La page **Admin → Conformité** liste les
machines sans leur nom d'hôte : il faut retrouver chaque identifiant
(`svmAFOFVMs2n-25-10-2026`) ailleurs. Le 191 l'a fait pour les clients d'un
groupe.

**À faire.** Ajouter le nom d'hôte (celui de l'inventaire `02_12`) à la liste
et à la fiche, avec l'identifiant en second ; le tri et la recherche sur le
nom. Un nom d'hôte `localhost.localdomain` ne désigne rien : le dire plutôt
que l'afficher tel quel.

### 218. [DEV] `dev-comp.sh --add-proxy` ne publie pas LDAP/LDAPS

**Constat** (recette du 25/10, § 101). Un proxy ajouté par `--add-proxy` ne
publie que son port Ducky : le relais LDAPS n'est joignable de nulle part, et
le § 101 ne peut pas se jouer. `--port 636:1636` le permet déjà, mais rien ne
le dit au moment où on en a besoin.

**À faire.** Au choix : publier d'office LDAP/LDAPS (décalés comme les autres
ports, `1636 → 1636 + N`) quand un relais `ldaps` est piloté ; ou, plus
simple, que `--add-proxy` **affiche** la commande `--port` et la commande
`cluster relais … set ldaps` à la fin, comme il affiche déjà `cluster expose`.
La recette M3 d'`A_TESTER.md` donne la marche à suivre en attendant.

### 219. [NEXUS] Import GitHub : accepter un tag sans `v`, dire les tags existants

**Constat** (recette du 25/10). « Importer depuis GitHub » rendait une **404** :
le tag saisi était `2.2.0`, et la release s'appelle `v2.2.0`. Vérifié le 25/10
depuis le poste : le dépôt est public, `tags/v2.2.0` et `latest` rendent 200,
`tags/2.2.0` et `tags/v2.3.0` (pas encore publiée) 404. Ce n'est pas un défaut
de Nexus ; la forme attendue est maintenant écrite dans
`src/vaultaire_nexus/README.md` et `Releases.md`.

**À faire** (`src/vaultaire_nexus/internal/files/github.go`, `Import`) :

1. un tag qui commence par un chiffre est essayé tel quel, puis avec un `v`
   devant ;
2. sur une 404, lire `GET /repos/<dépôt>/releases?per_page=10` et le dire :
   « release 2.3.0 introuvable sur Vaultaire-AD/vaultaire-core — disponibles :
   v2.2.0, v2.1.0 » ; si le dépôt lui-même rend 404, « dépôt introuvable (ou
   privé : NEXUS_GITHUB_TOKEN) » ;
3. une aide sous le champ tag de la page du dépôt : « v2.2.0, ou vide pour la
   dernière ».

---

## Idées à cadrer

### 217. [AUTH] Aucun service Vaultaire joignable : comment l'utilisateur se connecte-t-il ?

**Question** (recette du 25/10, § 100). Sans agent qui réponde, ou sans core
joignable, un compte du domaine ne se connecte plus — sous Windows (tuile
Vaultaire) comme sous Linux (PAM). Les comptes locaux et `root` passent, c'est
voulu et testé ; un poste portable hors réseau, lui, devient inutilisable pour
son propriétaire.

**À cadrer.** Un cache d'identifiants hors ligne, comme les « connexions mises
en cache » de Windows : une empreinte du mot de passe (argon2id) gardée sur le
poste après une connexion réussie, valable N jours, jamais pour un compte
révoqué ; le second facteur (TOTP impossible à vérifier sans secret local —
garder le secret sur le poste, ou s'en passer hors ligne ?) ; ce que la
révocation devient tant que le poste est coupé ; le réglage par GPO
(activé ou non, durée, nombre de comptes). Rien n'est à écrire avant la
décision : c'est un compromis de sécurité, pas un détail.

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
> (`--install-unit`). Le 111, le socle, est **traité** aussi : la version
> attendue par machine, groupe et parc, et la vue `vlt agent`. Le 116, le cœur
> du lot, est **traité** : l'agent Linux télécharge, vérifie, bascule, passe la
> porte de santé et revient en arrière seul. Le 117 est **traité** : la
> configuration système (piles PAM, `sshd_config`, `nsswitch.conf`) suit la
> version de l'agent. Reste Windows (118) : les limites relevées en faisant
> le lot (204 à 209) sont traitées.

### 202. [CI] [AGENT-UPDATE] La release produit les manifestes du paquet d'agent

**Origine** (reste du **113**). Le bloc n'a pas pu être écrit par l'IA :
`.github/` lui est fermé. Dans `.github/workflows/release.yaml`, étape
« Paquets », remplacer la ligne `(cd "$O" && sha256sum *.tar.gz > SHA256SUMS)`
par :

```bash
          # Les manifestes du paquet d'agent, NON signés (TO-DO 113) : un par
          # famille de modules. Produits par le binaire du core lui-même — le
          # même code qui les recalculera et les signera sur le site —, pour
          # que la CI et le core ne puissent pas diverger sur le format. La
          # CI ne détient la clé d'aucun cluster : chaque core signe ce qu'il
          # adopte (« vaultaire_serveur --sign-package »).
          "$B/vaultaire_server/vaultaire_serveur" --package-manifest \
            "$O/vaultaire_client-${TAG}-linux-amd64.tar.gz"
          (cd "$O" && sha256sum *.tar.gz *.manifest > SHA256SUMS)
```

`release/*` les publie avec le reste. Vérifier sur la release suivante :
`vaultaire_client-vX.Y.Z-linux-amd64.tar.gz.{rocky,debian}.manifest` présents
et dans `SHA256SUMS`. `docker-update.sh` n'a rien à changer : il ne vérifie
que les archives qu'il installe.

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
