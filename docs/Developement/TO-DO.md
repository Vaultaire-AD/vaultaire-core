# TO-DO — Vaultaire

> **Ce fichier ne contient que ce qui reste à faire.** Une tâche terminée le quitte.

## Convention

Trois gestes, dans le même passage que le code :

1. **Supprimer** l'entrée d'ici et l'écrire dans `DO/<version en cours>/<version>.md`, avec ce qui a été fait, ce qui a été mesuré, et ce qui n'a pas été traité.
2. **Re-numéroter le reste** : une partie non traitée revient ici sous un numéro **neuf** — jamais l'ancien, qui se lirait comme une tâche entière non commencée.
3. **Consigner** le changement en haut de `docs/Version/<majeure>/<mineure>.md`.

`DO/` est l'archive, `Version/` le compte rendu, ce fichier la liste de courses.

**Numérotation.** Les numéros sont uniques et croissants : le prochain libre est **111**. Avant la 49, des numéros ont servi plusieurs fois (par exemple trois « 12 » dans `DO/2.1/2.1.md`) ; pour les citer sans ambiguïté, écrire la version et le titre : « 2.1 #12 — create permission ».

**Audit de sécurité du 25/09.** Les points 95 à 107 viennent d'une relecture du
code existant, pas d'une recette. Les constats **sérieux** (101 à 107) sont
détaillés dans [`Audit_securite_2026-09-25.md`](./Audit_securite_2026-09-25.md).
**Traités dans la 2.2** : 95, 96, 97, 99, 100, 106, 107 et 108. **Restent
ouverts** : 98 (secrets au repos, à cadrer) et 101 à 105. Ce fichier porte :
ce que le code fait, qui peut l'atteindre, ce qu'il obtient, et pourquoi la
correction n'est pas triviale. Ce fichier porte aussi les constats laissés de
côté, pour qu'ils ne soient pas redécouverts comme neufs.

**Statut.** « FAIT-IA » veut dire *écrit*, pas *validé*. Tant qu'un point figure dans `docs/exploitation/A_TESTER.md`, il n'a pas été compilé ni exécuté sur une vraie machine.

---

## Vue d'ensemble

| #   | Domaine      | Sujet                                                      | État                                    |
| --- | ------------ | ---------------------------------------------------------- | --------------------------------------- |
| 98  | SÉCURITÉ     | Chiffrer les secrets au repos (clés privées, secrets TOTP)  | À faire — **critique**, à cadrer        |
| 101 | DUCKY        | Cadrage des trames : taille, lectures courtes, SDK          | À faire — sérieux                       |
| 102 | API          | Ni freinage ni borne de corps sur `/api/command`            | À faire — sérieux                       |
| 103 | WEB          | Ni jeton CSRF ni en-tête de sécurité sur le portail         | À faire — sérieux                       |
| 104 | RBAC         | « Deny » ne refuse pas                                      | À faire — sérieux, à trancher           |
| 105 | DNS          | Nom de table construit par concaténation                    | À faire — sérieux                       |
| 109 | CLUSTER      | Un proxy oublié ne se réenregistre jamais                   | À faire                                 |
| 110 | RÉGLAGES     | `check_online_minutes` peut couper le parc en silence       | À faire                                 |
| 86  | GPO          | Le mode audit ne se distingue pas — à reproduire           | À faire — à préciser d'abord            |
| 82  | ENRÔLEMENT   | Archive d'enrôlement : identité machine et empreinte       | À faire                                 |
| 79  | WINDOWS      | GPO et révocations sur les postes Windows                  | À faire — gros chantier                 |
| 67  | CLUSTER      | Restreindre les nœuds qu'un client ou un proxy voit        | À faire — gros chantier                 |
| 71  | CLIENT       | `-join` ne sait installer que Rocky                        | À faire                                 |
| 22  | SELINUX      | Domaine dédié pour l'agent                                 | En cours                                |
| 49  | RÉVOCATION   | Retenter les révocations poussées en échec                 | À faire                                 |
| 8   | LDAP         | Mode synchro avec un annuaire existant                     | Idée                                    |
| 40  | AGENT-UPDATE | Mettre à jour le parc de clients                           | Idée — à trancher                       |

---

## Réseau Ducky

### 101. [DUCKY] Le cadrage des trames : taille, lectures courtes, garde-fou du SDK

**Constat** (audit du 25/09). Trois défauts du même fichier de transport.

1. **Panique déclenchable sans authentification.** `Read_Header_Size`
   (`trames_manager/ReadHeaderSize.go:7`) rend le **premier octet reçu**, sans
   contrainte, et `Read_Message_Size` alloue un tampon de cette taille avant d'y
   faire `binary.BigEndian.Uint16`. Deux octets — `\x01\xff` — suffisent à
   paniquer. Le `recover` de `handleConnection` empêche l'arrêt du core, mais
   chaque panique écrit une ligne **CRITICAL avec la pile complète** : quelques
   octets par seconde noient le journal commun.
2. **Lectures courtes.** `conn.Read` n'est jamais `io.ReadFull`, ni côté core ni
   côté SDK. TCP a le droit de rendre moins d'octets que demandé : l'appelant lit
   alors une taille fausse puis un corps tronqué, et la suite passe pour l'en-tête
   suivant. **Cela arrive sans attaquant**, sur une liaison lente — défaut de
   robustesse qui se manifeste en échec d'authentification intermittent.
3. **Troncature silencieuse à l'émission.** `CompileMessageSize`
   (`sendmessage/SendMessage.go:19`) fait `uint16(len(message))` : au-delà de
   65535, le corps entier part mais est annoncé modulo 65536, et le tunnel est
   désynchronisé définitivement. La trame `02_04` embarque **toutes** les clés
   SSH de l'utilisateur, jointes par virgule, et rien ne borne leur nombre : un
   utilisateur ordinaire peut donc casser l'authentification Ducky de toutes les
   personnes du poste, à chacune de ses connexions. *(Seuil à confirmer par
   mesure ; le mécanisme est certain.)*

**Et le garde-fou qui manque d'un seul côté.** Le core refuse une trame de moins
de cinq lignes (`ReadMessageContent.go:16`, commentaire « SÉCURITÉ » et test
dédié). Le SDK indexe `lines[1]`, `lines[2]`, `lines[3:]` **sans rien vérifier**
(`ducky-network-sdk-service/.../ReadMessageContent.go:12`) — et ce SDK est
partagé par l'agent, le proxy, Nexus et le client Windows. Le défaut a été
identifié et corrigé d'un seul côté.

**À faire.** Refuser tout `headerSize` différent de 2 avant d'allouer ;
`io.ReadFull` partout ; **erreur** au lieu de troncature dans
`CompileMessageSize` ; porter le garde-fou de `parseTrames` dans le SDK ; borner
le nombre de clés SSH par compte. Une dizaine de lignes en tout — le piège est de
corriger le core et d'oublier le SDK, comme la première fois.

Détail : [`Audit_securite_2026-09-25.md`](./Audit_securite_2026-09-25.md) § 101.

### 109. [CLUSTER] Un proxy oublié ne se réenregistre jamais

**Constat** (relevé dans la revue des sessions du 25/09). Dans
`decouverte.DemarrerNoeud` (SDK), le booléen `enregistre` passe à vrai à la
réception du `04_02` et **n'est jamais remis à faux**.

Côté core, `handleHostHeartbeat` sur `touchees == 0` rend `("", error)` : **aucune
trame n'est envoyée**, `Spliter.go` journalise l'erreur et n'a rien à
transmettre. Et même si une trame partait, `decouverte.HandleTrame` range `"08"`
dans les accusés « rien à faire ».

Un proxy purgé après 24 h hors ligne bat donc dans le vide indéfiniment,
invisible du cluster, en se croyant enregistré. C'est le TO-DO 84 pour les
proxies : le correctif du point 85 (`startHeartbeatLoop` → `RegisterNode`) ne
vaut que pour un **core** qui écrit dans sa propre base.

**À faire.** Renvoyer un refus explicite au battement d'un nœud inconnu — le
commentaire de `Spliter.go` décrit déjà ce besoin, mais pour `04_01` — et remettre
`enregistre` à faux à sa réception, ce qui fait rejouer `04_01` au tour suivant.
Un test du côté SDK : un refus de battement doit produire un réenregistrement.

### 110. [RÉGLAGES] `check_online_minutes` peut couper le parc en silence

**Constat** (audit du 25/09). Le réglage `check_online_minutes` est réglable de 1
à 60 minutes. Mais `authIdleTimeout` (**5 min**) et `handshakeIdleTimeout`
(60 s) sont des constantes de `duckyGoroutine.go`, et `dbsessions.ValiditeSession`
(**10 min**) en est une autre. Seul `FraicheurTunnel()` suit le réglage.

Porter la cadence à 6 minutes fait donc couper par le balayage **toutes les
sessions authentifiées** avant leur premier battement. La porter à 11 fait quitter
`status -c` à tout le parc entre deux battements. Rien ne l'interdit, rien ne le
signale, et le symptôme — « le parc se déconnecte en boucle » — ne désigne pas le
réglage qu'on vient de changer.

Les commentaires justifient les 5 et 10 minutes **par rapport à la valeur par
défaut de 2**. C'est exactement le raisonnement que `dbgpo.CadenceAgent` a été
créé pour éviter côté GPO, où la tolérance « trois cycles » est calculée depuis le
réglage et non écrite en dur.

**À faire.** Dériver les trois valeurs du réglage — par exemple
`2 × cadence + 1 min` pour le balayage et `5 × cadence` pour la validité en base
— avec un plancher. Le même geste que `FraicheurTunnel()`, appliqué aux deux
autres. Et un test qui pose la cadence à son maximum et vérifie qu'aucune session
saine n'est coupée.


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

---

## Agent

### 71. [CLIENT] `create -c … -join` ne sait installer que Rocky

**Constat.** `ExecuterCommandesSSHAvecCle` choisit `debian.sh`, `ubuntu.sh` ou
`rocky.sh` selon `/etc/os-release`, mais seul `rocky.sh` existe dans
`automatisation/auto_deployements/` : sur Debian ou Ubuntu, l'installation
échoue au transfert du script. `rocky.sh` est aussi propre à dnf et aux chemins
`/usr/lib64`.

**À faire.** Un `debian.sh` (apt, `/lib/x86_64-linux-gnu/security`) commun à
Debian et Ubuntu, avec la même section 4 (liste des cores déposée par le core,
repli sur `SSH_CONNECTION`).

### 82. [ENRÔLEMENT] Archive d'enrôlement : identité de la machine et empreinte du core

**Constat** (recette du 24/09). Récupérer l'identité d'une machine créée demande un `docker exec` sur le core ; récupérer l'empreinte du core demande d'aller la lire sur un poste déjà installé. Deux étapes manuelles au milieu d'une installation qui se veut simple — et l'empreinte finit recopiée dans la documentation d'installation, c'est-à-dire publiée.

**Décision du 24/09.** Une **archive d'enrôlement**, produite par la CLI et téléchargeable depuis le portail. Le modèle de confiance ne change pas : un agent ne s'enrôle toujours pas seul, l'identité est créée sur le core et transportée. On rend seulement le transport praticable.

**À faire.**

1. `vlt create -c <nom> --export <chemin>`, et une commande d'export pour une machine déjà créée : une archive portant `client_software.yaml`, `private_key.pem` **et l'empreinte du core**.
2. Page Machines du portail : téléchargement de cette archive, sous le droit qui crée la machine.
3. `install.ps1` accepte l'archive et ne pose plus de question sur l'empreinte.
4. Retirer de [`Installation/Client_Windows.md`](../Installation/Client_Windows.md) l'étape « relevez l'empreinte » : elle n'a plus lieu d'être — c'est la demande explicite du 24/09.

**Attention.** L'archive porte une **clé privée de machine**. Validité courte du lien de téléchargement, trace dans le journal, aucune mise en cache côté portail, et un nom de fichier qui ne laisse aucun doute sur ce qu'il contient.

---

## GPO

### 86. [GPO] Le mode audit ne se distingue pas d'enforce, et une GPO modifiée ne semble pas repartir

**Constat** (recette du 24/09, **à préciser**). Deux symptômes rapportés, aucun reproduit ici : le mode `audit` ne produit pas de différence visible, et une GPO mise à jour ne semble rien changer chez un client qui l'avait déjà appliquée.

**À faire.** D'abord **reproduire et décrire** : que voit-on exactement, et où — `vlt gpo status`, le journal de l'agent, ou l'état réel des fichiers sur la machine ? Tant que le symptôme n'est pas posé, toute correction serait une supposition.

Une piste pour le second symptôme : l'empreinte porte sur la **politique effective**. Si elle ne bouge pas quand on modifie un module, le client reçoit un `05_03` « rien à faire » — ce qui est cohérent de son point de vue et faux du nôtre. Vérifier ce qui entre dans le calcul de l'empreinte, et si la version de la GPO est bien incrémentée à la modification d'un module.

---

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

### 102. [API] Ni freinage ni borne de corps sur `/api/command`

**Constat** (audit du 25/09). `core/api/api.go` n'importe pas `ratelimit`, et `commandHandler` (l. 130) décode le corps JSON **avant toute authentification**, sans `http.MaxBytesReader`.

Chaque requête anonyme coûte donc au core deux lectures en base puis une vérification RSA **par clé enregistrée** sur le compte visé. Le port est ouvert à tous, puisque l'authentification *est* la signature.

Trois conséquences : un amplificateur de déni de service ; une énumération de l'annuaire par chronométrage (« utilisateur introuvable » sort avant la lecture des clés) ; et plusieurs gigaoctets en mémoire par requête en vol, avec un `ReadTimeout` de 30 s.

**À faire.** Freiner **sur la source seule**, avant de savoir de quel compte il s'agit — le freinage existant raisonne sur un couple (compte, source) après échec, il ne convient pas tel quel. Borner le corps avec `http.MaxBytesReader`. Égaliser le temps de réponse entre compte inconnu et signature invalide.

**Attention.** Un intégrateur légitime pilote le parc en rafale : le barème par source doit le laisser travailler. Voir [`Audit_securite_2026-09-25.md`](./Audit_securite_2026-09-25.md) § 102.

### 103. [WEB] Ni jeton CSRF ni en-tête de sécurité sur le portail

**Constat** (audit du 25/09). Recherche exhaustive dans `vaultaire_serveur` : **zéro** occurrence de `csrf`, `Content-Security-Policy`, `X-Frame-Options`, `Strict-Transport-Security`, `X-Content-Type-Options`, `Referrer-Policy`. La seule mention de CSRF est un commentaire de `web_login.go:126` qui **constate l'absence**.

La défense repose entièrement sur `SameSite=Strict`. Les actions d'administration sont des POST simples : créer un compte, lier une GPO, déclencher un **kill switch**.

**À faire.** Porter le dispositif de Nexus (`vaultaire_nexus/internal/web/ui.go:212`), qui a déjà de vrais jetons CSRF — il s'agit de le reprendre, pas de l'inventer. Ajouter les en-têtes, et sortir le JavaScript en ligne des gabarits pour qu'une `Content-Security-Policy` stricte tienne.

**Attention.** Un jeton par formulaire veut dire toucher **tous** les gabarits d'administration et tous les gestionnaires POST. Voir [`Audit_securite_2026-09-25.md`](./Audit_securite_2026-09-25.md) § 103.

### 104. [RBAC] « Deny » ne refuse pas

**Constat** (audit du 25/09). `permission-manager.go:82` et `permission-manager-strict.go`, même motif : `if parsedPermission.Deny { continue }`. Un refus explicite fait **sauter ce groupe** ; si un autre groupe accorde, c'est accordé.

Un exploitant qui croit retirer un droit en posant un refus ne retire **rien** tant que la cible appartient à un autre groupe permissif. Un mot qui dit l'inverse de ce qu'il fait, sur un contrôle d'accès.

**À trancher avant d'écrire.** Le comportement est **délibéré** : le commentaire de `DomainsWhereAllowed` l'assume, pour que « ce qu'on voit » et « ce qu'on peut » restent cohérents. Deux issues, et le choix n'est pas technique :

- rendre `Deny` prioritaire — la sémantique attendue, celle d'AD —, au risque de retirer des droits en service à la mise à jour ;
- **renommer** : si ce n'est pas un refus, cela ne doit pas s'appeler `Deny`.

Voir [`Audit_securite_2026-09-25.md`](./Audit_securite_2026-09-25.md) § 104.

### 105. [DNS] Le nom de table est construit par concaténation

**Constat** (audit du 25/09). Cinq fichiers de `core/dns/DNS_Database/` font `safeTableName := "zone_" + strings.ReplaceAll(zoneName, ".", "_")` puis l'interpolent dans la requête (`DNS_DELETE_Zone.go:11`). La variable s'appelle `safeTableName` ; seuls les points ont été remplacés.

`nomDNSAcceptable` (`actions_dns.go:361`) refuse les espaces, `/`, `\` et les sauts de ligne — mais **laisse passer l'apostrophe inverse et la virgule**. Or `DROP TABLE` accepte une liste séparée par des virgules, et MySQL cite les identifiants avec des apostrophes inverses.

Un délégué `write:dns` peut vraisemblablement faire supprimer une table arbitraire. `multiStatements` n'étant pas activé dans le DSN, il n'y a pas de requête empilée — la portée est la destruction, pas l'exécution. **À confirmer par un essai réel.**

**À faire.** Valider le nom de zone par une **liste blanche** (`^[a-z0-9]([a-z0-9-]*[a-z0-9])?(\.[a-z0-9]([a-z0-9-]*[a-z0-9])?)*$`) et citer l'identifiant, dans les **cinq** fichiers. Allonger la liste de caractères interdits serait la mauvaise correction.


### 22. [EN COURS] [SELINUX] Politique pour les clients

**Contexte.** Le module NSS lit désormais un fichier et ouvre un socket. Sous `sshd_t`, SELinux refuse : d'où « Invalid user » sans aucun journal Vaultaire, alors que `getent` lancé à la main réussit. Détails : `docs/exploitation/selinux.md`.

**Fait.** `deployments/selinux/` : `collect.sh`, `vaultaire.te`, `vaultaire.fc`, `install.sh`.

**Reste à faire.** Un domaine dédié pour l'agent — il tourne aujourd'hui en `unconfined_service_t`.

### 49. [RÉVOCATION] Retenter les révocations poussées en échec

**Origine.** Reste noté dans `DO/2.0/2.0.md` (kill switch) et jamais reporté ici.

**Constat.** La révocation poussée ne touche que les machines connectées au moment du déclenchement. Une machine absente récupère ses ordres en attente à sa reconnexion (`revocation_manager/trames.go`), mais une machine **connectée dont le push a échoué** attend elle aussi la reconnexion suivante, qui peut ne jamais venir tant que le tunnel tient.

**À faire.** Une tâche de fond côté core qui renvoie périodiquement les ordres en attente aux clients connectés.

**Déjà corrigé par le point 89 (24/09).** Une partie des « push en échec sur une machine connectée » ne venait pas du réseau : la session était choisie au hasard parmi celles qui portaient l'identifiant de la machine — poignée de main, session d'un utilisateur. `pushToOnline` passe désormais par `sessionmgr.SessionsMachine`. Reste le vrai sujet de ce point : rejouer un ordre dont l'envoi a réellement échoué.

---

## Idées à cadrer

### 8. [LDAP] Mode synchro avec un annuaire existant

Relier Vaultaire à un AD déjà en place pour bénéficier de ses fonctionnalités sans migrer l'annuaire.

### 40. [AGENT-UPDATE] Mettre à jour le parc de clients

**Question.** Comment mettre à jour les agents, y compris sans accès Internet ?

**Pistes :**

- **Dépôt (Nexus)** ordonné par le core — la plus simple ; le dépôt n'a pas besoin d'authentification, ce n'est pas un service sensible à consulter. **Piste privilégiée.**
- Téléchargement **via le réseau Ducky**.
- Un nouveau service, **`vlt-upm`** (Vaultaire Update Manager), pour les parcs sans Internet — fonctionnement à définir.

Dans tous les cas, le pilotage passe par l'interface web d'administration.
