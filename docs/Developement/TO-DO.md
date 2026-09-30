# TO-DO — Vaultaire

> **Ce fichier ne contient que ce qui reste à faire.** Une tâche terminée le quitte.

## Convention

Trois gestes, dans le même passage que le code :

1. **Supprimer** l'entrée d'ici et l'écrire dans `DO/<version en cours>/<version>.md`, avec ce qui a été fait, ce qui a été mesuré, et ce qui n'a pas été traité.
2. **Re-numéroter le reste** : une partie non traitée revient ici sous un numéro **neuf** — jamais l'ancien, qui se lirait comme une tâche entière non commencée.
3. **Consigner** le changement en haut de `docs/Version/<majeure>/<mineure>.md`.

`DO/` est l'archive, `Version/` le compte rendu, ce fichier la liste de courses.

**Numérotation.** Les numéros sont uniques et croissants : le prochain libre est **138**. Avant la 49, des numéros ont servi plusieurs fois (par exemple trois « 12 » dans `DO/2.1/2.1.md`) ; pour les citer sans ambiguïté, écrire la version et le titre : « 2.1 #12 — create permission ».

**Audit de sécurité du 25/09.** Les points 95 à 107 viennent d'une relecture du
code existant, pas d'une recette. Les constats **sérieux** (101 à 107) sont
détaillés dans [`Audit_securite_2026-09-25.md`](./Audit_securite_2026-09-25.md).
**Traités dans la 2.2** : 95, 96, 97, 99, 100, 106, 107 et 108. **Restent
ouverts** : 98 (secrets au repos, à cadrer) et 101 à 105. Ce fichier porte :
ce que le code fait, qui peut l'atteindre, ce qu'il obtient, et pourquoi la
correction n'est pas triviale. Ce fichier porte aussi les constats laissés de
côté, pour qu'ils ne soient pas redécouverts comme neufs.

**Mise à jour du parc (point 40).** Cadrée le 28/09 : la stratégie et ses
arbitrages sont dans [`Mise_a_jour_du_parc.md`](./Mise_a_jour_du_parc.md), le
travail est découpé aux points **111 à 118**. Lire le fichier avant d'ouvrir l'un
d'eux — l'ordre entre les points n'est pas indifférent, et ce qui a été écarté
compte autant que ce qui a été retenu.

**Audit LDAP du 28/09.** Relecture de `core/ldap` — sécurité, fonctionnalités et
compatibilité avec les clients LDAP du marché. Les constats sont détaillés dans
[`Audit_LDAP_2026-09-28.md`](./Audit_LDAP_2026-09-28.md), le travail est découpé
aux points **119 à 131**. **Traités dans la 2.2** : 119 à 127. **Restent
ouverts** : 128 à 131, plus le **132**, relevé en traitant le 120.

**Le point 122 a été tranché à l'inverse de ce qu'il demandait** : il proposait de
rendre visible un compte sans groupe ; la décision a été qu'un tel compte n'a
aucun droit sur le parc, donc rien à faire dans l'annuaire — ni s'y lier, ni y
être trouvé. Le raisonnement est dans `DO/2.2/2.2.md`, point 122. Les entrées ci-dessous disent
quoi faire ; le fichier d'audit dit ce que le code fait aujourd'hui, avec fichier
et ligne — le lire avant d'ouvrir un point. Il porte aussi la section « ce qui est
sain » : plusieurs de ces corrections touchent des fichiers voisins du chemin de
bind, qui vient d'être repris.

**Recette du 30/09 (postes Windows et Linux).** Six constats, dont cinq ouvrent
un point : **133** et **134** (révocation), **135** (dérive du scope
utilisateur), **136** (le test 29d est contradictoire) et **137** (la DLL Windows
manque en silence) — ces deux derniers **traités**, voir `DO/2.2/2.2.md`. Le sixième — récupérer l'identité d'une machine créée depuis
le portail — n'est pas neuf : c'est le **82**, dont la section « À faire » a été
complétée de ce que la recette a montré. Le Credential Provider reste en
attente : la DLL a été recompilée, l'essai n'a pas encore eu lieu.

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
| 128 | LDAP         | Bind non authentifié : le mauvais cas est refusé            | À faire — petit                         |
| 129 | LDAP         | Identifiant d'entrée stable, indépendant du nom             | À faire — débloque le sous-schéma        |
| 130 | LDAP         | Pagination `1.2.840.113556.1.4.319`                         | À faire — au-delà de 10 000 entrées     |
| 131 | LDAP         | Requête par groupe, et `isInScope` mort                     | À faire — petit                         |
| 132 | LDAP         | `memberOf` porte les groupes des sous-domaines              | À faire — **la seule fuite restante**   |
| 135 | GPO          | Le scope utilisateur n'entre jamais dans l'inventaire       | À faire — **la conformité ment**        |
| 86  | GPO          | Le mode audit ne se distingue pas — à reproduire           | À faire — à préciser d'abord            |
| 133 | RÉVOCATION   | `kill -u` ne coupe aucune session ouverte                   | À faire — **l'aide affirme le contraire** |
| 134 | RÉVOCATION   | Le rattrapage `06_04` n'est demandé qu'au démarrage         | À faire                                 |
| 82  | ENRÔLEMENT   | Archive d'enrôlement : identité machine et empreinte       | À faire                                 |
| 79  | WINDOWS      | GPO et révocations sur les postes Windows                  | À faire — gros chantier                 |
| 67  | CLUSTER      | Restreindre les nœuds qu'un client ou un proxy voit        | À faire — gros chantier                 |
| 71  | CLIENT       | `-join` ne sait installer que Rocky                        | À faire                                 |
| 112 | AGENT        | Durcir le service de l'agent (relance bornée, `--check`)    | À faire — **à faire en premier**        |
| 111 | AGENT-UPDATE | Version attendue par groupe, et la vue « constaté vs attendu » | À faire — socle                      |
| 113 | AGENT-UPDATE | Clé `pkg_signing` et format du manifeste signé              | À faire                                 |
| 114 | AGENT-UPDATE | Dépôt Nexus en lecture anonyme, découvert par `04_15`       | À faire                                 |
| 115 | AGENT-UPDATE | Ordre de mise à jour : catégorie de trames `09`             | À faire                                 |
| 116 | AGENT-UPDATE | Basculement survivable et retour arrière automatique        | À faire — **cœur du lot**, après 112    |
| 117 | AGENT-UPDATE | Configuration système réconciliée avec la version           | À faire                                 |
| 118 | AGENT-UPDATE | Mise à jour du client Windows                               | À faire — après la mise en production   |
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

**Ce que la recette du 30/09 ajoute.** Le besoin est confirmé sur un poste Windows, et l'analyse du code précise ce qu'il faut produire — ce n'était pas dans la décision du 24/09.

- **Le portail appelle EXACTEMENT la même action que la CLI** (`create_client` → `client.create`, `web_action.go`). Il crée donc bien l'identité, et laisse ses trois fichiers dans `/opt/vaultaire/clientsoftware/<ID>/` sur le disque du core, où seul un `docker exec` les atteint. La page ne rend que « Machine créée, identifiant … ».
- **Trois fichiers nécessaires ne sont produits QUE par `-join`** : `core_key_fingerprint`, `gpo_signing_key.pem` et `client_conf.json` (`Manage_AUTO_ADD.go`). Une création sans `-join` — celle du portail — n'en produit aucun. L'archive doit donc les fabriquer à la demande ; les trois fonctions existent déjà et prennent un simple répertoire en argument.
- **`client_conf.json` est BLOQUANT pour l'agent Windows** et il est aujourd'hui saisi à la main par `install.ps1`. C'est le fichier dont l'absence de l'archive ruinerait tout le bénéfice.
- **Le choix « Windows » à la création ne doit PAS toucher la colonne `os`.** Elle est écrite en dur à « Linux » à l'insertion, puis renseignée par l'inventaire que l'agent déclare — un commentaire du code interdit explicitement de la rendre éditable, pour qu'elle ne mente pas sur l'état réel. Le choix ne sert donc qu'à composer l'archive : quels fichiers, quel format, quel script.
- **Réserver l'archive aux clients « basic ».** Leur clé privée naît sur le core et voyage déjà — l'archive ne change pas le modèle de confiance, seulement le canal. Celle d'un client SERVICE naît sur son propre hôte et ne doit jamais voyager : le code l'interdit en trois endroits, et la proposer pour un service inverserait un invariant du produit.
- **Format** : préférer le `zip`, que Windows décompresse nativement. Rien n'est à réutiliser côté core (aucune fabrication d'archive en Go nulle part) ; le motif d'en-têtes est dans `src/vaultaire_nexus/internal/web/downloads.go`, et le précédent de gouvernance est `web_admin_enroll.go`, qui montre déjà un secret une seule fois, dans la réponse au POST qui l'a créé.
- **Deux scories relevées en chemin** : `command_setup/setUpNewClient.go` est du code mort qui lirait un certificat `client_software_<id>` que rien n'écrit ; et le core produit `public_key.pem` là où `install.ps1` cherche `public.pem` — sans conséquence, ce fichier n'étant jamais lu, mais l'archive doit trancher.

---

## GPO

### 135. [GPO] [CLIENT] Les fichiers du scope utilisateur n'entrent jamais dans l'inventaire

**Constat** (recette du 30/09). Une GPO de scope `user` dépose un fichier. L'utilisateur le supprime, ou le modifie. La dérive n'est **jamais** détectée : après plusieurs ouvertures de session, `vlt gpo status` et la page Conformité continuent d'annoncer que tout va bien.

**Ce que le code fait.** Le scan lui-même est juste. `scanFromState` (`drift.go`) traite la modification, l'absence, le mode, et même le lien symbolique posé à la place du fichier ; `drift_absent_test.go` le couvre. Le point 33 a bien ajouté le déclenchement à l'ouverture de session, avec sa borne de cadence et son verrou par compte.

**La rupture est en amont, et elle tient en une ligne.** L'inventaire est alimenté par `recordWrite` / `recordAbsent` (`manifest.go`), et ces deux fonctions ne sont appelées **que** par `writeSystemFile` / `removeSystemFile`, dans `appliers_machine.go`. Le chemin du scope utilisateur — `writeUserFile` (`appliers_user.go`) → `ecrireFichierUtilisateur` (`chemin_sur_linux.go`) — n'appelle **ni l'un ni l'autre**.

Conséquence en chaîne : `outcome.Files` est vide → `state.Files` reste vide pour ce scope → `scanFromState` sort sur `len(scopeState.Files) == 0` → `report.Checked == 0` → `scanUserDrift` **renonce en silence, avant même d'émettre un rapport**. Le core ne reçoit donc rien, et la conformité affiche le dernier état connu : conforme.

**Pourquoi les tests ne l'ont pas vu.** `TestLaDeriveEstDetecteeDansUnHome` construit le `ScopeState` **à la main**, en y injectant les entrées `Files` que le vrai chemin n'écrit jamais. Il vérifie donc la règle, pas ce qui la nourrit. C'est exactement le défaut du point 120 (LDAP) : la règle était juste, ce qui l'alimentait ne l'était pas.

**À faire.**

1. Appeler `recordWrite` depuis le chemin du scope utilisateur, avec le chemin **résolu** (le `%h` développé) — c'est celui que le scan relira.
2. Prévoir l'équivalent de `recordAbsent` si un module utilisateur retire un fichier.
3. Un test qui parte du **vrai** applicateur et non d'un état fabriqué : déposer, muter, scanner. Un test-sentinelle interdisant une écriture de fichier qui ne passerait pas par une fonction enregistrant l'inventaire serait mieux encore — c'est la classe d'erreur, pas l'occurrence, qu'il faut fermer.
4. Distinguer, côté affichage, « aucune dérive constatée » de « aucun scan n'a eu lieu ». Aujourd'hui les deux se lisent « conforme », et c'est ce qui a rendu ce défaut invisible.

---

### 86. [GPO] Le mode audit ne se distingue pas d'enforce, et une GPO modifiée ne semble pas repartir

**Constat** (recette du 24/09, **à préciser**). Deux symptômes rapportés, aucun reproduit ici : le mode `audit` ne produit pas de différence visible, et une GPO mise à jour ne semble rien changer chez un client qui l'avait déjà appliquée.

**À faire.** D'abord **reproduire et décrire** : que voit-on exactement, et où — `vlt gpo status`, le journal de l'agent, ou l'état réel des fichiers sur la machine ? Tant que le symptôme n'est pas posé, toute correction serait une supposition.

Une piste pour le second symptôme : l'empreinte porte sur la **politique effective**. Si elle ne bouge pas quand on modifie un module, le client reçoit un `05_03` « rien à faire » — ce qui est cohérent de son point de vue et faux du nôtre. Vérifier ce qui entre dans le calcul de l'empreinte, et si la version de la GPO est bien incrémentée à la modification d'un module.

---

## Sécurité et authentification

### 133. [RÉVOCATION] [SÉCURITÉ] `kill -u` ne termine aucune session ouverte — et son aide affirme le contraire

**Constat** (recette du 30/09). `kill -u <compte>` ne ferme pas les sessions SSH ouvertes, et n'en laisse aucune trace côté client. Le testeur admettait qu'une session GDM survive ; en réalité **aucune** session système n'est coupée, SSH comme GDM.

**Ce que le code fait.** Le chemin est complet et branché — le gestionnaire `06` existe côté agent, la trame arrive, elle est appliquée et acquittée. Mais le mode par défaut (`soft`) se réduit à `lockAccount` (`src/vaultaire_client/revocation/apply.go`) : `usermod -L` puis `chage -E 1`. Deux écritures dans `/etc/shadow`, **aucune action sur un processus vivant**.

C'est correct pour la PRÉVENTION : la phase `account` de PAM refusera toute connexion neuve, clé SSH comprise. C'est sans effet sur une session en cours : une fois `sshd` fourché et le shell lancé, plus rien ne relit `/etc/shadow`. La session survit jusqu'au `exit` — ou indéfiniment sous `tmux`. Le seul `pkill` du dépôt est dans `deleteAccount`, donc en `--hard` seulement, et sa motivation écrite est de laisser passer `userdel`, pas de couper une session.

**Ce que le core ferme, lui**, ce sont les sessions Ducky, les sessions web, et des LIGNES D'AFFICHAGE en base — le commentaire de `FermerSessionsUtilisateurPartout` le dit sans détour. Le compteur « sessions fermées » affiché par la CLI ne compte donc jamais une session SSH, même quand il est non nul.

**Deux obstacles de fond, à trancher avant d'écrire.**

1. **Vaultaire ne sait pas identifier une session.** La table `user_sessions` a pour clé le couple *(compte, machine)*, avec une contrainte d'unicité qui **fusionne trois `ssh` simultanés en une seule ligne**. Ni PID, ni TTY, ni identifiant `logind`. Le module PAM n'en relève aucun non plus. Même en ajoutant demain une trame « tue la session X », rien nulle part ne sait remplir X : l'agent devra repartir du système local.
2. **Les cibles ne viennent pas des sessions ouvertes** mais des GROUPES (`machines_sharing_group_with.go`). Une machine où la personne a une session SSH mais qui n'est dans aucun de ses groupes n'est **jamais visée**, et la CLI affiche quand même un succès.

**À faire.**

1. Dans `lockAccount`, après les deux verrous : `loginctl terminate-user <compte>` quand `systemd-logind` est là, avec repli `pkill -KILL -u`. **À trancher explicitement** : `pkill -u` emporte aussi les processus détachés (`tmux`, `cron`) — probablement voulu sur un compte compromis, mais ce doit être une décision, pas un effet de bord.
2. Corriger le texte d'aide de `kill -h`, qui affirme aujourd'hui « ses sessions ouvertes sont fermées immédiatement » sous un titre « Ce que fait le mode par défaut (soft) ». C'est faux, et c'est l'endroit où un exploitant va chercher la vérité pendant un incident. Vérifier aussi `docs/training/09-…/02-incident-et-journaux.md` et `MAN.md`.
3. Ajouter les sessions ouvertes aux cibles, en plus des groupes.
4. Une recette qui vérifie qu'une session SSH **ouverte** est réellement coupée. Aucun scénario ne le demande aujourd'hui, et le répertoire `revocation/` n'a **aucun** test.

---

### 134. [RÉVOCATION] Le rattrapage `06_04` n'est demandé qu'au démarrage de l'agent

**Constat.** Relevé en instruisant le 133, et probable explication du « aucune trace côté client ».

`revocation.AskPending` n'a qu'un seul appelant dans tout le dépôt : une goroutine lancée par `bootstrapRevocation()`, lui-même appelé **une seule fois** au démarrage de l'agent. Trois commentaires du code et la documentation de conception affirment pourtant le contraire — « à chaque démarrage **et à chaque reconnexion du tunnel** », « une machine éteinte reçoit l'ordre à sa prochaine connexion ».

**Conséquence.** Un ordre émis pendant que le tunnel machine est tombé reste en attente jusqu'au **redémarrage complet du service agent**. C'est exactement le scénario 3 de la recette (couper le réseau une minute, rétablir) : il ne peut pas passer.

**À faire.** Rejouer `AskPending` à chaque rétablissement du tunnel, pas seulement à l'amorçage — ou corriger les trois commentaires et la documentation si l'on décide l'inverse. Ce qui ne doit pas rester, c'est l'écart entre les deux.

---

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

## Annuaire LDAP

> Constats détaillés : [`Audit_LDAP_2026-09-28.md`](./Audit_LDAP_2026-09-28.md).
> Chaque entrée renvoie à la section qui porte le fichier, la ligne et le
> scénario.
>
> **Neuf points sont traités dans la 2.2** : 119 à 127. Ce qui reste : le
> **132**, seule fuite restante et suite directe du 120 ; le **129**, identifiant
> d'entrée stable, dont le 125 a montré qu'il empêche de déclarer `entryUUID`
> sous son vrai OID ; le **130**, pagination ; et le **128**, petit.
>
> **Ordre.** 132 d'abord, puis 129 — le 125 a laissé quatre attributs sous une
> branche privée provisoire faute d'identifiants stables, et le 129 en libère
> deux.

### 128. [LDAP] Le bind non authentifié refusé n'est pas celui de la RFC

**Petit, et à faire pour ce qu'il évite de croire.**

**Constat.** `LDAP_bind.go:148` refuse `op.Name == "" && len(op.Authentication) > 0`
sous un commentaire qui cite la RFC 4513 §5.1.2. Or §5.1.2 vise l'inverse : DN
**non vide** et mot de passe **de longueur nulle**. Ce cas-là descend jusqu'à
`VerifierMotDePasse` avec une chaîne vide.

**Ce n'est pas exploitable** : argon2id d'une chaîne vide ne correspond à aucune
empreinte, et les mots de passe vides sont refusés à la création depuis le point
100. Ce qui doit être corrigé, c'est que le commentaire affirme une protection qui
n'existe pas — la prochaine personne le croira couvert — et qu'un client mal
configuré consomme du rate-limit au lieu d'un refus de protocole immédiat.

**À faire.** Refuser aussi `op.Name != "" && len(op.Authentication) == 0`, avec
`invalidCredentials` ou `unwillingToPerform`, **avant** toute lecture de base, et
corriger les deux commentaires pour qu'ils nomment §5.1.1 et §5.1.2 chacun à sa
place.

Détail : [`Audit_LDAP_2026-09-28.md`](./Audit_LDAP_2026-09-28.md) § 1.4.

### 129. [LDAP] Un identifiant d'entrée stable, indépendant du nom

**Constat.** `entryuuid`, `objectguid`, `nsuniqueid` et `ipauniqueid` valent le
nom d'utilisateur, ou ce nom préfixé (`candidate/user.go`). Ce ne sont donc pas
des identifiants : renommer un compte le fait apparaître comme un compte **neuf**
chez tout client qui s'appuie dessus — Keycloak crée un doublon au lieu de
renommer.

**Ce que le point 125 a montré.** `entryUUID` ne peut pas être déclaré sous son
OID standard tant que sa valeur n'en est pas un : la RFC 4530 attache à cet OID
la syntaxe UUID, et un client strict attend 128 bits en hexadécimal. Il est donc
déclaré sous la branche privée provisoire de Vaultaire, avec `objectGUID`,
`nsUniqueId` et `ipaUniqueID`. Traiter ce point-ci en libère au moins un.

**À faire.** Un UUID posé à la création du compte, stocké, jamais réattribué,
servi en `entryUUID`. Les variantes propriétaires (`objectGUID`, `nsuniqueid`)
peuvent en dériver, ou disparaître : elles n'ont d'intérêt que pour un client qui
croit parler à AD ou à 389-ds.

Prévoir la migration des comptes existants, et le fait qu'un client déjà
synchronisé verra ses comptes changer d'identifiant **une fois**.

Détail : [`Audit_LDAP_2026-09-28.md`](./Audit_LDAP_2026-09-28.md) § 2.9.

### 130. [LDAP] Pagination `1.2.840.113556.1.4.319`

**Constat.** Le contrôle n'est ni annoncé ni supporté, et un contrôle critique
est refusé avec `unavailableCriticalExtension` (12). **C'est le bon comportement
en l'état** — mieux qu'un client qui boucle indéfiniment sur la même page.

La limite est ailleurs : au-delà de `MaxSearchEntries = 10000`, la réponse est
`sizeLimitExceeded` et il n'existe aucun moyen d'obtenir la suite. Un annuaire qui
dépasse ce seuil n'est plus énumérable par aucun client.

**À faire, quand le besoin se présentera.** Le contrôle « simple paged results » :
cookie opaque côté serveur, jeu ordonné stable entre deux pages — c'est cette
stabilité qui est le vrai travail, pas l'encodage du contrôle. Et l'annoncer dans
le RootDSE **seulement** une fois implémenté : il y était annoncé sans l'être, et
c'est précisément ce qui avait été retiré.

Détail : [`Audit_LDAP_2026-09-28.md`](./Audit_LDAP_2026-09-28.md) § 2.6.

### 131. [LDAP] Une requête SQL par groupe, et du code mort trompeur

**Deux petites choses du même passage.**

1. `GetGroupsWithUsersByNames`
   (`db_ldap/get_groups_with_users_by_names.go:18`) boucle et fait **une requête
   par groupe**, alors que le commentaire du résolveur annonce une lecture en lot.
   Le N+1 par **utilisateur** a bien été supprimé ; celui par groupe demeure. Sur
   500 groupes, c'est 500 allers-retours par recherche.
2. `isInScope` (`filter/logical.go`) n'est appelé par personne. Le point 120 étant
   traité, plus rien ne retient : il décrit la règle du « saut de sous-domaine »
   et peut faire croire qu'elle est appliquée au filtrage, alors que le contrôle
   d'accès vit désormais dans `security.PorteeDeRecherche`. Le retirer.

Détail : [`Audit_LDAP_2026-09-28.md`](./Audit_LDAP_2026-09-28.md) § 2.9.

### 132. [LDAP] [SÉCURITÉ] `memberOf` porte les groupes des sous-domaines

**Relevé en traitant le point 120**, et laissé ouvert à dessein : la correction
demande une décision de conception, pas une rustine glissée dans ce lot-là.

**Constat.** Le point 120 écarte bien les entrées de groupe qu'un compte n'a pas
le droit de lire. Mais `userMembershipMap` (`scope/resolver.go`) et
`memberOfForUser` (`scope/base_scope.go`) construisent l'attribut `memberOf` à
partir de **tous** les groupes du compte, sous-domaines compris.

Un délégué de `enov.local` **sans propagation** reçoit donc un compte dont le
`memberOf` nomme des groupes de `admin.enov.local`. Les entrées de ces groupes ne
sortent pas ; leurs **noms**, si. Et comme `ToRootDN` ne garde que les deux
derniers labels, le DN porté par `memberOf` ne dit même pas que le groupe vient
d'ailleurs — il est indistinguable d'un groupe du domaine parent.

C'est plus étroit que le 120 — des noms de groupes, pas des comptes — mais c'est
la même fuite, et elle rend les groupes d'un sous-domaine énumérables.

**Ce qu'il faut décider avant d'écrire.** Filtrer `memberOf` suppose de savoir à
quel domaine appartient chaque groupe listé, donc de porter ce domaine à côté de
son DN. Trois formes possibles, et ce n'est pas indifférent :

1. une liste parallèle dans `UserEntry` — simple, mais deux tranches à tenir
   alignées, ce qui finit toujours mal ;
2. `Groups` devenant une liste de structures `{DN, Domaine}` — propre, mais
   `GetAttributes` et tous ses appelants s'en ressentent ;
3. le filtrage fait dans le résolveur, qui connaît déjà les domaines — le moins
   de code, mais il faudrait y faire remonter la portée, donc mêler le contrôle
   d'accès à la résolution, ce que le point 120 a précisément séparé.

**Et ne pas oublier `member`** : l'attribut symétrique d'une `GroupEntry` liste
les DN de ses membres, y compris des comptes que l'appelant n'a pas le droit de
voir. Même question, même réponse à trouver.

Détail : `DO/2.2/2.2.md`, point 120, alinéa -13.

---

## Idées à cadrer

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
> **L'ordre compte.** Le 112 est un préalable de sûreté qui vaut par lui-même ;
> le 111 est le socle sans lequel rien n'est pilotable ; le 116 est le cœur du
> lot et ne doit pas être écrit avant que 112 ne soit en place.

### 112. [AGENT] Durcir le service de l'agent : relance bornée et validation au démarrage

**À faire en premier, et il vaut par lui-même** — indépendamment de toute mise à
jour.

**Constat.** `/etc/systemd/system/vaultaire_client.service`, écrit par
`rocky.sh:96-112`, ne porte que `Restart=on-failure`. Pas de `RestartSec`, pas de
`StartLimitBurst`, pas d'`ExecStartPre`, aucun durcissement. L'unité de Nexus
(`src/vaultaire_nexus/deploy/vaultaire_nexus.service`) a tout cela ; l'agent est
très en retard sur elle.

**Pourquoi c'est grave ici et pas ailleurs.** Les trois piles PAM sont en
`default=die` sans repli : un agent qui ne démarre pas rend la machine
inaccessible à **tous** les comptes du domaine, sur console, SSH et GDM. Sans
borne de relance, un binaire corrompu boucle indéfiniment et rien ne distingue
« en cours de démarrage » de « ne démarrera jamais ».

**À faire.**

1. `RestartSec=5s`, `StartLimitBurst=3`, `StartLimitIntervalSec=60`.
2. Un mode `vaultaire_client --check` : le binaire s'exécute, lit sa
   configuration, trouve ses clés, et **sort** — sans ouvrir de socket ni de
   tunnel. Branché en `ExecStartPre`.
3. Le même durcissement dans `rocky.sh`, pour les installations neuves, **et** un
   rattrapage sur les unités déjà posées.
4. Un test-sentinelle sur le gabarit des piles PAM : le `PAM_IGNORE` qui laisse
   passer les comptes **hors du domaine** vers `system-auth` est la seule porte
   de secours du produit. Le jour où quelqu'un le retire, plus rien ne le dira.

### 111. [AGENT-UPDATE] La version attendue, et la vue « constaté vs attendu »

**Le socle.** Sans lui, rien n'est pilotable — et il vaut déjà quelque chose
seul : savoir quelles machines sont en retard.

**Constat.** Le core **stocke** la version d'un agent (`id_logiciels.agent_version`,
remontée par `02_12`) et l'**affiche**. Il ne la compare à rien. Aucune notion de
version attendue n'existe nulle part : ni table, ni réglage, ni écart calculé.

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
5. Comparaison de versions sémantiques : à écrire une fois, proprement, et à
   éprouver — c'est elle qui décide de « la plus haute » et du refus de
   rétrogradation du point 116.

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
