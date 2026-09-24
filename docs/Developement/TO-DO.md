# TO-DO — Vaultaire

> **Ce fichier ne contient que ce qui reste à faire.** Une tâche terminée le quitte.

## Convention

Trois gestes, dans le même passage que le code :

1. **Supprimer** l'entrée d'ici et l'écrire dans `DO/<version en cours>/<version>.md`, avec ce qui a été fait, ce qui a été mesuré, et ce qui n'a pas été traité.
2. **Re-numéroter le reste** : une partie non traitée revient ici sous un numéro **neuf** — jamais l'ancien, qui se lirait comme une tâche entière non commencée.
3. **Consigner** le changement en haut de `docs/Version/<majeure>/<mineure>.md`.

`DO/` est l'archive, `Version/` le compte rendu, ce fichier la liste de courses.

**Numérotation.** Les numéros sont uniques et croissants : le prochain libre est **95**. Avant la 49, des numéros ont servi plusieurs fois (par exemple trois « 12 » dans `DO/2.1/2.1.md`) ; pour les citer sans ambiguïté, écrire la version et le titre : « 2.1 #12 — create permission ».

**Statut.** « FAIT-IA » veut dire *écrit*, pas *validé*. Tant qu'un point figure dans `docs/exploitation/A_TESTER.md`, il n'a pas été compilé ni exécuté sur une vraie machine.

---

## Vue d'ensemble

| #   | Domaine      | Sujet                                                      | État                                    |
| --- | ------------ | ---------------------------------------------------------- | --------------------------------------- |
| 89  | GPO          | `gpo refresh` répond « hors ligne » sur un client en ligne | À faire                                 |
| 86  | GPO          | Le mode audit ne se distingue pas — à reproduire           | À faire — à préciser d'abord            |
| 82  | ENRÔLEMENT   | Archive d'enrôlement : identité machine et empreinte       | À faire                                 |
| 90  | CLIENT       | Rafraîchir la liste des cores/proxies, et basculer         | À faire                                 |
| 94  | CORE         | Un core ne redémarre pas si `clientconfpath` ≠ `/opt/vaultaire/` | À faire                          |
| 84  | CLUSTER      | Les cores ne réintègrent pas le cluster après une veille   | À faire                                 |
| 85  | WEB          | Page Cluster : réglages perdus, et illisible               | À faire                                 |
| 72  | PROXY        | Relais HTTPS (vers les Nexus) et LDAP/S                    | À faire — code prêt, verrous à lever    |
| 93  | DEP VERSION  | Trois défauts relevés par l'inventaire des dépendances  | À faire                              |
| 79  | WINDOWS      | GPO et révocations sur les postes Windows                  | À faire — gros chantier                 |
| 67  | CLUSTER      | Restreindre les nœuds qu'un client ou un proxy voit        | À faire — gros chantier                 |
| 70  | CLIENT       | Le ménage quotidien des comptes ne trouve aucun compte     | À faire                                 |
| 71  | CLIENT       | `-join` ne sait installer que Rocky                        | À faire                                 |
| 33  | GPO          | La dérive du scope utilisateur n'est jamais scannée        | À faire                                 |
| 22  | SELINUX      | Domaine dédié pour l'agent                                 | En cours                                |
| 49  | RÉVOCATION   | Retenter les révocations poussées en échec                 | À faire                                 |
| 52  | GPO          | Signature des politiques par le core                       | À faire                                 |
| 53  | GPO          | Persister les rapports d'application en base               | À faire                                 |
| 8   | LDAP         | Mode synchro avec un annuaire existant                     | Idée                                    |
| 40  | AGENT-UPDATE | Mettre à jour le parc de clients                           | Idée — à trancher                       |

---

## Réseau Ducky

### 72. [PROXY] Relais HTTPS vers les services du cluster, et relais LDAP/S

**Reste du point 38** (lot 4, relais Ducky, fait en 2.2 : `DO/2.2/2.2.md`, entrée 38). Demande de Lorens (22/09) : « le proxy doit pouvoir faire des relais pas que vers du core, il doit aussi pouvoir faire des relais HTTPS vers les Nexus par exemple ».

**Aujourd'hui.** `src/vaultaire_proxy/relais/` connaît les types `https`, `ldap`, `ldaps` et la source `service:<type>`, et les **refuse** au démarrage (`ErrTypePrevu`). Le transport est commun à tous les types et déjà testé.

**Spécification :** `docs/proxy/prevu-https-ldap.md`.

- **HTTPS (lot 5 bis).**
  - Découverte des services : la `04_04` n'annonce que cores et proxies. Il faut que le proxy apprenne les Nexus (extension de `04_04` ou trame réservée aux proxies) — à concevoir avec le 67.
  - Le relais ne termine pas TLS : SAN du certificat du Nexus, ou DNS du site qui résout le nom du Nexus vers le proxy.
  - 443 est privilégié : port haut publié, ou `CAP_NET_BIND_SERVICE`.
- **LDAP/S (lot 5).**
  - SAN du certificat du core couvrant les proxies.
  - La limitation des échecs de bind est **par IP source** (`ratelimit.SourceConn`) : derrière un proxy, un site entier partage un compteur. Exemption pour les proxies enregistrés (comme `netguard` pour Ducky) ou PROXY protocol v2 cru seulement depuis un proxy enregistré.
  - `ldap` (389) : bind simple refusé hors TLS, donc utile seulement avec StartTLS — ou ne pas l'activer.
- Activer = ajouter le type à `actif` dans `relais/config.go`, avec des tests des conditions ci-dessus.

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

**Dépendances.** Le relais (point 38 fait pour Ducky, reste au 72) change ce qu'un proxy fait
pour un client ; le filtrage change qui il sert. À concevoir ensemble.

**Spécification à écrire** dans `how it work/ducky-network/04-cluster/`.

### 79. [WINDOWS] [GPO] Appliquer les politiques et les révocations sur un poste Windows

**Contexte.** La V1 Windows (voir `DO/2.2/2.2.md`, entrée 77) reçoit les trames `05` (GPO) et `06` (révocation) et les journalise **sans les appliquer**. C'est assumé : les modules GPO existants posent des fichiers, des unités systemd et des réglages PAM, dont aucun n'a d'équivalent direct.

**Ce qu'il faut trancher avant d'écrire.**

- Quel est l'équivalent Windows d'un module GPO : stratégie locale (`secedit`), clé de registre, script ? Le catalogue doit-il être commun aux deux systèmes, avec des modules marqués par plateforme, ou séparé ?
- La conformité et la dérive (`05_15` à `05_17`) supposent de pouvoir RELIRE l'état posé. Le registre s'y prête, un réglage d'interface moins.
- **Révocation** : que fait-on d'une session ouverte ? Fermer une session interactive fait perdre le travail en cours ; ne rien faire laisse un compte révoqué travailler jusqu'à sa déconnexion. Et le mot de passe du compte local reste valable tant qu'il n'est pas changé — la révocation devrait au minimum le rendre inutilisable.
- Les groupes du domaine n'ont pas d'équivalent local posé par l'agent : faut-il créer des groupes Windows locaux, comme on crée les comptes ?

**Dépendance.** À concevoir avec le point 78 : les deux touchent au même agent, et un module GPO qui décrit une machine a besoin de l'inventaire.

### 94. [CORE] Un core ne redémarre pas sur sa base quand `clientconfpath` n'est pas `/opt/vaultaire/`

**Constat** (relevé en éprouvant le point 91, 24/09 ; reproduit sur le commit de départ, sans rapport avec lui). Premier démarrage sur une base neuve : normal. Second démarrage sur la même base : arrêt, « Impossible d'amorcer les clés du core : clé SSH de déploiement des agents : sauvegarde clé SSH en BDD: certificat 'server_login_client' existe déjà ».

**Cause lue dans le code.** `Generate_SSH_Key_For_Login_Client` appelle `EnsureLoginClientKeyFiles`, et prend **toute** erreur pour « clé absente » : elle régénère alors, et l'enregistrement bute sur la clé déjà en base. Or l'erreur vient ici de l'écriture du FICHIER : le répertoire créé suit `clientconfpath` (`storage.Client_Conf_path + ".ssh"`), mais le chemin écrit est `storage.PrivateKeyforlogintoclient`, codé en dur sous `/opt/vaultaire/.ssh/`. Dans le conteneur de référence les deux coïncident, d'où un défaut invisible jusqu'ici.

**À faire.** Distinguer « absente en base » de « présente mais pas écrite sur disque » — la seconde ne doit jamais régénérer une clé que tout le parc a déjà acceptée. Et dériver le chemin du fichier de `clientconfpath`, comme le répertoire.

### 84. [CLUSTER] Les cores ne réintègrent pas le cluster après une veille de l'hôte

**Constat** (recette du 24/09). L'hôte des conteneurs se met en veille ; au réveil, les cores sont sortis du cluster et n'y reviennent pas seuls. Il faut les redémarrer.

**Pourquoi c'est important.** Le parc, lui, sait revenir — la dégressivité et le battement sont en place côté agent depuis le point 74. Ce sont les **nœuds entre eux** qui restent fâchés, et un core hors cluster continue de répondre aux agents qui le connaissent déjà : la panne ne se voit pas, elle se découvre.

**À faire.** Reproduire (une veille suffit, ou `docker pause` sur un core). Puis vérifier deux choses : qu'un nœud retente son `04_01` après une rupture — et pas seulement au démarrage —, et que le battement du cluster distingue « pas de réponse » d'une connexion morte. L'hypothèse la plus probable est la seconde : la connexion TCP paraît encore ouverte au réveil, donc rien ne déclenche de réenregistrement.

---

## Agent

### 70. [CLIENT] Le ménage quotidien des comptes locaux ne trouve aucun compte

**Constat** (relevé en écrivant le rapport de debug, 22/09). `StartDailyUserCleanup`
lance chaque jour à 6 h `DeleteUser_Vaultaire_Past_4Days_withoutconnection`
(`tools/local_user_management/deleteUserPast4days.go`), qui cherche les comptes
dont le GECOS contient `vaultaire_user_account`. Or `ProvisionVaultaireUser`
(`createuser.go`) écrit `<compte>@vaultaire`. Aucun compte créé aujourd'hui n'est
donc jamais retiré. De plus, un `/etc/passwd` illisible y déclenche `log.Fatalf`,
qui arrête l'agent entier.

**À faire.** Reconnaître les comptes par la carte `/etc/vaultaire/uid.map` (la
source sûre) plutôt que par le GECOS, remplacer `log.Fatalf` par une erreur
journalisée, et tester sur un `passwd` de fixture. Vérifier au passage le point
11c de `A_TESTER.md` (comptes `x@sous.domaine` d'avant la 2.2).

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

### 90. [CLIENT] La liste des cores et proxies ne se met à jour qu'au démarrage

**Constat** (recette du 24/09). La liste apprise ne se rafraîchit qu'au démarrage ou au redémarrage de l'agent. Un nœud ajouté, retiré ou repriorisé n'est donc pris en compte qu'au prochain redémarrage — et le poste peut rester accroché à un nœud qui n'est plus le bon.

**À faire.** Reprendre la recette des GPO, éprouvée aux points 50 et 51 :

1. **cadence configurable côté core**, envoyée à l'agent en queue d'une trame qu'il reçoit déjà (`04_04`), sur une ligne préfixée — même dispositif que `refresh:` et `sync:` ;
2. **déclenchement à la demande, par machine et par groupe** : une trame poussée par le core et une commande `vlt`, sur le modèle de `gpo refresh` ;
3. **bascule** : si le nœud en cours d'utilisation n'est pas de priorité maximale, fermer la session et en rouvrir une — la reconnexion choisit naturellement le premier. **Égalité de priorité : on ne bascule pas.** C'est la règle qui empêche le va-et-vient entre deux nœuds équivalents, qui coûterait une coupure à chaque tour pour rien.

**Attention.** Une bascule coupe le tunnel machine. Vérifier qu'elle ne fait pas disparaître la machine de `status -c` le temps de la reconnexion, et qu'elle ne fait pas tomber une session PAM en cours — c'est exactement le défaut du point 64, atteint par un autre chemin.

---

## GPO

### 33. [GPO] La dérive du scope utilisateur n'est jamais scannée

**Constat.** `scanMachineDrift` n'existe que pour le scope machine (`vaultaire_client/gpo/cycle.go`). `RunUserCycle` applique les GPO utilisateur à l'ouverture de session mais ne vérifie jamais l'état laissé par la session précédente.

**Pourquoi c'est important.** Les fichiers du scope utilisateur vivent dans son `HOME`, le seul endroit où il édite librement sans être root. La dérive la plus probable est donc celle qui n'est pas surveillée.

**À faire.** Ajouter `scanUserDrift` dans `RunUserCycle`, symétrique de l'existant, à l'ouverture de session. Il doit respecter le mode enforce/audit de chaque module (point 34, fait). La correction reste **différée au cycle suivant**, comme côté machine : réappliquer dans le home pendant que l'utilisateur travaille écraserait ce qu'il vient d'éditer.

### 52. [GPO] Signature des politiques par le core

**Constat.** Le champ `Signature` du manifeste existe (`vaultaire_client/gpo/policy.go`) mais n'est ni rempli ni vérifié. Le tunnel Ducky protège déjà le transport ; la signature protégerait la politique elle-même (état local, relais futur du point 38).

**À faire.** Signer au core, vérifier sur l'agent avant application, refuser une politique non signée une fois la migration faite.

### 53. [GPO] Persister les rapports d'application en base

**Constat.** Les rapports d'application sont seulement journalisés. La conformité (dérive) a sa page ; le résultat d'une application, non.

**À faire.** Les stocker côté core et les afficher sur la page du client, par exemple avec une rétention bornée comme les métriques de nœuds (point 43).

### 86. [GPO] Le mode audit ne se distingue pas d'enforce, et une GPO modifiée ne semble pas repartir

**Constat** (recette du 24/09, **à préciser**). Deux symptômes rapportés, aucun reproduit ici : le mode `audit` ne produit pas de différence visible, et une GPO mise à jour ne semble rien changer chez un client qui l'avait déjà appliquée.

**À faire.** D'abord **reproduire et décrire** : que voit-on exactement, et où — `vlt gpo status`, le journal de l'agent, ou l'état réel des fichiers sur la machine ? Tant que le symptôme n'est pas posé, toute correction serait une supposition.

Une piste pour le second symptôme : l'empreinte porte sur la **politique effective**. Si elle ne bouge pas quand on modifie un module, le client reçoit un `05_03` « rien à faire » — ce qui est cohérent de son point de vue et faux du nôtre. Vérifier ce qui entre dans le calcul de l'empreinte, et si la version de la GPO est bien incrémentée à la modification d'un module.

### 89. [GPO] `gpo refresh` répond « hors ligne » sur un client en ligne

**Constat** (recette du 24/09). La commande annonce la machine hors ligne alors que sa session est établie et que `status -c` la voit. Non approfondi : une session en mauvais état n'est pas exclue.

**À faire.** `DemanderRafraichissement` cherche la session par `sessionmgr.Sessions.GetByClientSoftwareID`. Vérifier que l'identifiant porté par la session est bien celui qu'on lui passe (casse, forme, et **moment** où `SetIdentity` est appelé), et que la session est à l'état authentifié. C'est du neuf — point 50, écrit le 23/09 — et jamais éprouvé contre un vrai parc.

---

## Sécurité et authentification

### 22. [EN COURS] [SELINUX] Politique pour les clients

**Contexte.** Le module NSS lit désormais un fichier et ouvre un socket. Sous `sshd_t`, SELinux refuse : d'où « Invalid user » sans aucun journal Vaultaire, alors que `getent` lancé à la main réussit. Détails : `docs/exploitation/selinux.md`.

**Fait.** `deployments/selinux/` : `collect.sh`, `vaultaire.te`, `vaultaire.fc`, `install.sh`.

**Reste à faire.** Un domaine dédié pour l'agent — il tourne aujourd'hui en `unconfined_service_t`.

### 49. [RÉVOCATION] Retenter les révocations poussées en échec

**Origine.** Reste noté dans `DO/2.0/2.0.md` (kill switch) et jamais reporté ici.

**Constat.** La révocation poussée ne touche que les machines connectées au moment du déclenchement. Une machine absente récupère ses ordres en attente à sa reconnexion (`revocation_manager/trames.go`), mais une machine **connectée dont le push a échoué** attend elle aussi la reconnexion suivante, qui peut ne jamais venir tant que le tunnel tient.

**À faire.** Une tâche de fond côté core qui renvoie périodiquement les ordres en attente aux clients connectés.

### 93. [DEP VERSION] Trois défauts relevés par l'inventaire des dépendances

**Constat** (point 80, 24/09). L'inventaire mis en place a immédiatement montré trois choses qui dormaient. Aucune n'est urgente ; toutes sont écrites, et le test les garde visibles.

**1. `golang.org/x/crypto` en TROIS versions** — v0.47.0 (`vaultaire_ctl`), v0.52.0 (`vaultaire_serveur`), v0.54.0 (`api_client_package`).

C'est la plus gênante : c'est la bibliothèque qui porte argon2id, ed25519 et le client SSH. Un correctif de sécurité appliqué dans un module et pas dans les deux autres n'alerterait personne. `golang.org/x/sys` suit, tirée par elle.

**À faire.** Aligner sur la plus récente, module par module, en vérifiant que rien ne casse — `vaultaire_ctl` est le plus en retard. Puis retirer les deux déclarations de divergence de `dependances.roles` : le test refuse une justification qui ne correspond plus à rien.

**2. `github.com/go-ldap/ldap/v3` n'est plus importée nulle part.** Déclarée directe dans `vaultaire_serveur`, elle n'apparaît dans aucun fichier `.go` — le seul endroit qui la nomme est un commentaire de Nexus expliquant pourquoi Nexus ne l'emploie PAS. Elle tire `go-ntlmssp`, `google/uuid` et `golang.org/x/crypto` pour rien.

**À faire.** Vérifier (`go mod tidy`, qui demande le réseau), retirer, et laisser partir les trois dépendances indirectes qui la suivent. Attention : `x/crypto` doit RESTER, elle est directe depuis le passage à argon2id — c'est écrit dans le `go.mod` du serveur.

**3. Deux versions de YAML dans le même produit.** `vaultaire_serveur` lit sa configuration avec `yaml.v3`, tout le reste du dépôt avec `yaml.v2`. Les deux fonctionnent, et rien ne les oblige à se ressembler — mais un comportement qui diffère entre le core et l'agent sur un fichier de configuration se cherche longtemps.

**À faire.** Trancher : v3 partout, ou v2 partout. v3 est la version maintenue ; la migration n'est pas transparente (elle change le traitement des clés en double et l'indentation rendue).

---

---

## Portail et exploitation

### 85. [WEB] [CLUSTER] Page Cluster : réglages perdus, et illisible

**Constat** (recette du 24/09). Deux choses distinctes, dont une seule est grave :

- les réglages d'un nœud ne sont **pas persistants** — l'IP publique et le port exposé se perdent, et il faut les ressaisir ;
- la page s'allonge avec le cluster : il faut faire défiler pour trouver un nœud et le configurer.

**À faire.** Chercher d'abord **où la configuration d'un nœud est écrasée** : un battement qui réécrit la ligne, ou un redémarrage qui repart de la configuration de fichier. C'est le vrai défaut — une adresse d'exposition perdue, c'est un parc qui tente une adresse injoignable (voir le point 46). La lisibilité vient ensuite : liste courte des membres, et **fiche de configuration au clic** sur un membre, au lieu de tout déplier.

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
