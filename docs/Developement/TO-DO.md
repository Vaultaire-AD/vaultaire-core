# TO-DO — Vaultaire

> **Ce fichier ne contient que ce qui reste à faire.** Une tâche terminée le quitte.

## Convention

Trois gestes, dans le même passage que le code :

1. **Supprimer** l'entrée d'ici et l'écrire dans `DO/<version en cours>/<version>.md`, avec ce qui a été fait, ce qui a été mesuré, et ce qui n'a pas été traité.
2. **Re-numéroter le reste** : une partie non traitée revient ici sous un numéro **neuf** — jamais l'ancien, qui se lirait comme une tâche entière non commencée.
3. **Consigner** le changement en haut de `docs/Version/<majeure>/<mineure>.md`.

`DO/` est l'archive, `Version/` le compte rendu, ce fichier la liste de courses.

**Numérotation.** Les numéros sont uniques et croissants : le prochain libre est **181**. Avant la 49, des numéros ont servi plusieurs fois (par exemple trois « 12 » dans `DO/2.1/2.1.md`) ; pour les citer sans ambiguïté, écrire la version et le titre : « 2.1 #12 — create permission ».


**Statut.** « FAIT-IA » veut dire *écrit*, pas *validé*. Tant qu'un point figure dans `docs/exploitation/A_TESTER.md`, il n'a pas été compilé ni exécuté sur une vraie machine.

---

## Vue d'ensemble

| #   | Domaine      | Sujet                                                      | État                                    |
| --- | ------------ | ---------------------------------------------------------- | --------------------------------------- |
| 98  | SÉCURITÉ     | Chiffrer les secrets au repos (clés privées, secrets TOTP)  | À faire — **critique**, à cadrer        |
| 176 | CLUSTER      | Purger un PROXY en maintenance de ses connexions            | À faire — à concevoir, voir le 147      |
| 177 | CLUSTER      | Un core en maintenance accepte encore les connexions        | À faire — à trancher                    |
| 175 | LDAP         | Une recherche `base` rend un compte SANS groupe quand la base flanche | À faire — petit, la recherche `sub` échoue déjà |
| 171 | PAM          | Un mot de passe expiré se lit au journal du poste, pas à l'écran | À faire — petit, à trancher         |
| 172 | GPO          | « Demander un cycle » n'atteint que les machines de ce core | À faire — à vérifier sur un cluster     |
| 179 | WINDOWS      | Écran vide : valider le correctif du 157 sur un poste       | **À faire — bloque la recette Windows** |
| 79  | WINDOWS      | GPO et révocations sur les postes Windows                  | À faire — gros chantier                 |
| 67  | CLUSTER      | Restreindre les nœuds qu'un client ou un proxy voit        | À faire — gros chantier                 |
| 168 | AGENT        | Cloisonner le service de l'agent (`ProtectSystem`…)         | À faire — à éprouver directive par directive |
| 111 | AGENT-UPDATE | Version attendue par groupe, et la vue « constaté vs attendu » | À faire — socle                      |
| 113 | AGENT-UPDATE | Clé `pkg_signing` et format du manifeste signé              | À faire                                 |
| 114 | AGENT-UPDATE | Dépôt Nexus en lecture anonyme, découvert par `04_15`       | À faire                                 |
| 115 | AGENT-UPDATE | Ordre de mise à jour : catégorie de trames `09`             | À faire                                 |
| 116 | AGENT-UPDATE | Basculement survivable et retour arrière automatique        | À faire — **cœur du lot**, après 112    |
| 117 | AGENT-UPDATE | Configuration système réconciliée avec la version           | À faire                                 |
| 118 | AGENT-UPDATE | Mise à jour du client Windows                               | À faire — après la mise en production   |
| 180 | SELINUX      | Confiner l'agent : règles des GPO, puis enforcing          | À faire — sur un poste, voir le 22      |
| 8   | LDAP         | Mode synchro avec un annuaire existant                     | Idée                                    |
| 40  | AGENT-UPDATE | Mettre à jour le parc de clients                           | Idée — à trancher                       |

---

## Réseau Ducky

### 176. [CLUSTER] Purger un proxy en maintenance de ses connexions

**Origine** (relevé en traitant le 147). La purge ne vise que les **cores** : ce
sont eux qui tiennent les sessions, dans leur mémoire. Un **proxy** en maintenance
sort bien de toutes les listes, mais les connexions qu'il relaie restent ouvertes
jusqu'à ce que les agents s'en aillent d'eux-mêmes — à leur prochaine 04_04, ou à
une coupure. `cluster purge <proxy>` est refusé en le disant.

**À concevoir.** Deux voies : un ordre au proxy (trame nouvelle, ou une révision
de relais pilotés qui ferme puis rouvre ses écoutes), ou une 04_17 poussée par
chaque core aux machines dont la session arrive **par** ce proxy. La seconde
réemploie la purge des cores ; elle demande de savoir, sur chaque core, quelles
sessions sont relayées par quel proxy — *à vérifier* : un relais Ducky transporte
sans lire, le core devrait voir l'adresse du proxy comme source TCP de la session
(`Session.RemoteAddr`), mais derrière une redirection ce n'est pas garanti.

### 177. [CLUSTER] Un core en maintenance accepte encore les connexions

**Origine** (relevé en traitant le 147). La maintenance retire un core des
**listes** ; elle ne l'empêche pas d'accepter une connexion. Un agent qui ne
connaît que son fichier de configuration (agent ancien, ou liste jamais reçue)
peut donc y revenir après une purge. C'est visible — le compteur SESSIONS de
`cluster show` remonte —, mais la purge ne l'empêche pas.

**À trancher.** Refuser les nouvelles connexions sur un core en maintenance
ferait partir ces agents vers le core suivant de leur fichier ; mais c'est aussi
ce qui coupe un parc dont tous les autres cores seraient tombés pendant la
maintenance. Un refus seulement tant qu'un autre core est **en ligne**, relu à
chaque connexion ? Et que faire des connexions des autres cores et des proxies ?

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

### 179. [WINDOWS] Écran vide : valider le correctif du 157 sur un poste

**Origine.** Le **157** a corrigé à l'aveugle l'écran de connexion vide de la
recette du 05/10 : la DLL fait désormais ce que fait l'exemple « V2 » de
Microsoft sur les trois points où elle s'en écartait — plus de tuile par défaut,
une image et un libellé de fournisseur, `ICredentialProviderSetUserArray`
acceptée (`DO/2.3/2.3.md`). Rien de cela n'a tourné dans un vrai LogonUI.

**À faire, sur le poste de la recette** (`A_TESTER.md`, § 80) :

1. Archive refaite depuis `dev`, réinstallée, témoin de trace posé. Si les tuiles
   reviennent — celles de Windows et « Autre utilisateur » avec Vaultaire dans
   ses options de connexion —, se connecter, et fermer ce point.
2. Sinon, rétablir les écarts **un par un** par les variantes d'essai
   (`TuileParDefaut`, `ModeV1`, `SansImage`, sous
   `HKLM\SOFTWARE\Vaultaire\CredentialProvider`) : celle qui ramène les tuiles
   nomme la cause. Aucune ne les ramène : les étapes 2 et 3 de l'ancien 157 —
   `Disabled` = 1 sous la clé du fournisseur pour savoir si c'est bien notre
   DLL, puis l'Observateur d'événements (`LogonUI.exe`, 1000 et 1002).
3. Une fois la cause établie : retirer les variantes devenues inutiles du code,
   et le dire dans `README.md` du client Windows.

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

### 168. [AGENT] Cloisonner le service de l'agent

**Origine.** Reste du **112**. L'unité de l'agent a maintenant une relance bornée
et un contrôle avant démarrage ; elle n'a toujours aucune des protections que
porte l'unité de Nexus (`ProtectSystem`, `ProtectHome`, `NoNewPrivileges`,
`RestrictAddressFamilies`…).

**Pourquoi ce n'est pas fait.** L'agent crée des comptes, écrit dans les
dossiers personnels et applique des politiques sur tout le système. Chaque
directive couperait un appliqueur de GPO — `ProtectHome` tout le scope
utilisateur, `ProtectSystem=strict` tout dépôt de fichier sous `/etc`,
`NoNewPrivileges` les transitions SELinux de l'agent vers `useradd_t` et
`setfiles_t` (TO-DO 22). Les poser sans les avoir
éprouvées casserait des postes pour une promesse non tenue.

**À faire.** Sur un vrai poste, une directive à la fois, la suite de GPO de la
formation rejouée après chacune. Garder celles qui ne coûtent rien
(`ProtectKernelTunables` est exclu d'office par le module `sysctl`,
`LockPersonality` ou `RestrictRealtime` ne le sont probablement pas), écrire
pourquoi les autres ne peuvent pas l'être. Le gabarit vit dans
`src/vaultaire_client/unite/unite.go` : c'est lui qu'on modifie, et
`vaultaire_client --install-unit` qui le pose.

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

### 171. [PAM] [CLIENT] Un mot de passe expiré se lit au journal du poste, pas à l'écran

**Origine.** Reste du **159**. Le core donne un motif précis à deux refus, et
seulement après un mot de passe **prouvé** : `password expired` et
`mfa required` (trame `03_03`). Depuis le 159 l'agent l'écrit dans son journal ;
la personne devant l'invite, elle, ne voit toujours qu'un refus ordinaire, retape
son mot de passe, puis appelle le support — exactement ce que le commentaire de
`CheckAuthentification.go` dit vouloir éviter.

**Ce qu'il faut trancher.** L'agent ne transmet aujourd'hui un texte au module
PAM que sur un **succès** (`Notice`, TO-DO 99), et c'est voulu : dire quoi que ce
soit après un mot de passe faux apprendrait qu'un compte existe. Ces deux
motifs-là ne tombent pas sous cette objection — qui les lit connaît déjà le mot
de passe du compte —, mais la règle « rien sur un refus » est simple, et
l'entamer demande de s'assurer que **seuls** ces deux motifs passent.

**À faire.** Une liste fermée de motifs affichables, côté agent ; le module PAM
les montre par la conversation PAM ; tout autre refus reste muet. Un test par motif, et
un test qui garde le silence sur `permission denied`.

### 172. [GPO] [CLUSTER] « Demander un cycle » n'atteint que les machines de ce core

**Constat** (relevé en traitant le **169**, **non vérifié** faute de cluster sur
le banc). `gpo.refresh` pousse la trame `05_18` par le registre des sessions du
core qui exécute l'action. Sur un cluster, une machine connectée à un **autre**
core y est inconnue : `vlt gpo refresh --all` ne la compte pas, et le bouton
« Demander un cycle » d'une GPO la range parmi les « hors ligne ou non
jointes ». Le bilan est donc juste — elle n'a pas été jointe — mais le motif
annoncé (« elles rafraîchiront à leur reconnexion ») ne l'est pas : elle est en
ligne, ailleurs.

Le rejeu des révocations (**49**) a le même découpage et le résout par la base
commune : chaque core sert ses machines. Rien d'équivalent n'existe pour une
demande de cycle, qui n'est écrite nulle part.

**À faire.** D'abord **vérifier** sur un cluster à deux cores. Si c'est
confirmé : soit le dire dans le bilan (« N machine(s) sont peut-être tenues par
un autre core »), soit faire porter la demande par la base — une ligne que le
core qui tient la machine relève, comme pour les relais d'un proxy (**141**).


---

## Annuaire LDAP

> Constats détaillés : [`Audit_LDAP_2026-09-28.md`](./Audit_LDAP_2026-09-28.md).
> Chaque entrée renvoie à la section qui porte le fichier, la ligne et le
> scénario.
>
> **Tous les points de l'audit sont traités dans la 2.2** : 119 à 132. Ce qui
> reste ici en est sorti en chemin.

---

### 175. [LDAP] Une recherche `base` rend un compte SANS groupe quand la base flanche

**Origine.** Relevé en traitant le **155**. Les recherches `one` et `sub`
**échouent** si la lecture des appartenances échoue : l'erreur remonte, le
client reçoit une erreur. La recherche `base` sur le DN d'un compte, elle,
journalise l'erreur et rend le compte **avec un `memberOf` vide**
(`memberOfForUser`, `scope/base_scope.go`).

Un client qui lit cette réponse y voit un compte qui a quitté tous ses groupes.
C'est le chemin qu'emprunte JumpServer après chaque authentification.

**À faire.** Faire remonter l'erreur de `memberOfForUser` jusqu'au
gestionnaire, qui répond `operationsError` — comme il le fait déjà quand la
résolution `sub` échoue. Un test avec une base qui refuse (le connecteur
défaillant de `handler_nilsession_test.go`).

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
