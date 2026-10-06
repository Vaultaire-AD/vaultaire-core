# TO-DO — Vaultaire

> **Ce fichier ne contient que ce qui reste à faire.** Une tâche terminée le quitte.

## Convention

Trois gestes, dans le même passage que le code :

1. **Supprimer** l'entrée d'ici et l'écrire dans `DO/<version en cours>/<version>.md`, avec ce qui a été fait, ce qui a été mesuré, et ce qui n'a pas été traité.
2. **Re-numéroter le reste** : une partie non traitée revient ici sous un numéro **neuf** — jamais l'ancien, qui se lirait comme une tâche entière non commencée.
3. **Consigner** le changement en haut de `docs/Version/<majeure>/<mineure>.md`.

`DO/` est l'archive, `Version/` le compte rendu, ce fichier la liste de courses.

**Numérotation.** Les numéros sont uniques et croissants : le prochain libre est **166**. Avant la 49, des numéros ont servi plusieurs fois (par exemple trois « 12 » dans `DO/2.1/2.1.md`) ; pour les citer sans ambiguïté, écrire la version et le titre : « 2.1 #12 — create permission ».

**Audit de sécurité du 25/09.** Les points 95 à 107 viennent d'une relecture du
code existant, pas d'une recette. Les constats **sérieux** (101 à 107) sont
détaillés dans [`Audit_securite_2026-09-25.md`](./Audit_securite_2026-09-25.md).
**Traités dans la 2.2** : 95 à 97, 99 à 108. **Reste ouvert** : 98 (secrets au
repos, à cadrer). Ce fichier porte :
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
aux points **119 à 131**. **Tous sont traités dans la 2.2**, 119 à 131, ainsi que
le **132**, relevé en traitant le 120 — le dernier constat de sécurité de
l'audit. Quatre points en sont sortis en les traitant : **150** (la suite
`--test`), **151** (les mots de passe de la formation), **152** (les bornes
LDAP ne se réglaient pas — **traité**) et **155** (`memberOf` dépend de la base
de recherche).

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
manque en silence) — **tous traités**, voir `DO/2.2/2.2.md`. Le sixième — récupérer l'identité d'une machine créée depuis
le portail — n'est pas neuf : c'est le **82**, dont la section « À faire » a été
complétée de ce que la recette a montré. Le Credential Provider reste en
attente : la DLL a été recompilée, l'essai n'a pas encore eu lieu.

**Recette du 05/10 (branche `hotfix`, poste Windows).** La tuile s'inscrit et se
charge, mais l'écran de connexion reste **vide** — aucune tuile, pas même celles
de Windows. Deux défauts trouvés en cherchant sont **traités** (**156**, voir
`DO/2.2/2.2.md`) : l'échange avec l'agent n'avait aucune échéance côté DLL, et le
journal ne disait pas où LogonUI s'arrêtait. La cause de l'écran vide, elle,
**n'est pas établie** : c'est le **157**.

**Recette du 03/10 (retours de Lorens sur `A_TESTER.md`).** Dix points ouverts,
**139 à 148** : Windows (**139** la DLL dépend de `libwinpthread-1.dll`, **140**
le fournisseur s'inscrit sous le CLSID `{` — **traités** le jour même, voir
`DO/2.2/2.2.md` ; le **149** en est la suite),
proxy (**141** la configuration des relais se pilote depuis le core —
**traité**, voir `DO/2.2/2.2.md` ; les **158** et **160** en sont la suite), GPO
(**142** cadence de la vérification utilisateur — **traité** —, **143** une ligne
par machine dans la page Conformité), comptes et LDAP (**144** créer un compte sans mot de
passe provisoire, **145** journal LDAP illisible en debug — **traité**, voir
`DO/2.2/2.2.md` ; les **153** et **154** en sont la suite) et cluster (**146**
retirer un nœud à la main, **147** maintenance et purge, **148** sessions
actives par core). Le retour sur le § 26 — une suppression ou une modification
dans un `HOME` n'est pas détectée — n'ouvre pas de point : c'est le **135**,
confirmé, et **traité** depuis.

**Banc du 06/10 (premier agent réel lancé contre un core).** En traitant les
133, 134, 135 et 142, trois défauts que la relecture n'avait pas montrés sont
sortis, **traités** dans le même lot (voir `DO/2.2/2.2.md`) : `kill -u <nom>`
ne verrouillait **aucun** compte local quand le nom était donné sans domaine
(dans le **133**), deux appliqueurs du scope utilisateur suivaient encore les
liens d'un dossier personnel (**162**), et l'agent gardait un masque de création
faux selon son démarrage (**165**). Deux points en restent : **163** (les
modules utilisateur sans vérificateur) et **164** (voir où en est un ordre de
révocation, machine par machine).

**Statut.** « FAIT-IA » veut dire *écrit*, pas *validé*. Tant qu'un point figure dans `docs/exploitation/A_TESTER.md`, il n'a pas été compilé ni exécuté sur une vraie machine.

---

## Vue d'ensemble

| #   | Domaine      | Sujet                                                      | État                                    |
| --- | ------------ | ---------------------------------------------------------- | --------------------------------------- |
| 98  | SÉCURITÉ     | Chiffrer les secrets au repos (clés privées, secrets TOTP)  | À faire — **critique**, à cadrer        |
| 158 | PROXY        | Un proxy démarré sans core n'ouvre aucun relais             | À faire — **la copie locale ne sert pas à froid** |
| 159 | DUCKY        | Un refus `02_07` à une ligne fait paniquer le poste         | À faire — petit, à lire avant de toucher |
| 160 | DOC          | « Pas de port sous 1024 en UID 10001 » : à vérifier         | À faire — petit, une commande           |
| 161 | RÉGLAGES     | Prévenir quand la cadence dépasse ce que tolère le parc     | À faire — petit, la version est en base |
| 146 | CLUSTER      | Retirer à la main un nœud hors ligne                        | À faire — petit                         |
| 147 | CLUSTER      | Maintenance et purge d'un nœud                              | À faire — après le 148                  |
| 148 | CLUSTER      | Sessions actives par core, en page et en commande           | À faire                                 |
| 155 | LDAP         | `memberOf` dépend de la base de recherche                   | À faire — un client synchronisé sur un sous-domaine perd des groupes |
| 150 | TESTS        | La suite `--test` échoue sur dix points                     | À faire — **un échec masque les autres** |
| 151 | DOC          | Les mots de passe d'exemple sont refusés par la politique   | À faire — petit, bloque la formation    |
| 144 | COMPTES      | Créer un compte de service sans mot de passe provisoire     | À faire — petit, l'action le sait déjà  |
| 153 | JOURNAL      | Dix-huit écritures directes sur la sortie standard          | À faire — petit                         |
| 154 | JOURNAL      | Le tampon mémoire est recopié à chaque ligne une fois plein | À faire — petit, **2,4 ms par ligne de journal** |
| 143 | GPO          | Page Conformité : une seule ligne par machine               | À faire — moins urgent                  |
| 163 | GPO          | Modules utilisateur encore sans vérificateur                | À faire — petit, un module à la fois    |
| 86  | GPO          | Le mode audit ne se distingue pas — à reproduire           | À faire — à préciser d'abord            |
| 164 | RÉVOCATION   | Voir, machine par machine, où en est un ordre               | À faire — la lecture existe, sans appelant |
| 157 | WINDOWS      | L'écran de connexion reste vide une fois la tuile inscrite  | **À faire — bloque la recette Windows** |
| 149 | WINDOWS      | Éprouver la DLL du fournisseur dans la fabrication (wine)   | À faire — petit                         |
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
| 49  | RÉVOCATION   | Retenter les révocations poussées en échec                 | À faire — l'agent le borne déjà à dix minutes |
| 8   | LDAP         | Mode synchro avec un annuaire existant                     | Idée                                    |
| 40  | AGENT-UPDATE | Mettre à jour le parc de clients                           | Idée — à trancher                       |

---

## Réseau Ducky

### 159. [DUCKY] Un refus `02_07` à une seule ligne fait paniquer le poste

**Constat** (relevé en traitant le 138). Le poste lit un refus d'authentification
ainsi (`userauth/UserAuthentificationManager.go`, `case "07"`) :

```go
lines := strings.Split(trames_content.Content, "\n")
logs.Write_log("WARNING", fmt.Sprintf("Authentification failed for user %s : %s", lines[0], lines[1]))
```

Il attend donc **deux** lignes de contenu : le compte, puis le motif. Or neuf
des onze `02_07` de `CheckAuthentification.go` n'en portent qu'**une** —
`Wrong login Data`, `Auth Failed please retry`, `You are not authentificate`,
`Password expired…`. `lines[1]` sort alors du tableau et le traitement de la
trame panique. La panique est récupérée par `handleConnection`
(`serveur_communication/GoroutineConnection.go`), qui **ferme la connexion et
retire la session**. Le journal du poste porte donc « Panic récupéré dans
handleConnection … index out of range » là où il devrait porter le motif du
refus — « mot de passe expiré » compris, que l'utilisateur ne lit nulle part.

Deuxième défaut au même endroit : le refus de la ligne 213 du même fichier
(`Something go wrong contact you administrator`) est composé **sans** la ligne
de destination `serveur_central`. Tous ses champs sont décalés d'un rang.

Le refus ajouté par le 138 (« trop de clés ») porte, lui, le compte et le
motif : il s'affiche correctement.

**Pourquoi ce n'est pas corrigé en passant.** La panique a un effet de bord :
c'est elle qui **ferme** la connexion d'un essai refusé. Écrire la ligne
proprement la laisserait ouverte. *À vérifier avant de toucher* : ce qui, dans
`vaultaire_client`, conclut à l'échec — la fermeture, ou un délai — et ce que
voit `sshd` dans chaque cas.

**À faire.** Côté poste, lire le motif sans supposer le nombre de lignes (une
ligne : c'est le motif, le compte est inconnu), puis fermer la session
**explicitement**. Côté core, donner à tous les
`02_07` la même forme — compte, motif — et réparer celui qui n'a pas de
destination. Un test par forme de trame, des deux côtés.

### 158. [PROXY] Un proxy démarré sans core joignable n'ouvre aucun relais

**Constat** (relevé en traitant le 141). L'ordre de `vaultaire_proxy/main.go` est :
`ducky.Start` — qui attend une session authentifiée, **trente secondes** au
plus — puis le raccordement au cluster, puis les relais. Sans core joignable,
`Start` rend une erreur et le proxy s'arrête (`aucune session authentifiée
après 30s`) **avant** d'avoir ouvert un seul port.

Ce n'est pas neuf, mais le 141 le rend plus visible : le proxy garde maintenant
sur disque la dernière liste de relais reçue du core (`relais_du_core.json`),
précisément pour repartir sans lui. À froid, cette copie n'est jamais lue. Un
site dont le proxy redémarre pendant une coupure du lien perd donc aussi ses
relais `https` vers des cibles **locales** (`source: liste`), qui n'ont pas
besoin du core pour fonctionner. En conteneur, la politique de redémarrage
relance le proxy toutes les trente secondes, sans effet.

Un proxy **déjà démarré** qui perd ses cores n'est pas concerné : il garde tous
ses relais ouverts — vérifié sur le banc.

**Ce qu'il faut trancher.** Le relais **Ducky** sans core n'a rien vers quoi
relayer : l'ouvrir donne des refus francs, ce qui est le comportement voulu
(l'agent passe au nœud suivant). Mais le proxy doit-il rester en vie sans
session, et pour combien de temps ? Aujourd'hui l'arrêt sert d'alarme.

**À faire.** Ouvrir les relais **avant** d'attendre la session — depuis la copie
locale, sinon depuis le fichier —, et faire de l'absence de session un état
journalisé et retenté plutôt qu'un arrêt. Le raccordement au cluster et le
compte rendu attendent la session, eux. Un test : proxy démarré sans core, un
relais `liste` relaie.

### 160. [DOC] [PROXY] « Pas de port sous 1024 en UID 10001 » : à vérifier

**Constat** (relevé en écrivant la documentation du 141). Trois pages affirment
que le conteneur `vlt-proxy`, parce qu'il tourne en UID 10001, ne peut pas
écouter sous 1024 : `docs/proxy/https-et-ldaps.md`,
`deployments/pre-prod/vlt-proxy/README.md` et `config.example.yaml`. C'est vrai
d'un processus non root sur un hôte. *À vérifier* dans un conteneur : depuis
Docker 20.10, l'espace réseau d'un conteneur reçoit par défaut
`net.ipv4.ip_unprivileged_port_start=0`, ce qui autorise justement les ports
bas à un utilisateur ordinaire. La règle ne tiendrait alors que hors conteneur,
en réseau `host`, ou sur un moteur plus ancien.

Sans conséquence sur le fonctionnement : un port refusé remonte « refusé » avec
son motif (141), un port accepté fonctionne. Seule la documentation dirait une
chose fausse — et ferait choisir 1636 là où 636 conviendrait.

**À faire.** Une commande sur la préprod :
`vlt cluster relais <proxy> set essai --type ldaps --ecoute :636`, lire l'état,
retirer le relais. Puis corriger les trois pages dans le sens constaté.

### 161. [RÉGLAGES] Prévenir quand `check_online_minutes` dépasse ce que tolère le parc

**Constat** (reste du 110). Depuis la 2.2, le core et les postes à jour suivent
la cadence du battement. Un agent **antérieur** garde son délai fixe : il ferme
son tunnel après dix minutes sans trafic. Régler `check_online_minutes` à 10 ou
plus le fait donc se reconnecter en boucle — le symptôme même que le 110 a
retiré pour les autres. Aujourd'hui seule la `Consequence` affichée du réglage
le dit ; rien ne l'empêche à la saisie.

Le core a pourtant ce qu'il faut : `id_logiciels.agent_version`, remontée par
`02_12`.

**À faire.** À `settings set check_online_minutes <n>` avec `n` ≥ 10 (et sur la
page des durées), compter les machines dont la version est antérieure à la 2.2,
ou inconnue. S'il y en a : le dire, les nommer (les cinq premières et le
compte), et demander une confirmation explicite — pas un refus, un parc peut
vouloir assumer. Même calcul dans `settings list`, en avertissement à côté de la
valeur. Partage sa lecture de version avec le **111**.

### 148. [CLUSTER] Les sessions actives d'un core, en page et en commande

**Demande de Lorens** (recette du 03/10). Voir le nombre de sessions actives sur
chaque core, dans la page Cluster et par une commande.

**Aujourd'hui.** Les proxies remontent leurs compteurs par relais ; un **core**
ne publie rien de tel. Ses sessions Ducky vivent dans son registre en mémoire
(`sessionmgr.Sessions`), que les autres cores ne voient pas — *à vérifier* : la
table `user_sessions` a pour clé (compte, machine), sans le core qui porte la
session.

**À faire.** Chaque core publie avec son battement le nombre de ses sessions —
au moins : tunnels machine, sessions utilisateur authentifiées, connexions en
cours de poignée de main — dans les métriques de nœud (`metriques_noeud.go`,
déjà là pour les proxies). Affichage dans la liste et la fiche de la page
Cluster, et dans `vlt cluster list` / une fiche `vlt cluster show <nœud>`.
Mesure **déclarative**, comme celles des proxies : elle s'affiche, elle n'ordonne
pas la liste servie aux agents.

**Préalable du 147** : on ne purge pas un nœud sans voir son compteur descendre.

### 147. [CLUSTER] Mettre un nœud en maintenance, et le purger de ses sessions

**Demande de Lorens** (recette du 03/10). Deux gestes distincts :

- **maintenance** — le nœud reste dans le cluster, mais il est retiré de la
  liste de tout le monde : plus personne ne doit l'utiliser ;
- **purge** — le nœud se vide de toutes ses sessions.

**Ce qui existe déjà.** `vlt cluster rotation <nœud> out` retire un nœud de la
liste servie aux agents (`expose_aux_agents`), et la page Cluster porte le même
réglage. C'est la moitié de la maintenance. Ce qui manque :

- les sessions **déjà ouvertes** sur le nœud y restent : sortir de la rotation
  n'en ferme aucune, et un agent ne redemande la liste qu'à son rythme
  (`cluster refresh` le force, à la main) ;
- *à vérifier* : que « out » retire bien le nœud de **toutes** les listes — la
  `04_04` des agents, celle que reçoivent les proxies, les cibles `source: cores`
  des relais LDAPS, la `04_16` pour un Nexus — et pas seulement de la première ;
- aucun état nommé « maintenance » : un nœud sorti de la rotation ne se
  distingue pas, dans la liste, d'un nœud qu'on a oublié d'y remettre.

**À faire.**

1. Un état **maintenance** explicite, visible dans la liste et la fiche, posé et
   levé par un bouton et par `vlt cluster maintenance <nœud> <on|off>`. Il
   implique la sortie de toutes les listes.
2. La **purge** : le nœud en maintenance ferme ses sessions pour que les agents
   se reconnectent ailleurs. À trancher : fermeture immédiate, ou échelonnée
   pour ne pas faire reconnecter tout un site dans la même seconde ; et le sort
   des sessions web d'administration ouvertes sur ce core — on ne doit pas se
   couper la branche depuis laquelle on purge.
3. **Garde-fou** : refuser de mettre en maintenance le **dernier** core en
   rotation, ou l'exiger avec une confirmation explicite. C'est la commande qui
   coupe le parc.
4. Le suivi : le compteur du **148** descend à zéro, et la fiche le dit.

### 146. [CLUSTER] Retirer à la main un nœud hors ligne

**Demande de Lorens** (recette du 03/10). Un bouton pour supprimer du cluster un
service hors ligne, sans attendre.

**Aujourd'hui.** Un nœud absent n'est oublié que par `CleanupStaleNodes`, au
terme de `cluster purge-delay` (24 h par défaut). Aucune action, ni en page ni
en commande, ne le retire avant. Un proxy de test démonté reste donc un jour
entier dans la liste.

**À faire.** Une action `cluster.forget` — bouton sur la fiche du nœud et
`vlt cluster forget <nœud>` — **réservée aux nœuds hors ligne** : retirer un
nœud vivant ne sert à rien, il se réinscrit au battement suivant s'il est un
core comme s'il est un proxy (depuis le **109**, traité : le core refuse son
battement et il se réenregistre au tour suivant). Refuser franchement un nœud
dont le dernier battement est récent. Retirer aussi ce que le core lui demandait
d'exposer — les lignes `cluster_relays` et `cluster_relay_state` de ce nœud
(141) restent sinon en base, sans effet mais sans fin. Ligne d'audit, et rappel
de ce qui part avec la ligne : ses réglages d'exposition, de priorité et
d'affinité (TO-DO 85 les fait survivre à l'absence, pas à l'oubli).

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

### 157. [WINDOWS] L'écran de connexion reste vide une fois la tuile inscrite

**Constat** (recette du 05/10, DLL compilée depuis `hotfix`). Après
Ctrl+Alt+Suppr, l'écran de connexion n'affiche **aucune tuile** — ni celle de
Vaultaire, ni celles de Windows. Seuls restent le bouton du réseau et celui de
l'accessibilité. Le Bureau à distance ne passe pas non plus. Le journal de la
DLL porte « fournisseur charge » et « scenario 1 accepte », rien d'autre ;
celui de l'agent ne porte rien.

**Ce qui est établi.**

- Ces deux lignes sont aussi celles d'une ouverture de session **réussie** : le
  journal d'avant le 156 ne distinguait pas un écran vide d'un écran sain. Elles
  ne disent donc rien de la cause.
- Rejouée sous wine par un faux LogonUI (toute la suite d'appels d'un
  fournisseur, scénarios 1 et 2), la DLL de `hotfix` rend un résultat correct à
  chaque méthode, agent arrêté comme agent en marche.
- Un seul cas reproduit le symptôme : un tube **présent** dont l'agent ne répond
  pas. `SetSelected` y restait bloquée sans limite. C'est corrigé (156) — mais
  rien ne prouve que ce soit le cas de la recette.
- L'en-tête MinGW des interfaces (ordre des méthodes, identifiants, énumérations,
  taille des structures) a été relu contre les définitions de Windows : il est
  juste. Le faux LogonUI et la DLL partagent cet en-tête ; une erreur commune
  aux deux n'aurait pas été vue autrement.

**À faire, dans l'ordre.** Chaque étape tranche une hypothèse.

1. Refaire l'archive depuis une branche qui porte le 156, réinstaller, poser le
   témoin `C:\ProgramData\Vaultaire\logs\credential_provider.trace`, refaire
   l'essai, lire `credential_provider.log` (`A_TESTER.md`, §48). Une entrée
   « > Méthode » sans sa sortie « < Méthode » nomme l'endroit. Une suite
   complète dit que la DLL a tout rendu, et que la panne est en aval.
2. Valeur `Disabled` = 1 (DWORD) sous la clé du fournisseur : si les tuiles de
   Windows reviennent, c'est bien notre DLL ; sinon, chercher ailleurs.
3. Observateur d'événements, journal Application, sources « Application Error »
   (1000) et « Application Hang » (1002) pour `LogonUI.exe` : le module fautif
   y est nommé.
4. Si la trace est complète et que l'écran reste vide : ce qui distingue notre
   tuile de l'exemple de Microsoft — elle se déclare tuile **par défaut**
   (`GetCredentialCount`), n'a **pas d'image** (`CPFT_TILE_IMAGE`), et le
   fournisseur n'implémente pas `ICredentialProviderSetUserArray`. À essayer un
   par un, sur le poste.

**Lié.** Le 149 : le faux LogonUI qui a servi ici est exactement l'essai que le
149 demande d'ajouter à la fabrication.

### 149. [WINDOWS] [TESTS] Éprouver la DLL du fournisseur dans la fabrication

**Constat** (relevé en traitant les 139 et 140). Les deux défauts — une
dépendance manquante, une inscription sous le mauvais CLSID — n'ont été vus qu'à
l'écran de connexion d'un vrai Windows Server, alors qu'un essai de vingt lignes
les montre tous les deux : `regsvr32` sous **wine**, lecture des clés créées,
puis un `CoCreateInstance` du CLSID. C'est ce qui a servi à les reproduire et à
valider le correctif, à la main.

Le contrôle des imports et celui des formats sont désormais dans `build-cp.sh` :
ils ferment ces deux défauts-là. Rien n'éprouve encore que la DLL **s'inscrit et
s'active**.

**À faire.** Un script `credential_provider/essai-wine.sh`, lancé par `build.sh`
quand `wine` est présent (et sauté, en le disant, quand il ne l'est pas) :
inscription, GUID attendu sous les deux clés, activation par COM, retrait, plus
rien dans le registre. À brancher dans `tests.yaml` si l'image de CI peut porter
wine. Ce n'est pas LogonUI — la tuile elle-même reste une recette manuelle.

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

### 143. [GPO] [WEB] Page Conformité : une seule ligne par machine

**Constat** (recette du 03/10, moins urgent). La page Conformité liste une ligne
par **couple** (machine, scope) : le scope machine, puis une ligne par
utilisateur passé sur le poste. Toutes ouvrent pourtant la **même** page de
détail, qui montre déjà tous les scopes de la machine.

**À faire.** Une ligne par machine, portant l'état du scope **machine**. Les
scopes utilisateur vont dans la page de détail — et remontent dans la liste
**seulement en cas d'écart** : une machine dont un `HOME` a dérivé ne doit pas
s'afficher conforme parce que son scope machine l'est. Le résumé du parc
(`ResumerParc`) et le tri (`TrierConformite`) comptent aujourd'hui des lignes :
les faire compter des machines, sans perdre « le pire état l'emporte ».
`vlt gpo status` doit suivre la même règle (invariant § 6.1).

**Depuis le 135**, la ligne d'un compte porte un vrai état — `ok (N)`, ou des
écarts — au lieu de rester « non vérifié » : la règle « remonte seulement en cas
d'écart » a maintenant de quoi se nourrir. `ResumerParc` compte déjà des
machines, y compris pour « une portée jamais vérifiée ».

### 163. [GPO] [CLIENT] Les modules utilisateur encore sans vérificateur

**Origine.** Reste du **135**. Le scope utilisateur est inventorié, mais trois
modules n'y laissent rien que le scan sache relire. Un compte qui ne reçoit
qu'eux reste « non vérifié » — silence, et non fausse conformité.

| Module | Ce qui manque |
|---|---|
| `user_git_config` | un vérificateur de la clé. Le fichier est à la personne : pas de hachage. Relire `~/.gitconfig` par `lireFichierUtilisateur`, le copier hors du dossier, `git config --file <copie> --get <clé>` — jamais `git` sous le `HOME` (voir 162) |
| `user_password_policy` | relire `chage -l <compte>` ; `force_change` ne se vérifie pas (il se consomme à la connexion) |
| `user_cron` | les deux unités sont inventoriées ; l'**activation** du timer ne l'est pas (`systemctl --user is-enabled` demande le bus de la personne, absent hors session) |

**Deux lectures par chemin restent**, sans rien écrire :

- le scan des **fichiers** d'un `HOME` (`scanFromState`) refuse le lien posé à la
  place du fichier, mais traverse un répertoire intermédiaire devenu lien : root
  hache alors un autre fichier. Le hachage ne sort pas de la machine. Le passer
  par la descente sûre demande de résoudre le `HOME` et l'uid dans le scan ;
- le vérificateur d'ACL (`verifierACL`) appelle `getfacl <chemin>`. Même
  remède que l'appliqueur : `designerSousHome`, puis `/proc/<pid>/fd/<n>`.

**À faire.** Un module à la fois, chacun avec son test qui part du vrai
appliqueur — c'est la règle du paquet : une vérification approximative est pire
qu'aucune.

### 86. [GPO] Le mode audit ne se distingue pas d'enforce, et une GPO modifiée ne semble pas repartir

> **Banc du 06/10.** En scope **utilisateur**, avec un agent réel, `audit` se
> distingue bien : fichier supprimé, reconnexion, `gpo status` affiche
> « 1 écart(s) », le journal de l'agent dit « mode audit, 1 module(s) en ecart
> signale(s) sans correction », et le fichier n'est pas reposé. Avant le **135**
> il ne pouvait rien montrer dans ce scope — aucun écart n'y était jamais vu —,
> ce qui est peut-être tout le premier symptôme. Le scope **machine** n'a pas
> été rejoué.

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

### 22. [EN COURS] [SELINUX] Politique pour les clients

**Contexte.** Le module NSS lit désormais un fichier et ouvre un socket. Sous `sshd_t`, SELinux refuse : d'où « Invalid user » sans aucun journal Vaultaire, alors que `getent` lancé à la main réussit. Détails : `docs/exploitation/selinux.md`.

**Fait.** `deployments/selinux/` : `collect.sh`, `vaultaire.te`, `vaultaire.fc`, `install.sh`.

**Reste à faire.** Un domaine dédié pour l'agent — il tourne aujourd'hui en `unconfined_service_t`.

### 49. [RÉVOCATION] Retenter les révocations poussées en échec

**Origine.** Reste noté dans `DO/2.0/2.0.md` (kill switch) et jamais reporté ici.

**Constat.** La révocation poussée ne touche que les machines connectées au moment du déclenchement. Une machine absente récupère ses ordres en attente à sa reconnexion (`revocation_manager/trames.go`), mais une machine **connectée dont le push a échoué** attend elle aussi la reconnexion suivante, qui peut ne jamais venir tant que le tunnel tient.

**À faire.** Une tâche de fond côté core qui renvoie périodiquement les ordres en attente aux clients connectés.

**Borné par le point 134 (06/10).** Un agent à jour redemande ses ordres en
attente à chaque tunnel rétabli **et toutes les dix minutes** : un ordre poussé
en vain, ou appliqué en échec, est donc rejoué dans les dix minutes sans rien
demander au core. Ce point reste ouvert pour ramener ce délai à quelques
secondes, et pour les agents antérieurs, qui ne redemandent qu'à leur démarrage.

### 164. [RÉVOCATION] Voir, machine par machine, où en est un ordre

**Origine.** Reste du **133**. Le compte rendu de `kill -u` dit combien de
machines ont **reçu** l'ordre. Ce qu'elles en ont fait — acquitté, en échec parce
que des processus survivent, toujours en attente — ne se lit que dans le journal
du core (`revocation: ordre 12 acquitté par <machine> (applied)`).

Or depuis le 133 un ordre peut **échouer** sur une machine, et c'est précisément
l'information qu'on cherche pendant un incident : « où ce compte travaille-t-il
encore ? ».

**Ce qui existe.** `dbrevocation.TargetsOf` lit l'état de chaque cible d'un
ordre — et n'a **aucun appelant**. La table `user_revocation_target` porte le
statut, la date de la dernière tentative et le détail.

**À faire.** Une action au registre (lecture, clé à choisir : `write:killswitch`
couvre déjà qui a le droit de déclencher), exposée en commande — par exemple
`vlt kill -u <compte> --status` — **et** sur la fiche du compte du portail, sous
l'historique des ordres qui s'y trouve déjà. Colonnes : machine, statut, dernière
tentative, détail. Mettre devant ce qui n'est pas acquitté.

**Déjà corrigé par le point 89 (24/09).** Une partie des « push en échec sur une machine connectée » ne venait pas du réseau : la session était choisie au hasard parmi celles qui portaient l'identifiant de la machine — poignée de main, session d'un utilisateur. `pushToOnline` passe désormais par `sessionmgr.SessionsMachine`. Reste le vrai sujet de ce point : rejouer un ordre dont l'envoi a réellement échoué.

---

## Annuaire LDAP

> Constats détaillés : [`Audit_LDAP_2026-09-28.md`](./Audit_LDAP_2026-09-28.md).
> Chaque entrée renvoie à la section qui porte le fichier, la ligne et le
> scénario.
>
> **Tous les points de l'audit sont traités dans la 2.2** : 119 à 132. Ce qui
> reste ici en est sorti en chemin.

### 155. [LDAP] `memberOf` dépend de la base de recherche

**Constat** (relevé en traitant le 132, mesuré sur un core lancé). Le même
compte, lu par le même compte de service, ne porte pas le même `memberOf` selon
la base de la recherche :

| Recherche | `memberOf` d'alice |
|---|---|
| `sub` sur `dc=acme,dc=lan` | `Equipe`, `Dev`, `Secrets` |
| `sub` sur `dc=dev,dc=acme,dc=lan` | `Dev`, `Secrets` — **`Equipe` manque** |
| `base` sur le DN d'alice | `Equipe`, `Dev`, `Secrets` |

**Pourquoi.** `loadGroupsAndUsers` (`scope/resolver.go`) compose `memberOf` à
partir des groupes qu'il vient de **charger**, c'est-à-dire ceux du domaine
demandé et de ses sous-domaines. Les groupes du compte qui vivent **au-dessus**
ou **à côté** de la base n'y sont pas. La recherche `base`, elle, passe par
`memberOfForUser`, qui lit tous les groupes du compte.

Ce n'est pas une fuite — il manque des valeurs, il n'en sort pas de trop, et le
132 filtre de la même façon sur les deux chemins. C'est une réponse **fausse par
omission** : une application synchronisée sur un sous-domaine croit qu'un compte
a quitté un groupe du domaine parent, et peut lui retirer les droits qui vont
avec.

**À faire.** Composer `memberOf` de la même façon sur les deux chemins : lire les
appartenances de tous les comptes rendus en **une** requête — le pendant, en lot,
de `GetMemberOfByUsername` —, puis laisser `Restreinte` retirer ce que
l'appelant ne peut pas lire. Le lot 131 a montré comment faire sans requête par
compte. À éprouver par les trois recherches du tableau, qui doivent rendre la
même chose.

---

### 144. [COMPTES] [LDAP] Créer un compte de service sans mot de passe provisoire

**Constat** (recette du 03/10). Tout compte créé naît avec un mot de passe
**provisoire**, valable 24 heures (TO-DO 99). C'est le bon défaut pour une
personne. Pour un compte de service — celui qu'on donne à Keycloak ou à GitLab
pour se lier à l'annuaire — c'est une panne programmée : le lendemain, le bind
est refusé, et personne n'est là pour « changer le mot de passe à la première
connexion ».

**Ce que le code fait.** La dérogation existe déjà dans l'action : `user.create`
lit le paramètre `temporary` et ne pose pas le drapeau s'il vaut `non`
(`core/action/actions_users.go`). Mais **rien ne le transmet** — ni `create -u`
en ligne de commande, ni le formulaire du portail. Elle est donc inatteignable.
Et la réinitialisation par un tiers (`update -u … -p`) marque **toujours**
provisoire, sans dérogation : renouveler le secret d'un compte de service le
recasse.

**À faire.**

1. Une option sur `create -u` (`--service`, ou `--permanent`) et sur
   `update -u -p`, qui passe `temporary=non`.
2. Le même choix dans le formulaire du portail — un `<select>` à deux valeurs,
   pas une case à cocher (piège § 6.4) — avec le défaut sur **provisoire**.
3. Le défaut ne bouge pas : l'absence du champ doit continuer de produire un
   compte provisoire. Une ligne d'audit dit qu'un compte a été créé **sans**
   provisoire, et par qui : c'est une dérogation de sécurité.
4. Mettre à jour le jalon 8.1 de la formation (« Un compte de service LDAP ») et
   `MAN.md` § 5 : ce sont eux qui font créer le compte qui cassera le lendemain.

### 150. [TESTS] La suite `--test` échoue sur dix points

**Constat** (relevé en traitant les 128 à 130). `vaultaire_serveur --test` rend
**306 sur 316**. Les dix échecs existaient avant ce lot — même liste sur le
commit précédent, 304 sur 314 — et aucun ne touche LDAP. Mais une suite qui
échoue « comme d'habitude » ne signale plus rien : le prochain vrai défaut s'y
perdra.

Les dix, en trois familles :

- **un ordre d'initialisation** — `Filtrage.LExecuteurApplique` : « catalogue
  d'actions vide : `action.EnregistrerTout()` n'a pas été appelé ». `main()`
  lance `testrunner.RunFromMain()` **avant** `EnregistrerTout()`. Il est
  probable que plusieurs des échecs RBAC et GPO ci-dessous en découlent, ou au
  contraire qu'ils soient masqués par lui : à vérifier en premier ;
- **des invariants RBAC et GPO** — `RBAC.RefusHorsDomaine` (`client.list`),
  `RBAC.LectureVoitSonPerimetre`, `RBAC.AucuneEcritureNeSeContenteDUnDomaine`,
  `GPO.CleSpecifiqueAuxGPO` et `GPO.LectureResteDeleguee`
  (`gpo.get_signature_policy`, contrôlée par `read:log`), `GPO.EcrituresStrictes`
  et `GPO.PorteeNonExtensible` (`gpo.refresh`), `Filtrage.ChaqueFiltreEstEprouve`.
  Le README de `how it work` § 6.2 en annonce un comme « défaut connu » ; les
  autres ne sont écrits nulle part ;
- **un chemin** — `Empreinte/nom partagé (agent)` lit un fichier du module
  `vaultaire_client` par un chemin relatif : il échoue dès que le binaire n'est
  pas lancé depuis l'endroit attendu.

**À faire.** Appeler `EnregistrerTout()` avant la suite, relancer, et trier ce
qui reste : chaque échec est soit un défaut à corriger — et alors c'est une
entrée de sécurité, `gpo.refresh` qui se contente d'un domaine en est une —,
soit un test à corriger. Puis brancher `--test` dans `tests.yaml` : aujourd'hui
rien ne lance cette suite, c'est pour cela qu'elle a dérivé.

### 151. [DOC] Les mots de passe d'exemple de la formation sont refusés

**Constat** (relevé en montant une pile d'essai pour le 130). Trois commandes
données en exemple échouent telles quelles, sur la politique de mots de passe :

| Où | Commande | Refus |
|---|---|---|
| `README.md`, démarrage rapide | `create -u alice.martin … 'Ch4ngeMe!'` | 9 caractères, il en faut 12 |
| formation, jalon 2.2 | `'Alice-2026!'`, `'David-2026!'` | 11 caractères |
| formation, jalon 8.1 | `create -u svc_keycloak … 'Svc-Keycloak-2026!'` | « il contient keycloak, trop prévisible » |

Le premier geste de la formation échoue donc, et le lecteur ne sait pas si c'est
lui ou le produit.

**À faire.** Remplacer les exemples par des mots de passe que la politique
accepte, et les **éprouver** : un test qui extrait les `create -u` de `README.md`
et de `docs/training/` et les passe à la politique, pour que le prochain
durcissement ne recasse pas la formation en silence. À traiter avec le **144** :
le jalon 8.1 crée justement le compte de service qui cassera le lendemain.

### 153. [JOURNAL] Dix-huit écritures directes sur la sortie standard

**Constat** (relevé en traitant le 145). Le serveur écrit encore sur la sortie
standard **hors du journal** : dix-huit `fmt.Print…` dans dix fichiers, sans
compter les commandes — dont c'est le rôle — ni la rotation des journaux, qui ne
peut pas se journaliser elle-même.

| Fichier | Lignes | Ce qu'elles écrivent |
|---|---:|---|
| `core/global/security/keymanagement/GenerateKeyPair.go` | 5 | création de paire de clés, y compris ses erreurs |
| `ducky-network/new_client/AUTO_ADD_client.go/send_file_to_client.go` | 3 | « 📦 Envoi du fichier avec SCP… » |
| `ducky-network/new_client/AUTO_ADD_client.go/execute_list_of_command_on_client.go` | 3 | détection de l'OS d'un poste |
| `core/dns/DNS_Database/` (`DNS_CHECK_Domain`, `DNS_DELETE_Reccord`, `DNS_ADD_EntryToZone`) | 3 | **des erreurs** : « ❌ Erreur lors de la vérification du domaine » |
| `core/database/db_permission/add_user_permission_to_group.go`, `add_permission_to_software_group.go` | 2 | « ✅ La permission … a été ajoutée » |
| `core/global/security/generateCert.go` | 1 | certificat déjà présent |
| `ducky-network/authentification/client/GenerateChallenge.go` | 1 | **une erreur** brute : `fmt.Println(err)` |

Ces lignes n'ont ni horodatage ni niveau, ne partent pas dans le journal commun
des cores, et ne s'éteignent pas. Plusieurs sont des **erreurs** — les trois du
DNS, celle du défi d'authentification, deux de la création de clés : elles ne
figurent donc dans aucun journal consultable, ni `vlt logs` ni la page Logs.

Le 145 en a retiré une dix-neuvième, qui était la pire :
`GetGroupsDirectlyUnderDomainExact` écrivait « DEBUG: checking… » une fois **par
groupe de l'annuaire**, à chaque recherche LDAP de portée `one`.

**À faire.** Chacune devient une ligne de journal au niveau qui convient —
`ERROR` pour les erreurs, `INFO` ou `DEBUG` pour le reste — ou disparaît.
Puis un test de sentinelle : aucun `fmt.Print` hors de `core/command`,
`core/testrunner`, `core/logs/rotation.go` et `main`.

### 154. [JOURNAL] Le tampon mémoire est recopié à chaque ligne une fois plein

**Constat** (relevé en traitant le 145, en mesurant l'ancien journal LDAP).
`LogBuffer.addEntry` (`core/logs/rfc5424.go`) garde les 10 000 dernières lignes
pour le repli de `vlt logs` quand la base ne répond pas. Une fois ce nombre
atteint, **chaque** ligne ajoutée alloue une tranche neuve et y recopie les
10 000 entrées :

```go
if len(b.entries) > b.maxSize {
	keep := b.entries[len(b.entries)-b.maxSize:]
	b.entries = make([]LogEntry, len(keep), b.maxSize)
	copy(b.entries, keep)
}
```

Sous le verrou du tampon, donc en série pour toutes les goroutines qui
journalisent.

**Mesuré** (sortie standard vers `/dev/null`, pour ne compter que le tampon) :

| | Par ligne de journal |
|---|---:|
| tampon pas encore plein | **1,6 µs** |
| tampon plein | **2,4 ms** — mille cinq cents fois plus |

Le tampon se remplit une fois pour toutes : un core qui a écrit dix mille lignes
depuis son démarrage paie ensuite 2,4 ms **à chaque ligne**, `INFO` comprises.
Un bind LDAP réussi en écrit deux. Le core entier ne peut donc pas journaliser
plus de quatre cents lignes par seconde environ, et tout ce qui journalise
attend son tour.

C'est aussi ce qui faisait durer plus de deux minutes, en mode debug, une
conversation LDAP de trois recherches. Le 145 a retiré la cause du volume, pas
ce coût.

**À faire.** Un tampon circulaire : un tableau fixe et un indice d'écriture,
sans allocation ni recopie. `recentes()` le déroule à la lecture. Un test de
performance simple suffit à le garder : dix mille lignes au-delà du plein ne
doivent pas coûter dix mille recopies.

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
