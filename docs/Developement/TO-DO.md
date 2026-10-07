# TO-DO — Vaultaire

> **Ce fichier ne contient que ce qui reste à faire.** Une tâche terminée le quitte.

## Convention

Trois gestes, dans le même passage que le code :

1. **Supprimer** l'entrée d'ici et l'écrire dans `DO/<version en cours>/<version>.md`, avec ce qui a été fait, ce qui a été mesuré, et ce qui n'a pas été traité.
2. **Re-numéroter le reste** : une partie non traitée revient ici sous un numéro **neuf** — jamais l'ancien, qui se lirait comme une tâche entière non commencée.
3. **Consigner** le changement en haut de `docs/Version/<majeure>/<mineure>.md`.

`DO/` est l'archive, `Version/` le compte rendu, ce fichier la liste de courses.

**Numérotation.** Les numéros sont uniques et croissants : le prochain libre est **176**. Avant la 49, des numéros ont servi plusieurs fois (par exemple trois « 12 » dans `DO/2.1/2.1.md`) ; pour les citer sans ambiguïté, écrire la version et le titre : « 2.1 #12 — create permission ».

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
**traité**, voir `DO/2.2/2.2.md` ; le **158**, **traité** en 2.3, et le **160** en sont la suite), GPO
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

**Banc du 07/10 (points 49, 86, 112, 143 et 163).** Tous traités, voir
`DO/2.3/2.3.md`. Le **86** demandait d'abord de reproduire : le premier
symptôme (« audit ne se distingue pas d'enforce ») est **établi et corrigé** —
en portée machine, un écart corrigé restait affiché une cadence entière, comme
un écart en audit ; le second (« une GPO modifiée ne repart pas ») **n'est pas
reproduit**, et ce qui y ressemble est désormais dit par les actions. Un défaut
que personne n'avait relevé est sorti en chemin et **traité** dans le même lot :
une machine dont la politique ne change pas passait « en retard » pour toujours
(**166**). Trois points en restent : **167** (le client Windows n'acquitte aucun
ordre, et le core le relance sans fin), **168** (cloisonner le service de
l'agent) et **169** (demander un cycle depuis le portail).

**Banc du 07/10, second lot (points 158, 159, 164 et 169).** Tous traités, voir
`DO/2.3/2.3.md`. Le **159** demandait de lire avant de toucher : la panique
fermait bien la session refusée, et rien d'autre ne le faisait — la fermeture
est maintenant décidée, des deux côtés. Deux choses que sa description ne
disait pas sont sorties : un agent refusé revenait toutes les **deux secondes**,
sans fin (le délai de reprise repartait de zéro à chaque connexion) ; et le
`02_07` n'est **pas** sur le chemin d'une personne qui se connecte — PAM passe
par `03_01` —, c'est le tunnel de la machine qui le reçoit. Le motif d'un refus
`03_03`, lui, n'était écrit nulle part sur le poste. Un défaut du portail est
sorti en ouvrant enfin les pages dans un navigateur, et il est **traité** dans
le même lot (**170**) : les étiquettes d'état n'avaient aucune règle de style,
« non vérifié » ne ressortait donc pas. Deux points en restent : **171** (le
motif d'un refus ne va pas jusqu'à l'écran de la personne) et **172** (demander
un cycle n'atteint que les machines connectées à ce core). Le **167** est
élargi : un proxy ou un Nexus rangé dans un groupe avec des comptes est visé par
les ordres de révocation, et ne les acquitte pas plus qu'un poste Windows.

**Banc du 07/10, troisième lot (points 71, 150, 154 et 155).** Tous traités,
voir `DO/2.3/2.3.md`. Le **150** supposait un ordre d'initialisation : ce n'en
était pas un. Des dix échecs de `--test`, **un** était un défaut — deux
écritures qui se contentaient d'un domaine (`gpo.refresh`,
`cluster.refresh_nodes`), rendues strictes —, deux étaient des filtres jamais
éprouvés, et sept décrivaient un registre d'avant `PorteeOuverte`. La suite est
désormais jouée par `go test`. Trois points en restent : **173** (les modules
natifs sont compilés une fois pour toutes les distributions), **174** (donner à
`rocky.sh` les précautions de `debian.sh`) et **175** (une recherche `base`
rend un compte sans groupe quand la base flanche).

**Statut.** « FAIT-IA » veut dire *écrit*, pas *validé*. Tant qu'un point figure dans `docs/exploitation/A_TESTER.md`, il n'a pas été compilé ni exécuté sur une vraie machine.

---

## Vue d'ensemble

| #   | Domaine      | Sujet                                                      | État                                    |
| --- | ------------ | ---------------------------------------------------------- | --------------------------------------- |
| 98  | SÉCURITÉ     | Chiffrer les secrets au repos (clés privées, secrets TOTP)  | À faire — **critique**, à cadrer        |
| 160 | DOC          | « Pas de port sous 1024 en UID 10001 » : à vérifier         | À faire — petit, une commande           |
| 161 | RÉGLAGES     | Prévenir quand la cadence dépasse ce que tolère le parc     | À faire — petit, la version est en base |
| 146 | CLUSTER      | Retirer à la main un nœud hors ligne                        | À faire — petit                         |
| 147 | CLUSTER      | Maintenance et purge d'un nœud                              | À faire — après le 148                  |
| 148 | CLUSTER      | Sessions actives par core, en page et en commande           | À faire                                 |
| 151 | DOC          | Les mots de passe d'exemple sont refusés par la politique   | À faire — petit, bloque la formation    |
| 175 | LDAP         | Une recherche `base` rend un compte SANS groupe quand la base flanche | À faire — petit, la recherche `sub` échoue déjà |
| 144 | COMPTES      | Créer un compte de service sans mot de passe provisoire     | À faire — petit, l'action le sait déjà  |
| 153 | JOURNAL      | Dix-huit écritures directes sur la sortie standard          | À faire — petit                         |
| 167 | RÉVOCATION   | Windows et les services n'acquittent aucun ordre : rejeu sans fin | À faire — petit, lié au 79         |
| 171 | PAM          | Un mot de passe expiré se lit au journal du poste, pas à l'écran | À faire — petit, à trancher         |
| 172 | GPO          | « Demander un cycle » n'atteint que les machines de ce core | À faire — à vérifier sur un cluster     |
| 157 | WINDOWS      | L'écran de connexion reste vide une fois la tuile inscrite  | **À faire — bloque la recette Windows** |
| 149 | WINDOWS      | Éprouver la DLL du fournisseur dans la fabrication (wine)   | À faire — petit                         |
| 79  | WINDOWS      | GPO et révocations sur les postes Windows                  | À faire — gros chantier                 |
| 67  | CLUSTER      | Restreindre les nœuds qu'un client ou un proxy voit        | À faire — gros chantier                 |
| 173 | AGENT        | Les modules natifs sont compilés une fois, pour toutes les distributions | À faire — **debian.sh le détecte, rien ne le résout** |
| 174 | AGENT        | `rocky.sh` : éprouver les modules et `sshd_config` avant PAM | À faire — petit, `debian.sh` le fait |
| 168 | AGENT        | Cloisonner le service de l'agent (`ProtectSystem`…)         | À faire — à éprouver directive par directive |
| 111 | AGENT-UPDATE | Version attendue par groupe, et la vue « constaté vs attendu » | À faire — socle                      |
| 113 | AGENT-UPDATE | Clé `pkg_signing` et format du manifeste signé              | À faire                                 |
| 114 | AGENT-UPDATE | Dépôt Nexus en lecture anonyme, découvert par `04_15`       | À faire                                 |
| 115 | AGENT-UPDATE | Ordre de mise à jour : catégorie de trames `09`             | À faire                                 |
| 116 | AGENT-UPDATE | Basculement survivable et retour arrière automatique        | À faire — **cœur du lot**, après 112    |
| 117 | AGENT-UPDATE | Configuration système réconciliée avec la version           | À faire                                 |
| 118 | AGENT-UPDATE | Mise à jour du client Windows                               | À faire — après la mise en production   |
| 22  | SELINUX      | Domaine dédié pour l'agent                                 | En cours                                |
| 8   | LDAP         | Mode synchro avec un annuaire existant                     | Idée                                    |
| 40  | AGENT-UPDATE | Mettre à jour le parc de clients                           | Idée — à trancher                       |

---

## Réseau Ducky

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

### 173. [AGENT] [CLIENT] Les modules natifs sont compilés une fois, pour toutes les distributions

**Origine.** Relevé en traitant le **71**. Les trois modules PAM et la
bibliothèque NSS que le core envoie à un poste sont ceux de
`/opt/vaultaire/vaultaire_client/` : compilés une fois, là où le core a été
fabriqué. Un module compilé contre une glibc plus récente que celle du poste ne
s'y charge pas — et derrière une ligne `default=die`, un module PAM qui ne se
charge pas refuse **tout le monde**, `root` et les comptes locaux compris
(mesuré le 07/10 sur Ubuntu 24.04 : « Module is unknown »).

`debian.sh` le **détecte** (`ldd`, avant de toucher à PAM) et s'arrête. Rien ne
le **résout** : sur un poste plus ancien que la machine de fabrication,
l'installation est refusée, proprement, et c'est tout.

Au passage : `pam_module/auto_compil.sh` lie les modules à `libcurl`
(`-lcurl`), qu'aucun d'eux n'appelle. C'est une dépendance à installer pour
rien sur chaque poste.

**À faire.** Décider où les modules sont fabriqués — une image par famille
(RHEL 9, Debian 12) dans la CI, la plus ancienne glibc prise en charge faisant
foi — et les ranger par famille dans ce que le core envoie
(`vaultaire_client/rocky/`, `vaultaire_client/debian/`). Retirer `-lcurl`. C'est
aussi un préalable du lot « Mise à jour du parc » (**116**, **117**), qui devra
remplacer ces modules sur des postes en service.

### 174. [AGENT] `rocky.sh` : éprouver les modules et `sshd_config` avant PAM

**Origine.** Reste du **71**. `debian.sh` prend deux précautions que `rocky.sh`
n'a pas : il vérifie par `ldd` que les modules natifs se chargent **avant** de
brancher PAM, et il valide `sshd_config` par `sshd -t` avant de le garder (en
le remettant comme il était sinon). `rocky.sh` réécrit les trois piles et
recharge `sshd` sans avoir vérifié ni l'un ni l'autre.

Il réécrit aussi les piles **en entier** : ce qu'un administrateur ou
`authselect` y avait mis disparaît, sans copie.

**À faire.** Reprendre dans `rocky.sh` l'étape 3 de `debian.sh` (chargement des
modules) et la validation de `sshd_config` ; garder une copie
`.avant-vaultaire` des trois piles avant de les écrire. L'essai à blanc
(`VAULTAIRE_RACINE`) permettrait de le garder par les mêmes tests. À faire sur
un Rocky, pas à l'aveugle.

### 168. [AGENT] Cloisonner le service de l'agent

**Origine.** Reste du **112**. L'unité de l'agent a maintenant une relance bornée
et un contrôle avant démarrage ; elle n'a toujours aucune des protections que
porte l'unité de Nexus (`ProtectSystem`, `ProtectHome`, `NoNewPrivileges`,
`RestrictAddressFamilies`…).

**Pourquoi ce n'est pas fait.** L'agent crée des comptes, écrit dans les
dossiers personnels et applique des politiques sur tout le système. Chaque
directive couperait un appliqueur de GPO — `ProtectHome` tout le scope
utilisateur, `ProtectSystem=strict` tout dépôt de fichier sous `/etc`,
`NoNewPrivileges` une transition SELinux (TO-DO 22). Les poser sans les avoir
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

### 22. [EN COURS] [SELINUX] Politique pour les clients

**Contexte.** Le module NSS lit désormais un fichier et ouvre un socket. Sous `sshd_t`, SELinux refuse : d'où « Invalid user » sans aucun journal Vaultaire, alors que `getent` lancé à la main réussit. Détails : `docs/exploitation/selinux.md`.

**Fait.** `deployments/selinux/` : `collect.sh`, `vaultaire.te`, `vaultaire.fc`, `install.sh`.

**Reste à faire.** Un domaine dédié pour l'agent — il tourne aujourd'hui en `unconfined_service_t`.

### 167. [RÉVOCATION] [WINDOWS] Windows et les services n'acquittent aucun ordre

**Origine.** Conséquence du **49**. Le client Windows V1 reçoit les trames `06`
et les journalise **sans les appliquer** ni les acquitter (c'est le **79**). Le
core, qui rejoue désormais ce qui n'est pas acquitté, lui remet donc ses ordres
toutes les cinq minutes, pour toujours. C'est exact — le compte n'est **pas**
coupé sur ce poste, et le journal le dit en toutes lettres au cinquième essai —
mais c'est du bruit sans remède tant que le 79 n'est pas fait.

**Élargi le 07/10 (banc du 164).** Ce n'est pas propre à Windows. Les cibles
d'un ordre sont « les machines qui partagent un groupe avec le compte »
(`MachinesSharingGroupWith`), **quel que soit leur type** : un proxy ou un Nexus
rangé dans un groupe où se trouvent des comptes est visé, reçoit la `06_05`, n'a
aucun gestionnaire pour elle (`trames: catégorie 06 reçue sans gestionnaire
branché`) et reste « en attente » indéfiniment. `kill -u <compte> --status` le
montre maintenant — « remis N fois, aucune réponse de la machine » —, ce qui le
rend visible sans le régler.

**À faire.** Deux gestes, indépendants :

- ne **viser** que ce qui peut porter un compte local : filtrer les cibles par
  type de client (le catalogue des types dit lesquels ont le droit d'émettre
  l'acquittement `06_02`), pour qu'un service ne soit jamais une cible ;
- pour le client Windows, le plus petit geste honnête : qu'il réponde `06_03`
  avec un code que le core reconnaisse (« non pris en charge par ce client »),
  et que le core range alors la cible dans un état à part, affiché tel quel par
  `--status`, sans plus la relancer. Ne **pas** acquitter : un ordre acquitté se
  lit comme un compte coupé.

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
