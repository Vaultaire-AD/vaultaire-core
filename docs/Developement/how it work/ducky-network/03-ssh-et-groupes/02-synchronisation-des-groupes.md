[⌂ Ducky Network](../README.md) › [Chapitre 3 — Poste de travail : SSH, PAM et groupes (03)](./README.md) › 3.2

# 3.2 — Synchronisation des groupes de la machine

[← Authentification SSH / PAM](./01-authentification-ssh.md) · [Chapitre 4 — Cluster et découverte (04) →](../04-cluster/README.md)

---


Les appartenances arrivent avec `03_02`, à chaque connexion. Encore faut-il que
les groupes existent sur la machine : sans eux, une appartenance annoncée n'est
posée nulle part. C'est ce que cet échange apporte.

```
03_08  demande            (agent → core)   contenu vide
  03_09  liste            (core → agent)   sync:<minutes> puis <nom>:<id_group>
  03_10  refus            (core → agent)   <raison>
```

L'agent émet au démarrage du service, puis à la cadence que le core lui annonce,
et une fois de plus quand une ouverture de session révèle un groupe annoncé mais
absent localement — le seul moment où l'écart est visible et où il a une
conséquence immédiate.

## Le GID vient du core

`GID = 100000 + id_group`.

Un GID choisi localement serait différent sur chaque machine. Sur un partage NFS,
où seuls des nombres circulent, deux postes du même domaine liraient alors des
droits différents sur les mêmes fichiers. C'est le problème que `uid.map` résout
pour les utilisateurs, et il ne se résout pas machine par machine : le seul point
qui voit tout le domaine est le core.

La formule est **sans état**. Une machine réinstallée retrouve les mêmes numéros
sans rien recopier, et deux machines qui découvrent les groupes dans un ordre
différent obtiennent le même résultat. Une table d'allocation aurait ajouté un
état à sauvegarder, à migrer, et à réparer le jour où il diverge de `groups`.

### Pourquoi 100000

`ProvisionVaultaireUser` donne à chaque compte un groupe primaire dont le GID
vaut l'UID : **5000–60000 est déjà consommé en entier**. Y placer les groupes du
domaine garantirait la collision — deux groupes portant le même numéro, donc des
droits qui s'appliquent au mauvais.

60001–65533 est libre mais étroit et bute sur `nogroup`. Les GID sont des entiers
32 bits ; 100000 laisse la place et reste lisible dans un `ls -n`.

Borne haute : `id_group ≤ 60000`. La table `groups` en est très loin — la borne
existe pour que l'hypothèse soit **vérifiée** plutôt que supposée.

### La règle est écrite des deux côtés

`db_groups.GIDDeGroupe` et `localusermanagement.GIDDeGroupe`, dans deux modules
Go qu'aucune compilation ne relie.

C'est le prix d'un choix : `03_09` porte les `id_group`, **pas les GID**. Envoyer
le numéro déjà calculé laisserait un core en imposer un arbitraire — dont `0`,
qui est `root`. Le core est authentifié, il n'est pas infaillible : une injection
SQL, une base restaurée de travers, un bogue suffisent.

Des tests jumeaux figent les constantes aux deux bouts, plus un test côté agent
qui refuse que la plage des groupes descende sur celle des UID. Sans eux, une
divergence n'apparaîtrait qu'au premier partage NFS, sous forme de droits qui ne
s'appliquent pas, sans message d'erreur nulle part.

## Ce que la machine reçoit

Les groupes des **domaines** auxquels elle appartient — pas ceux dont elle est
membre, pas ceux du reste de l'organisation.

Le filtre porte sur le domaine parce qu'un utilisateur qui s'y connecte peut
appartenir à un groupe que la machine ne partage pas. Il ne va pas plus loin
parce que la liste complète des groupes de l'organisation est une information de
structure, et que `/etc/group` est lisible par tous les comptes locaux du poste.

L'identifiant de la machine est lu dans **l'en-tête** de `03_08`, où la couche de
session l'a posé — donc authentifié. Le lire dans le contenu laisserait n'importe
quel agent réclamer les groupes d'un autre.

## La cadence voyage avec la liste

`group_sync_minutes` est un réglage du core (défaut 60 min), mais la boucle qu'il
pilote tourne sur l'agent. Sa valeur part donc dans `03_09`, sur une ligne
préfixée `sync:`.

L'alternative — une constante côté agent — aurait reproduit un défaut déjà nommé
ici : `IntervalleRapportAgent` duplique `gpo.MachineRefreshInterval`, et allonger
l'un sans l'autre fait apparaître tout le parc en retard du jour au lendemain.
Surtout, **un réglage qui s'affiche sans agir est plus trompeur que pas de
réglage du tout**.

La boucle de l'agent reconstruit son `time.After` à chaque tour : un `Ticker`
lirait sa période une seule fois, et la nouvelle valeur n'aurait d'effet qu'au
redémarrage du service. C'est la raison d'être de `reglages.Boucle` côté core, et
la même ici.

Une machine hors ligne applique la nouvelle cadence à son retour, pas avant.

## La suppression vide le groupe, elle n'efface pas la ligne

Quand un groupe disparaît du domaine, l'agent **retire ses membres** et
**conserve la ligne**.

Effacer la ligne rendrait orphelins tous les fichiers dont c'est le groupe
propriétaire : `ls -l` n'afficherait plus qu'un nombre, sur des données que
personne n'a demandé à toucher, et sans qu'aucune trace n'explique le numéro. Un
agent ne peut pas savoir ce qui en porte la marque sans parcourir tous les
systèmes de fichiers montés — partages réseau compris, où le parcours dure des
heures et où les fichiers appartiennent à d'autres machines.

Vider suffit à couper les droits, immédiatement et partout. Le nom subsiste pour
que l'administrateur puisse lire ce qu'il regarde.

L'effacement définitif est une décision humaine : `vaultaire_client
--purge-groups` affiche ce qui serait effacé, et n'agit qu'avec `--confirm`.

> **Écart avec la spécification initiale.** Elle proposait `vlt purge groups
> --machine <id>`, une commande du core. Cela aurait supposé une trame de plus,
> autorisant une écriture dans `/etc/group` à distance : une frontière de
> privilège neuve, donc une clé RBAC, une action et une entrée de catalogue —
> pour un geste dont le seul bénéfice est de la propreté, le vidage ayant déjà
> coupé les droits. La commande est donc locale, sur la machine concernée.

## Ce que l'agent ne touche jamais

Les groupes qu'il n'a pas créés. La limite est tenue par `/etc/vaultaire/groups.map`,
au format `<nom>:<gid>`, écrit atomiquement — même modèle que `user_groups.map`
pour les appartenances, et que `uid.map` pour les identifiants.

Un groupe local **homonyme** d'un groupe du domaine n'est jamais repris : il est
signalé en WARNING et laissé intact, GID compris. Le renuméroter changerait le
propriétaire de tous les fichiers qui en portent la marque.

**État illisible ⇒ aucun vidage.** Vider sans savoir ce qu'on a créé reviendrait
à toucher aux groupes de l'administrateur local — ce que le fichier existe pour
empêcher. Les créations, elles, se font quand même : elles n'enlèvent rien.

**Trois fichiers d'état sont deux de trop.** Les fusionner est possible, mais
`uid.map` est lu par le module NSS, en C, dans des processus non privilégiés :
en changer le format engage bien plus que la synchronisation des groupes. La
séparation est le choix prudent, pas le choix élégant.

## Les refus, et la liste vide

`03_10` et « aucun groupe » ne se confondent pas, et la distinction compte : un
domaine peut légitimement n'avoir aucun groupe, auquel cas il faut vider ceux qui
restent — mais vider le parc parce que la base du core est indisponible serait
exactement le mauvais réflexe.

Devant un refus, l'agent ne touche à rien. Devant une réponse dont **toutes** les
lignes ont été rejetées, non plus : elle ressemble à une liste vide sans en être
une.

Le motif du refus est volontairement grossier — « indisponible », jamais le
détail de l'erreur SQL. La trame part vers une machine du parc, dont le journal
est lisible par qui a un accès local.

## Ordre des opérations

Créations **avant** vidages — l'inverse de ce que fait `03_02` pour les
appartenances, et pour la même raison de fond.

Pour les appartenances, retirer d'abord garantit qu'un incident au milieu laisse
l'utilisateur avec moins de droits qu'attendu, jamais plus. Ici, vider d'abord
ouvrirait une fenêtre pendant laquelle un groupe renommé — disparu sous un nom,
réapparu sous un autre — n'existerait sous aucun des deux. Créer d'abord ne
retire jamais de droit par accident : le vidage qui suit s'en charge, sur une
liste déjà à jour.

## Ce qui reste ouvert

**Le groupe primaire de l'utilisateur** porte le nom du compte et le GID de son
UID. Le remplacer par un groupe du domaine toucherait `/etc/passwd` et la
propriété des fichiers déjà créés. Choix retenu : ne pas y toucher, ne gérer que
les groupes secondaires.

**Les machines hors ligne longtemps.** Une machine absente six mois retrouve des
groupes supprimés depuis. Le vidage les traite au premier contact, mais entre son
démarrage et cette synchronisation, les droits sont ceux d'il y a six mois.
Refuser les sessions en attendant transformerait une panne de réseau en
verrouillage de la machine : ce n'est pas fait.

---

[← Authentification SSH / PAM](./01-authentification-ssh.md) · [Chapitre 4 — Cluster et découverte (04) →](../04-cluster/README.md)
