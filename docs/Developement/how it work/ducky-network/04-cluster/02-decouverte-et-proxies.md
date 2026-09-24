[⌂ Ducky Network](../README.md) › [Chapitre 4 — Cluster et découverte (04)](./README.md) › 4.2

# 4.2 — Découverte de service et proxies

[← Nœuds et services : enregistrement et battement](./01-noeuds-et-services.md) · [Affinité, enrôlement par site, et ce qui reste →](./03-arbitrages-et-suite.md)

---


Un agent ne connaissait que les serveurs de son fichier de configuration.
Ajouter un core au cluster demandait de repasser sur chaque machine du parc ; en
retirer un laissait les agents s'y acharner. Un proxy déployé, lui, n'apparaissait
dans aucune configuration — donc aucun agent n'y passait, donc il ne servait à
rien.

```
04_01  s'enregistrer dans le cluster   (nœud → core)
  04_02  accusé
04_03  demander les nœuds joignables   (client → core)   contenu vide
  04_04  la liste, ORDONNÉE            (core → client)
04_05  remonter une métrique           (nœud → core)
  04_06  accusé
04_07  battre                          (nœud → core)
  04_08  accusé
```

> **Ce qui est en place** : les lots 0 à 4, 6 et 7 — un agent apprend ses nœuds
> joignables, un proxy existe dans le cluster, bat, et **relaie le Ducky** vers
> les cores (lot 4, 2.2). **Le relais LDAP/S et HTTPS n'est pas activé** (TO-DO
> 72) ; voir [4.3](./03-arbitrages-et-suite.md) et [`docs/proxy/`](../../../../proxy/README.md).

### L'adresse annoncée en `04_04` n'est pas toujours celle du nœud

Le champ `<ip>` de `04_04` porte l'adresse **EFFECTIVE**, pas `ip_address`.

Un nœud déclare en `04_01` l'adresse qu'il voit de lui-même. C'est un fait, et il
est bien placé pour le donner — mais derrière une redirection NAT, dans un
conteneur, ou sur un hôte à plusieurs interfaces, ce n'est pas celle par laquelle
le parc l'atteint. Il ne peut pas le savoir : il ne voit pas son infrastructure
de l'extérieur. Le core distribuait donc à toutes les machines une adresse privée
que personne ne pouvait joindre.

Deux colonnes portent la déclaration d'un administrateur, et priment ici :

| Colonne | Prime sur | Vide / zéro |
|---|---|---|
| `adresse_publique` | `ip_address` | on sert `ip_address` |
| `port_public` | `ducky_port` | on sert `ducky_port` |

Elles sont **indépendantes** : une redirection translate souvent le port sans
changer l'hôte, et l'inverse existe aussi.

Comme `priorite` et `expose_aux_agents`, ce sont des décisions d'EXPLOITATION :
`RegisterNode` ne les touche pas, sinon un nœud écraserait la déclaration avec sa
propre vue à son prochain démarrage.

Un nœud sans port déclaré **ni par lui-même ni par un administrateur** reste omis
de la liste. Un port public suffit donc à remettre dans la rotation un nœud
enregistré par une version antérieure, sans attendre qu'il se réenregistre.

Réglage : `vlt cluster expose <nœud> <adresse> [port]`, ou **Admin → Cluster**.

## Ce qui bloquait

La catégorie `04` était écrite **côté serveur** presque en entier. Ce qui
manquait n'était pas le code du core : c'est que le **catalogue de types ne
l'accordait à personne**, et que rien ne l'émettait.

| Trame | Code serveur | Émetteur, avant | Émetteur, maintenant |
|---|---|---|---|
| `04_01` | oui | personne | proxy |
| `04_03` | oui | personne | agent, proxy |
| `04_05` | oui | personne | proxy |
| `04_07` | oui | personne | proxy |
| `04_15` | oui (TO-DO 72) | — (trame neuve) | proxy seulement |

## Arbitrage 1 — la découverte vit en `04`, et nulle part ailleurs

Le tableau en tête de document a longtemps porté deux entrées de la catégorie
`02` pour « demander la liste des proxies/cores » et « rendre la liste ». Aucune
ligne de code ne les a jamais implémentées, et elles faisaient doublon avec
`04_03`/`04_04`. Elles ont été retirées du protocole.

La catégorie `02` est « User auth » : y ranger la découverte de service se
paierait à chaque lecture. Qui a le droit de demander reste décidé par le
catalogue de types, pas par le numéro de trame.

*(Détail du retrait : DO/2.1/2.1.md, entrée 9+10.)*

## Arbitrage 2 — le proxy est un RELAIS, il ne déchiffre rien

Deux modèles étaient possibles : transporter les octets sans les lire, ou
terminer la session Ducky et en ouvrir une autre vers le core.

C'est le **point 29 qui a tranché**. Avant lui, le chemin PAM ne faisait passer
qu'une preuve HMAC : un proxy qui terminait la session ne voyait rien
d'utilisable. Depuis, le mot de passe transite dans le tunnel — un proxy qui
déchiffrerait deviendrait un point de collecte des mots de passe du parc.

*Fait en 2.2 (lot 4)* : `src/vaultaire_proxy/relais/`, transport TCP sans
lecture. Deux conséquences écrites en même temps :

- l'agent **n'apprend pas** l'empreinte d'un nœud de rôle `proxy` (c'est la clé
  de son identité de client, pas une clé de core : l'apprendre laisserait le
  proxy répondre à la poignée de main à la place d'un core) ; la liste persistée
  ne garde un proxy que si un core de confiance y figure ;
- le core accorde 1000 connexions (au lieu de 20) aux adresses des proxies
  enregistrés et en ligne, puisque tous les agents d'un site arrivent de
  l'adresse du proxy.

Exploitation : [`docs/proxy/`](../../../../proxy/README.md).

## Arbitrage 3 — les empreintes s'apprennent depuis une confiance existante

Sans cela, distribuer une liste de cores ne servirait à rien : l'agent
refuserait tous ceux qu'il ne connaît pas — c'est-à-dire tous sauf un.

`core_key_fingerprint` est donc devenu une **liste**. N'importe laquelle de ses
entrées suffit à accepter une clé. La première ligne reste celle déposée par
`vlt create -join`, la seule dont on sache par quel canal elle est arrivée ;
l'ordre du fichier le dit.

Une empreinte s'apprend en recevant `04_04`, qui la porte pour chaque nœud
annoncé. Le message ne s'atteste pas lui-même : il arrive sur une session dont la
clé du core a **déjà** été vérifiée. Ce n'est pas un nœud qui se déclare, c'est
un core de confiance qui atteste ses pairs.

**On n'apprend jamais depuis rien.** Une machine sans aucune empreinte est en
confiance au premier usage ; y ajouter une valeur venue du réseau serait la même
chose sous un autre nom. `ApprendreEmpreinte` refuse ce cas.

La liste est **bornée** à 16 entrées. Un fichier de confiance qui grossit tout
seul finit par ne plus rien attester — personne ne relit trente empreintes pour
savoir laquelle n'a rien à y faire. L'atteindre est un signal, d'où le refus
explicite plutôt qu'une éviction de la plus ancienne, qui retirerait justement
celle de l'installation.

> **Limite assumée.** Tout core de confiance peut ajouter de la confiance. Un
> core compromis fait apprendre au parc l'empreinte de son choix. Ce qui borne le
> risque est ailleurs : un core compromis détient déjà les clés du domaine, et
> l'empreinte n'est pas ce qui le retient.

## Arbitrage 4 — un nœud est joignable par défaut

`expose_aux_agents`, **VRAI par défaut**, y compris pour les nœuds déjà
enregistrés. Le défaut compte : à faux, la migration aurait retiré d'un coup tous
les cores existants de la liste, et le parc n'aurait plus eu aucune adresse — sur
une mise à jour censée n'ajouter qu'une fonctionnalité.

**Ce n'est pas un contrôle d'accès.** Le drapeau retire une adresse d'une liste,
il n'empêche personne de se connecter. Le pare-feu reste ce qui protège un core.
Il sert à sortir un nœud de la rotation sans le désenregistrer, ce qui le ferait
disparaître des vues de supervision au moment précis où on le surveille.

## Le tri est fait par le SERVEUR

L'agent parcourt la liste de haut en bas, sans rien décider.

Trier côté agent supposerait de lui envoyer de quoi le faire — métriques,
affinités, état de chaque nœud — c'est-à-dire de distribuer à toutes les machines
du parc une carte de l'infrastructure. Et chaque agent trierait avec SA version
du code : changer la règle demanderait de mettre le parc à jour avant qu'elle
prenne effet.

L'ordre, en trois critères :

1. les **proxies** avant les cores — c'est leur raison d'être ;
2. à rôle égal, la **priorité la plus basse** d'abord ;
3. à priorité égale, le **nom**, pour que l'ordre soit reproductible.

Les cores restent **toujours** dans la liste, en queue : un client dont tous les
proxies échouent doit pouvoir en joindre un, sans quoi la panne d'un relais
deviendrait une panne d'authentification.

**Zéro se range APRÈS.** Une priorité nulle vaut « sans préférence ». Si elle se
rangeait avant, donner une priorité à un seul nœud le reléguerait derrière tous
les autres — l'exact inverse de l'intention. C'est le piège classique d'un défaut
à zéro sur un champ d'ordre, et il se paie une fois en production.

Le troisième critère n'est pas décoratif : sans lui, deux nœuds équivalents
s'ordonneraient selon le plan d'exécution, et tout le parc basculerait ensemble
sur un nœud que rien n'a désigné.

## Ce qu'un nœud doit déclarer pour être annoncé

Trois choses, et leur absence l'écarte de la liste plutôt que de l'y faire
figurer à moitié :

| | Sans quoi |
|---|---|
| un **port** | l'agent composerait l'adresse avec un port deviné — une tentative qui échoue, un délai, un basculement retardé |
| une **empreinte** | l'agent devrait accepter la clé de ce nœud en aveugle à sa première connexion |
| l'état **en ligne** | l'adresse serait servie alors que personne n'écoute |

Le core se déclare lui-même au démarrage, avec le port de sa configuration
d'écoute — la même source, pour que les deux ne puissent pas diverger. Sur une
installation mono-core, un défaut ici reviendrait à n'annoncer personne, et rien
ne relierait « les agents ne trouvent plus de serveur » à une colonne ajoutée au
schéma. D'où le message d'erreur explicite.

## Un nœud n'écrit que SA ligne

C'est la règle dont dépend toute la chaîne de confiance de la découverte. Elle
n'existait pas : `04_01` lisait le hostname, l'IP et le **rôle** dans le contenu
de la trame, sans aucun lien avec la session authentifiée.

Un proxy enrôlé pouvait donc envoyer le hostname d'un core. L'écriture écrasait
sa ligne — adresse, port et **empreinte** comprises. La `04_04` annonçait ensuite
l'empreinte de l'attaquant sous le nom du core ; les agents l'apprenaient, la
plaçaient devant leurs serveurs statiques, et s'y connectaient pour
s'authentifier. Élévation de « service qui relaie » à « serveur qui
authentifie ».

### Deux barrières indépendantes

**La ligne appartient à quelqu'un.** `cluster_nodes.owner_client_id` porte
l'identifiant machine figé à la poignée de main `01_01`. Un nœud met à jour la
ligne dont il est propriétaire, ou la crée — et se voit refuser un hostname déjà
pris par un autre propriétaire, ce qui est précisément le geste de l'usurpation.

Deux formes de propriétaire :

| Forme | Qui |
|---|---|
| `<client_software_id>` | un nœud enregistré par le réseau — proxy, service |
| `@core:<hostname>` | un core, qui écrit sa ligne depuis son propre processus |

Le préfixe `@` est **réservé** : un propriétaire venu d'une session ne peut pas
commencer par lui. Et le nom du core porte son **hostname**, parce qu'une valeur
commune à tous les cores laisserait chacun écrire la ligne des autres — le même
défaut, sous une autre forme.

**Le rôle se déduit, il ne se déclare pas.** `clienttype.RoleCluster` le rend à
partir du type figé à la poignée de main. `vaultaire_proxy` → `proxy`, et rien
d'autre ne prend de rôle de nœud. **Aucun type ne peut produire `core`** : un
core n'est pas au catalogue — il ne peut pas se juger lui-même — et n'entre dans
la table que par son propre processus. Le rôle annoncé dans la trame n'est plus
lu que pour journaliser un écart.

### La même règle sur les trois autres trames

| Trame | Désignait la ligne par | Désormais |
|---|---|---|
| `04_01` | hostname et IP du contenu | propriétaire |
| `04_07` | hostname du contenu | propriétaire |
| `04_05` | hostname du contenu | hostname de la ligne du propriétaire |
| `04_12`, `04_14` | hostname de l'en-tête | propriétaire |

Un battement dit « **je** suis là », pas « celui-là est là ». Sans quoi n'importe
quel nœud maintenait en ligne la ligne d'un core éteint, qui restait annoncé aux
agents et absorbait leurs tentatives. Et les métriques alimentent le **tri** de
la liste : les écrire au nom d'un pair revenait à décider vers qui le parc se
dirige.

`04_12` et `04_14` prenaient l'identifiant dans l'**en-tête** — que
`Split_Action` vérifie déjà contre la session. Ce n'était donc pas exploitable,
mais c'était juste *par dépendance* : le jour où ce contrôle bouge, ce code
devient faux sans avoir été touché.

### Ce qui borne les métriques

`04_05` insère une ligne dans `proxy_metrics`. Rien ne bornait ni le **débit**
d'écriture ni la **durée de vie** des lignes : la table grossissait
indéfiniment, y compris en fonctionnement normal.

| | Valeur | Réglable |
|---|---|---|
| rétention | 30 jours (0 = illimité) | `cluster metrics-retention <jours>` |
| débit | 60 par nœud et par minute | au démarrage du core |

**Le refus de quota n'est pas une sanction.** Ni fermeture de connexion, ni
erreur : punir un nœud qui remonte trop de métriques couperait aussi son
enregistrement et son battement, donc le retirerait de la liste servie aux
agents. La sanction serait pire que le problème. La métrique est abandonnée et
le core répond `throttled` plutôt que d'accuser réception d'une écriture qui n'a
pas eu lieu.

**Le journal est lui-même limité** — une ligne par nœud toutes les cinq minutes.
Journaliser chaque métrique refusée déplacerait l'inondation de la table vers le
fichier de journal, qui la supporte encore moins bien.

**La purge est bornée par passage** (10 000 lignes). Le premier passage après la
mise en service est celui qui a le plus à supprimer : sans borne, le comportement
le plus lourd arriverait au moment le moins attendu, sur une base en service.

Ce n'est **pas** `core/auth/ratelimit`. Ce paquet-là freine la force brute sur
les mots de passe — trois essais gratuits, échéance qui double, deux compteurs
croisés — et se pilote par `Echec`/`Reussite`. Une métrique n'échoue jamais : le
réutiliser voudrait dire appeler `Echec` sur chaque écriture légitime. Un
plafond et un frein sont deux problèmes différents.

### Le piège de `RowsAffected`

`RegisterNode` fait un `SELECT` puis un `UPDATE` par identifiant, et non un
`UPDATE` dont on lirait le nombre de lignes touchées. MySQL rend `0` quand
l'`UPDATE` ne **change** rien — le cas ordinaire d'un nœud qui se réenregistre
sans avoir bougé. S'en servir pour conclure « la ligne n'existe pas » ferait
échouer chaque réenregistrement sur un conflit de hostname : un défaut qui
n'apparaît qu'au **deuxième** démarrage d'un nœud stable.

## Ce que l'agent fait de la liste

Il la **fusionne** : les nœuds appris devant, les serveurs du fichier de
configuration derrière.

**Les statiques ne sont jamais écrasés.** Ils sont le dernier recours. Un agent
qui les remplacerait par les nœuds reçus n'aurait plus rien à joindre le jour où
la liste distribuée est vide, fausse, ou pointe sur des nœuds tous éteints — et
il faudrait repasser à la main sur les machines, c'est-à-dire exactement ce que
la découverte existe pour éviter.

**Une liste vide n'en écrase pas une pleine.** Un core qui répond « aucun nœud » a
peut-être une base indisponible. Effacer sur cette foi couperait l'agent de tout
ce qu'il avait appris, au moment précis où le core va mal.

**La liste apprise est persistée** (depuis la 2.2, TO-DO 61). L'agent l'écrit
dans la section `learned` de `client_conf.json` — seulement les nœuds dont
l'empreinte est de confiance, seulement quand elle change —, et la relit au
démarrage, entre la mémoire et les serveurs d'installation. Avant, elle ne
vivait qu'en mémoire : après un redémarrage, l'agent repartait de la seule
adresse du fichier. Côté SDK, un programme s'abonne avec
`decouverte.SurNouvelleListe`. Détail :
[Agent : liste des cores et rapport de debug](../../../../exploitation/Agent_configuration_et_debug.md).

## La cadence vient du core, la liste peut être poussée (2.2, TO-DO 90)

La cadence était une **constante** de 30 minutes côté agent, avec cet argument :
elle ne pilote qu'une lecture, dont le seul effet est de rafraîchir une liste
d'adresses en mémoire.

L'argument ne tient plus depuis que la liste sert à **basculer** (ci-dessous) :
une lecture peut désormais décider que le nœud en cours d'usage n'est plus le
bon, et provoquer une reconnexion. Ce qu'elle pilote est devenu un effet sur le
parc, comme `group_sync_minutes` et `gpo_refresh_minutes` — et comme eux, cela
se règle depuis le core, par `node_list_refresh_minutes`.

**La valeur voyage en queue de `04_04`, derrière `disco:`.** Les lignes de nœud
de cette trame se lisent **par position** — six champs séparés par `|` —, à la
différence de `03_09` et `05_02` qui se lisent par préfixe : une ligne de plus au
milieu casserait l'analyse. En queue et préfixée, un agent d'une version
antérieure la rejette comme une ligne fautive et garde le reste. Elle n'entre
**pas** dans le nombre annoncé en première ligne, qui compte des nœuds et que
l'agent vérifie : l'y ajouter ferait croire à une trame tronquée à chaque envoi.

L'agent **borne** ce qu'il reçoit entre 5 minutes et 24 heures, comme le réglage
côté core. Cette borne est là parce qu'une valeur venue du **réseau** pilote une
boucle infinie : une cadence nulle ferait de l'agent un générateur de trafic, une
cadence d'un mois le laisserait ignorer un nœud retiré. Une ligne illisible ne
change **rien** : la valeur en vigueur a été décidée par un core, et la
remplacer par le défaut à la première trame abîmée annulerait le réglage.

**`04_17` pousse une actualisation.** La cadence borne le retard — au pire une
demi-heure entre l'ajout d'un core et sa prise en compte. C'est acceptable en
régime normal et beaucoup trop long pendant une bascule de cluster. Raccourcir
la cadence de tout le parc à cause d'un moment particulier reviendrait à faire
redemander la liste toutes les minutes pendant l'année, pour les dix minutes qui
comptent.

Cette trame **ne transporte aucune liste** : l'agent repart sur une `04_03`
ordinaire, et tout le chemin habituel — filtrage par groupes, tri, apprentissage
des empreintes, persistance — reste identique. Une trame de réveil ne pouvait
pas devenir un second chemin d'apprentissage, qu'il aurait fallu tenir d'accord
avec le premier ; c'est le même arbitrage que pour `05_18` côté GPO.

**Rien n'est mis en file.** Une machine hors ligne ne la reçoit pas et n'en garde
aucune trace : elle redemandera sa liste à sa reconnexion, puisque la boucle de
découverte commence par un passage immédiat.

Côté exploitation : `vlt cluster refresh <machine|-g groupe|--all>`, action
`cluster.refresh_nodes`.

## La bascule vers le nœud prioritaire (2.2, TO-DO 90)

L'agent se connecte au premier nœud qui répond, dans l'ordre servi par le core.
Cet ordre est calculé **une fois**, à la connexion. Si un nœud plus prioritaire
est ajouté, remis en ligne ou repriorisé ensuite, l'agent continue de parler à
celui qu'il tient — jusqu'au prochain redémarrage. Un poste pouvait donc rester
des semaines sur un nœud de secours alors que le principal était revenu, sans
que rien ne le signale : de son point de vue tout fonctionnait.

À chaque nouvelle liste, l'agent compare la priorité du nœud **courant** à la
meilleure de la liste, et **ferme sa session mère** si elle est strictement
moins bonne. Il ne CHOISIT pas de nœud : la supervision du tunnel rétablit la
connexion par le chemin ordinaire, qui essaie les adresses dans l'ordre servi
par le core. Rejouer ici une logique de sélection en aurait fait une seconde, à
tenir d'accord avec la première.

**L'égalité ne bascule pas.** Deux nœuds de même priorité sont équivalents :
basculer de l'un vers l'autre ne gagne rien et coûte une coupure. Pire, sur un
parc où deux nœuds se disputent la tête de liste, chaque `04_04` provoquerait
une reconnexion — un va-et-vient permanent déclenché par le mécanisme censé
améliorer les choses.

Deux autres cas, pour la même raison :

- **liste vide** : elle ne dit pas que le nœud courant est mauvais, elle dit
  qu'on ne sait rien ; basculer couperait le tunnel pour se reconnecter au même
  endroit, ou à rien ;
- **priorité 0 ou absente** : elle vaut « dernier », comme côté core
  (`prioriteEffective`) ; la lire comme « premier » ferait basculer tout le parc
  vers le nœud le moins bien renseigné.

Le nœud courant **absent de la liste** servie est en revanche un cas de bascule :
il a été retiré ou n'est plus joignable.

## Ce que le proxy émet

`04_01` au démarrage, `04_07` toutes les 20 secondes, `04_03` pour trouver ses
cores. La cadence de battement est **locale et volontairement courte** : un
`reglages` lit la base, qu'un proxy n'a pas, et un battement trop espacé ferait
déclarer hors ligne un nœud parfaitement vivant.

`-listen-port` est **obligatoire et sans défaut**. Une valeur devinée serait
annoncée à tout le parc, et les agents s'y connecteraient sans que rien n'écoute.

Un échec de raccordement **n'arrête pas le proxy** : il reste connecté et
authentifié, il perd sa visibilité. Traiter cela comme fatal ferait qu'un nom
d'hôte introuvable coupe un service qui fonctionne par ailleurs.

---

[← Nœuds et services : enregistrement et battement](./01-noeuds-et-services.md) · [Affinité, enrôlement par site, et ce qui reste →](./03-arbitrages-et-suite.md)
