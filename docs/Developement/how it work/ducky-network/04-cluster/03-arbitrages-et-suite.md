[⌂ Ducky Network](../README.md) › [Chapitre 4 — Cluster et découverte (04)](./README.md) › 4.3

# 4.3 — Affinité, enrôlement par site, et ce qui reste

[← Découverte de service et proxies](./02-decouverte-et-proxies.md) · [Chapitre 5 — Transport des GPO (05) →](../05-gpo/README.md)

---


## Arbitrage 5 — l'affinité nœud ↔ groupe *(fait — lot 6)*

Table `cluster_node_group (nœud, groupe)`, la MÊME pour les cores et les proxies.
Ordre servi : **proxies affins, autres proxies, cores affins, autres cores.**

**Préférence et non exclusivité.** Tous les nœuds exposés restent dans la liste,
en queue. C'est ce qui empêche la panne d'un site de devenir une panne
d'authentification pour ce site : un agent dont le proxy local est tombé descend
dans sa liste et finit par joindre un core — plus loin, plus lent, et il
travaille.

**Table dédiée, et non les groupes du client propriétaire.** Un proxy est un
client et pourrait figurer dans `logiciel_group` ; un CORE, non — il n'a pas de
ligne client, il se déclare lui-même avec le propriétaire réservé
`@core:<hostname>`. Faire dépendre l'affinité des groupes du client aurait laissé
les cores dehors, et demandé un second mécanisme pour eux.

**Pas de colonne de priorité**, contrairement à la spécification initiale. L'ordre
voulu ne demande qu'un OUI/NON, et un second nombre d'ordre devrait être concilié
avec `cluster_nodes.priorite` — deux réglages qui se contredisent ne se tranchent
qu'en lisant le code.

### Où l'affinité s'insère dans le tri

| # | Critère | Pourquoi là |
|---|---|---|
| 1 | proxies avant cores | le rôle décide de la NATURE du chemin ; un core affin ne doit pas doubler un proxy quelconque, sinon les proxies perdent leur raison d'être partout où il n'y en a pas |
| 2 | **affins d'abord** | départage entre pairs |
| 3 | priorité la plus basse | réglage global |
| 4 | nom | reproductible |

L'affinité passe **avant** la priorité, et c'est délibéré : la priorité est
globale, l'affinité est locale au demandeur. Si la priorité l'emportait, un proxy
mis en tête pour un site passerait devant le proxy local de tous les autres —
régler un site déréglerait les autres.

Les groupes du demandeur sont lus dans **l'en-tête** de `04_03`, où la couche de
session les a authentifiés. Les lire dans le contenu laisserait un agent réclamer
l'ordre d'un autre, donc apprendre à quel site appartient une machine qu'il ne
connaît pas.

Réglage : `vlt cluster affinity <nœud> <groupe...>`, ou **Admin → Cluster**.

## Arbitrage 6 — une clé d'enrôlement porte une affinité, pas un droit *(fait — lot 7)*

Table `service_enrollment_key_group`. Le service enrôlé par la clé est ajouté à
ces groupes **une fois**, à son enrôlement.

Le relire à chaque connexion ferait qu'une clé modifiée changerait les groupes
d'un service déjà en production, et le lien entre la cause et l'effet serait
introuvable des mois plus tard. Après l'enrôlement, les groupes du service se
modifient comme ceux de n'importe quelle machine.

Ce que les groupes portent est décidé ailleurs, et reste modifiable après coup.
Une clé qui accorderait des droits deviendrait un second système de permissions,
à tenir d'accord avec le premier.

**Le NOM du groupe est stocké, pas son identifiant.** Pas de clé étrangère vers
`groups` : une clé sert des mois après son émission, et une clé étrangère
effacerait la ligne en silence si le groupe disparaissait — l'enrôlement se ferait
alors sans affinité, sans que rien puisse dire laquelle manquait. Contrepartie
assumée : un groupe **renommé** n'est plus retrouvé.

**Un groupe manquant n'empêche pas l'enrôlement.** La clé porte une affinité, pas
un droit : le service entre avec les groupes qui existent encore, et l'absence
part en `SECURITY`. Refuser arrêterait une chaîne de déploiement pour une question
de rangement, et le rapport entre « ce proxy ne démarre plus » et « quelqu'un a
renommé un groupe » ne sauterait aux yeux de personne.

Émission : `vlt enroll create --type … --groups paris,lyon`, ou **Admin →
Enrôlement**.

### Le semis d'affinité, en `04_01`

La clé fait du service un **membre** de ses groupes. Mais l'affinité vit sur la
ligne de NŒUD, qui n'existe pas encore à l'enrôlement : elle est écrite plus
tard, quand le proxy envoie sa `04_01`.

`RegisterNode` reporte donc les groupes du client propriétaire dans
`cluster_node_group` — **une seule fois**, si le nœud n'a aucune affinité. Sans
ce geste, un proxy enrôlé avec la clé de Lyon naissait dans le groupe lyon et ne
servait pourtant personne en priorité : il fallait encore taper `vlt cluster
affinity` à la main, ce qui vide la clé de son intérêt pour une chaîne de
déploiement.

La condition « aucune affinité » est ce qui protège un réglage manuel : sans
elle, l'affinité reviendrait à celle de la clé au prochain redémarrage du proxy —
le défaut que `RegisterNode` évite déjà pour la priorité et la rotation.

Conséquence assumée : retirer TOUTES les affinités d'un nœud est un état qui se
re-sème au redémarrage suivant. « Aucune affinité » et « jamais réglé » ne se
distinguent pas sans une colonne de plus, et cette colonne existerait pour un
seul cas — vouloir qu'un proxy de Lyon ne serve pas Lyon — qui se traite en
retirant le client du groupe.

Un CORE n'est pas concerné : il n'a pas de ligne client, ne naît d'aucune clé, et
son affinité se règle à la main.

## Le relais *(lot 4 fait — 2.2)*

Relais TCP Ducky en place ; relais LDAP/S et HTTPS prévus. Le code
(`src/vaultaire_proxy/relais/`) connaît déjà les quatre types et plusieurs
relais par proxy ; seuls `ducky` et les sources `cores`/`liste` sont actifs.
Exploitation : [`docs/proxy/relais.md`](../../../../proxy/relais.md).

**Que fait un proxy dont tous les cores sont injoignables ?** Tranché : il
**refuse franchement**. Un client qui reçoit un refus essaie le suivant de sa
liste — un core, puisqu'ils y figurent toujours. Un client en attente ne fait
rien pendant tout le délai, et le proxy en panne devient un trou noir au lieu
d'un nœud qu'on contourne. *Implémenté* : aucune cible ne répond (3 s par
cible) → la connexion de l'agent est fermée.

**Ordre des cibles fixe, sans rotation.** L'agent garde en cache la clé d'UN
core ; le promener d'un core à l'autre ferait échouer la poignée de main dès que
les cores n'ont pas la même clé. Le repli n'a lieu que si la cible précédente ne
répond pas.

**Relayer vers autre chose qu'un core.** Le proxy doit pouvoir relayer du HTTPS
vers les Nexus. Il y faut que le core annonce les **services** (la `04_04`
n'annonce que cores et proxies) : source `service:<type>`, prévue. Pour LDAP/S :
SAN du core couvrant les proxies, et limitation des échecs de bind qui ne
pénalise pas tout un site. Détail : [`docs/proxy/prevu-https-ldap.md`](../../../../proxy/prevu-https-ldap.md).

## Découpage restant

| Lot | Contenu | État |
|---|---|---|
| 4 | Relais TCP Ducky | **fait** (2.2) |
| 5 | Relais LDAP/S, SAN du core couvrant les proxies | **reste à faire** — TO-DO 72 |
| 5 bis | Relais HTTPS vers les services (Nexus), découverte des services | **reste à faire** — TO-DO 72 |
| 6 | Table d'affinité `(nœud, groupe)` et tri côté serveur | fait |
| 7 | Groupes portés par une clé d'enrôlement | fait |

Le lot 7 est venu **après** le 6 et non avant : rattacher un service à des groupes
n'a aucun effet observable tant que l'affinité ne trie rien. L'écrire d'abord
aurait donné une fonctionnalité qu'on ne peut pas éprouver.

Ce qui reste est le sujet du point 72 dans `TO-DO.md`.

---

[← Découverte de service et proxies](./02-decouverte-et-proxies.md) · [Chapitre 5 — Transport des GPO (05) →](../05-gpo/README.md)
