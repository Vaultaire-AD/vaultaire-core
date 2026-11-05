[⌂ Documentation](../README.md) › [Proxy](./README.md) › Sécurité

# Sécurité du proxy

[← Relais](./relais.md) · [HTTPS et LDAPS →](./https-et-ldaps.md)

---

## Le proxy ne déchiffre rien

C'est l'**arbitrage 2** du cluster ([spécification](../Developement/how%20it%20work/ducky-network/04-cluster/02-decouverte-et-proxies.md#arbitrage-2--le-proxy-est-un-relais-il-ne-déchiffre-rien)).
Depuis le point 29, le **mot de passe** d'un utilisateur transite dans le
tunnel Ducky, du module PAM jusqu'au core. Un proxy qui terminerait la session
pour en rouvrir une autre verrait passer en clair les mots de passe de tout le
site : il deviendrait la cible la plus rentable du parc.

Le relais transporte donc des octets chiffrés de bout en bout, entre l'agent et
le core. Ce qu'un proxy compromis peut faire :

| Il peut | Il ne peut pas |
|---|---|
| couper, retarder, refuser des connexions | lire une trame, un mot de passe, un jeton |
| voir qui se connecte, quand, et combien d'octets | modifier une trame sans que la session échoue |
| rediriger vers un autre core du cluster | se faire passer pour un core (voir ci-dessous) |

Le même principe vaudra pour les relais prévus : un relais HTTPS ou LDAPS ne
terminera pas TLS ; le certificat présenté au client restera celui du service.

## L'agent n'accorde aucune confiance au proxy

Au bout du tunnel, l'agent vérifie la clé **du core**, contre son fichier de
confiance (`core_key_fingerprint`), exactement comme en direct. Le proxy n'y
entre jamais :

- La trame `04_04` porte une empreinte pour chaque nœud. Pour un proxy, c'est la
  clé de son **identité de client**, pas une clé de core. L'agent **n'apprend
  pas** les empreintes des nœuds de rôle `proxy` : sinon un proxy pourrait
  répondre lui-même à la poignée de main et se faire accepter comme un core.
- La liste persistée par l'agent (section `learned` de `client_conf.json`) ne
  garde un proxy que si un core de confiance y figure aussi. Un agent dont la
  seule entrée serait un proxy n'aurait plus aucun moyen de joindre un core.

Conséquence pratique : un agent peut n'avoir **que** l'adresse d'un proxy dans
sa configuration d'installation. Il joint le core par le relais, vérifie sa clé,
et apprend ensuite les autres nœuds.

## Le plafond par adresse, côté core

Le core limite les connexions Ducky à **20 par adresse IP** (2000 au total) : une
machine ne doit pas prendre toutes les places. Or, derrière un relais, **tous**
les agents d'un site arrivent de l'adresse du proxy.

Le core accorde donc **1000** connexions aux adresses d'un proxy **enregistré et
en ligne**, sous l'adresse où le core le **voit** *(TO-DO 184)* : la source de
la session Ducky par laquelle il bat (`adresse_vue`), celle de ses sessions sur
ce core, et l'adresse qu'il déclare tant qu'aucune n'a encore été vue.
L'adresse d'exposition (`cluster expose`) n'y entre pas : c'est celle des
**clients**. La liste est relue toutes les 30 secondes. Ce n'est pas une porte
qu'une source s'ouvre elle-même : enregistrer un nœud proxy exige une identité
de type `vaultaire_proxy`, donc une clé d'enrôlement de ce type. Le plafond
global reste commun à tous.

> **À savoir.** Derrière un NAT — proxy et core en conteneurs —, le core voit
> le proxy sous l'adresse de la **passerelle** : c'est elle qui reçoit
> l'exemption, sans réglage. Les autres programmes qui sortent par la même
> passerelle en profitent aussi ; dans un tel montage, la passerelle EST le
> proxy pour le core.

## Ce que le core voit d'un agent relayé

L'adresse du **proxy**, pas celle de l'agent. Cela touche :

- les journaux de connexion du core (`New connection established: <IP du proxy>`) ;
- la trace de consommation d'une clé d'enrôlement (adresse d'origine) quand une
  machine s'enrôle à travers un proxy.

L'identité de la machine, elle, est prouvée par sa clé dans la session : ce qui
décide d'un droit ne dépend jamais de l'adresse.

Pour LDAP, c'est plus sérieux : la limitation des échecs de bind se fait **par
adresse source**, et relayer sans rien de plus ferait partager un compteur à
tout un site. Le relais `ldaps` place donc un **en-tête PROXY v2** devant chaque
connexion, avec l'adresse du client. Le core ne le croit que d'un **proxy
enregistré** — la même liste que pour l'exemption Ducky — et ferme la connexion
de quiconque d'autre l'envoie : sinon n'importe qui choisirait l'adresse sous
laquelle il est compté. Détail : [`https-et-ldaps.md`](./https-et-ldaps.md).

> **À savoir.** Comme l'exemption, la confiance suit l'adresse **vue par le
> core**, sans configuration *(TO-DO 184)*. `cluster expose` ne sert plus qu'aux
> clients : l'exposer à l'adresse que voit le core — le contournement de la
> recette du 12/10 — n'est plus nécessaire, et casserait leur accès. Reste une
> limite : un core qui ne tient pas la session du proxy le connaît par
> l'adresse qu'a vue le core qui la tient ; deux cores derrière deux NAT
> différents ne voient pas la même.

## Le pilotage par le core

Depuis la 2.2, le core peut dire à un proxy quels relais ouvrir
([`pilotage.md`](./pilotage.md)). C'est un pouvoir : poser un relais ouvre un
port sur une machine du site et y fait arriver un service — ou, par une source
`liste`, n'importe quelle adresse que le proxy sait joindre.

| Qui | Ce qui le borne |
|---|---|
| l'administrateur | la clé `write:relay`, distincte de `write:cluster`, accordée à personne par défaut ; chaque écriture laisse une ligne `SECURITY` avec l'état avant et après |
| le core | il contrôle la liste avant de l'écrire : types admis, pas de LDAP en clair, le relais Ducky gardé sur son port |
| le proxy | il contrôle **de nouveau** tout ce qu'il reçoit, refuse en entier une liste qu'il ne comprend pas complètement ou qui retirerait son relais Ducky, et ne reçoit de liste que par son tunnel authentifié |
| la machine | `pilotage_par_le_core: false` : le proxy rend compte et ne se laisse rien changer |

Ce que le pilotage **ne change pas** : un relais ne lit toujours rien et ne
termine toujours ni la session Ducky ni TLS. Un core compromis peut faire ouvrir
un port à un proxy ; il ne peut pas lui faire déchiffrer ce qui y passe.

Le compte rendu du proxy (`04_18`) est gardé à part de la demande : un proxy
peut mentir sur son état, pas se donner une configuration.

## Plafonds du proxy lui-même

Par relais : 20 connexions par adresse cliente, 4000 au total, fermeture après 15
minutes sans un octet. Un relais n'authentifie personne ; ces plafonds l'empêchent
seulement d'être saturé par une machine. Voir [`relais.md`](./relais.md).

---

[← Relais](./relais.md) · [HTTPS et LDAPS →](./https-et-ldaps.md)
