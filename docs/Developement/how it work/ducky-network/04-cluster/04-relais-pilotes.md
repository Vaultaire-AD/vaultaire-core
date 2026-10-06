[⌂ Ducky Network](../README.md) › [Chapitre 4 — Cluster et découverte (04)](./README.md) › 4.4

# 4.4 — Les relais d'un proxy, pilotés par le core

[← Affinité, enrôlement par site, et ce qui reste](./03-arbitrages-et-suite.md) · [Chapitre 5 — Transport des GPO (05) →](../05-gpo/README.md)

---

*(2.2, TO-DO 141 — et le refus de battement du TO-DO 109)*

| Trame | Reçue par | Nom | Rôle |
|---|---|---|---|
| `04_18` | core | relay_state | **proxy seulement** : compte rendu de ses relais — un document JSON, sur une ligne |
| `04_19` | proxy | relay_config | ce que le core veut : `<mode>`, `<révision>`, puis le document JSON des relais demandés |
| `04_08` | nœud | host_heartbeat_ack | `ack`, ou — depuis la 2.2 — `refus` puis le motif : le core ne connaît pas ce nœud |

## Ce qui manquait

Ce qu'un proxy expose — Ducky, HTTPS, LDAPS, sur quel port, vers quoi — ne
s'écrivait que dans son fichier YAML. Le core n'en recevait que des compteurs
(`04_05`). Ajouter un relais à un site demandait une session sur la machine du
proxy et un redémarrage, donc la coupure de tous les tunnels qu'il transportait.

## Arbitrage 1 — où vit la vérité

| | Le core n'a rien décidé | Le core a une liste |
|---|---|---|
| le proxy applique | son fichier | la liste du core |
| le core affiche | ce que le proxy rapporte | sa demande, et l'état de chaque relais |

Le fichier **amorce**. La première écriture faite depuis le core prend la main,
en repartant des relais **actifs** du dernier compte rendu : partir d'une liste
vide ferait d'« ajouter un relais » le retrait de tous les autres. Rendre la
main (`cluster.relay_release`) fait réappliquer le fichier.

Le proxy garde sur son disque la dernière liste reçue (`relais_du_core.json`,
dans le répertoire des clés), et la rouvre à son démarrage. Elle ne le fait
**pas** relayer sans core : les relais ne s'ouvrent qu'une fois la session
établie (TO-DO 158).

## Arbitrage 2 — le core demande, le proxy dit ce qu'il a obtenu

Le port d'écoute dépend de la machine : port bas refusé à un processus qui
n'est pas root, port déjà pris, adresse qu'elle ne porte pas. Le core ne peut pas le savoir. Chaque relais demandé a donc un état,
et seul le proxy le fait avancer :

```
  demandé ──(04_18 du proxy, à la bonne révision)──▶ appliqué
                                                 └──▶ refusé (+ motif de la machine)
```

Un relais refusé n'empêche pas les autres. Une liste **entière** n'est refusée
que si elle retirerait le relais Ducky — le proxy est annoncé aux agents sur ce
port, et y laisser un port mort en ferait un trou noir — ou si le proxy ne la
comprend pas complètement. Rien ne bouge alors.

## Arbitrage 3 — une trame qui rend compte ET demande

La `04_18` est émise par le proxy : à son démarrage, après chaque application,
puis **une fois par minute**. Le core y répond **toujours** par une `04_19` :

| Mode | Quand | Suite du contenu |
|---|---|---|
| `inchange` | le proxy applique ce qu'il faut — ou a déjà refusé cette révision | `0` |
| `core` | le core pilote, et le proxy n'applique pas la bonne révision | `<révision>`, puis `{"relais":[…]}` |
| `fichier` | le core ne pilote pas, et le proxy applique encore une liste du core | `0` |

Le core émet aussi une `04_19` **de lui-même** quand un administrateur vient
d'écrire : le proxy raccordé à ce core applique dans la seconde. Les autres —
raccordés à un autre core du cluster, ou hors ligne — la reçoivent en réponse à
leur compte rendu suivant. Rien n'est mis en file : la base est la file, et la
révision dit qui est à jour.

Une révision refusée en entier n'est **pas** renvoyée : la réponse du proxy ne
changerait pas, et deux journaux se rempliraient. Le core attend que la demande
change.

## La révision

Un entier par proxy, incrémenté à **chaque** écriture dans la même transaction
que la liste. Le proxy le rapporte ; le core compare.

Il ne redescend jamais — pas même quand le core rend la main, où c'est le
drapeau `pilote` qui retombe. Remis à zéro, il redonnerait le numéro 1 à la
liste suivante, et un proxy resté hors ligne pendant l'aller-retour dirait
« appliquée » d'une liste qu'il n'a jamais reçue.

## Les documents

`04_18`, du proxy :

```json
{"v":1,"revision":4,"origine":"core","pilotage":true,"port_annonce":6666,
 "revision_refusee":0,"refus":"",
 "relais":[{"nom":"ducky","type":"ducky","ecoute":":6666",
            "cibles":{"source":"cores"},
            "delai_connexion_secondes":3,"inactivite_secondes":900,
            "max_connexions":4000,"max_par_source":20,
            "statut":"actif","ecoute_effective":"[::]:6666",
            "cibles_resolues":["10.0.0.1:6666"]}]}
```

- `origine` : `fichier` ou `core`. Toute autre valeur se lit `fichier`.
- `pilotage` : `false` quand le fichier du proxy porte
  `pilotage_par_le_core: false`. Le core refuse alors d'écrire, et le dit.
- `statut` : `actif` ou `refuse`, avec `motif`.
- Les quatre réglages sont rapportés **résolus** : le core n'a pas à connaître
  les défauts du proxy.
- Borné à 32 Ko et 32 relais. Un document illisible est ignoré, et répondu
  `inchange`.

`04_19`, du core, en mode `core` :

```json
{"relais":[{"nom":"nexus","type":"https","ecoute":":8843",
            "cibles":{"source":"service:vaultaire_nexus"},"max_connexions":200}]}
```

Les clés sont celles du fichier YAML du proxy. Un champ **inconnu** fait refuser
le document : le proxy ouvre des ports sur sa foi, et mieux vaut refuser une
liste qu'on ne comprend pas en entier que d'en appliquer la moitié reconnue.

Ces deux documents sont un **format de protocole** : le core et le proxy ne
partagent aucun code, et chacun porte un test qui fige ce qu'il lit de l'autre.

## Qui peut écrire quoi

- La `04_18` est **réservée au proxy** dans le catalogue (`core/clienttype`).
- Le **propriétaire** de la ligne vient de la session, jamais du contenu : un
  proxy ne rend compte que de lui-même.
- Le compte rendu est gardé à part de la demande (`cluster_relay_state.rapport`
  contre `cluster_relays`) : un proxy peut mentir sur son état, pas se donner
  une configuration.
- Les deux tables sont rattachées au propriétaire — l'identifiant du client —
  et non au nœud : `cluster_nodes` oublie un nœud resté hors ligne un jour, et
  sa liste de relais ne doit pas partir avec lui.

## Jamais vers un core qui ne l'annonce pas

Le core **ferme** la connexion d'un client qui émet une trame que son type n'a
pas le droit d'émettre. Pour un core d'une version antérieure, une trame
ajoutée depuis est exactement cela : un proxy mis à jour avant son core se
ferait couper à chaque compte rendu, en boucle.

Le core annonce donc ce qu'il sait faire, en queue de chaque `02_11` :

```
capacites:relais
```

Le proxy n'émet la `04_18` que vers un core qui l'annonce. La ligne est dans la
`02_11` et non dans l'accusé d'enregistrement parce qu'elle arrive à **chaque**
connexion, avant toute autre trame : un proxy qui bascule sur un autre core du
cluster, resté en arrière, le sait avant d'avoir rien émis.

Dans l'autre sens, un proxy antérieur à la 2.2 ne rend pas compte : le core ne
lui pousse rien, et refuse toute écriture avec le motif.

## Le battement refusé *(TO-DO 109)*

`handleHostHeartbeat` rendait une chaîne vide et une erreur quand le battement
ne touchait aucune ligne : rien ne partait. Le nœud, lui, avait un booléen
`enregistre` qui passait à vrai sur le `04_02` et n'en revenait jamais. Un proxy
oublié après vingt-quatre heures hors ligne battait donc dans le vide,
indéfiniment, invisible du cluster, en se croyant enregistré.

Le core répond maintenant `04_08` avec `refus` et le motif ; le nœud relève un
drapeau, et son tour de boucle suivant rejoue `04_01` au lieu de battre. Un nœud
resté à l'ancienne version range toute `04_08` dans « rien à faire » : ce refus
ne change rien pour lui.

---

[← Affinité, enrôlement par site, et ce qui reste](./03-arbitrages-et-suite.md) · [Chapitre 5 — Transport des GPO (05) →](../05-gpo/README.md)
