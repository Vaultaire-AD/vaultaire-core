[⌂ Documentation](../README.md) › [Proxy](./README.md) › Piloter les relais depuis le core

# Piloter les relais d'un proxy depuis le core

[← Relais](./relais.md) · [Sécurité →](./securite.md)

---

**Qui expose quoi** — Ducky, HTTPS, LDAPS, sur quel port, vers quelles cibles —
se lit et se change depuis le core : en commande (`vlt cluster relais`) et sur
la page **Admin → Cluster**, fiche du proxy. Le proxy applique **sans
redémarrer** : les tunnels en cours ne sont pas coupés *(TO-DO 141)*.

## En une minute

| Je veux… | Commande |
|---|---|
| voir ce qu'un proxy expose, vers quoi, et son état | `vlt cluster relais <proxy>` |
| ajouter un relais HTTPS vers les Nexus | `vlt cluster relais <proxy> set nexus --type https --ecoute :8843 --source service:vaultaire_nexus` |
| ajouter un relais LDAPS vers les cores | `vlt cluster relais <proxy> set ldaps --type ldaps --ecoute :1636` |
| changer un seul réglage | `vlt cluster relais <proxy> set nexus --max 200` |
| retirer un relais | `vlt cluster relais <proxy> remove nexus` |
| rendre la main au fichier du proxy | `vlt cluster relais <proxy> release` |

Droits : `read:cluster` pour voir, **`write:relay`** pour changer.

## Où vit la vérité

```
            le core n'a rien décidé              le core a une liste
            ───────────────────────              ───────────────────
  proxy     applique son fichier (relais:)       applique la liste du core
  core      affiche ce que le proxy rapporte     demande, et affiche l'état
```

- **Tant que le core n'a rien décidé** pour un proxy, celui-ci applique la
  section `relais:` de son fichier, comme avant, et **rend compte** : c'est ce
  que montrent la commande et la page, avec l'état « du fichier ».
- **La première modification prend la main.** Le core repart de ce que le proxy
  fait tourner — ajouter un relais ne retire donc pas ceux du fichier — et sa
  liste fait foi ensuite. Le fichier n'est plus lu.
- **`release` rend la main** : le proxy referme ce que le core avait posé et
  réapplique son fichier.
- **Le proxy garde une copie** de la dernière liste reçue, à côté de son
  identité (`relais_du_core.json`). À son redémarrage, il la rouvre telle
  quelle, sans repasser par son fichier.

> **Sans aucun core joignable** *(2.3, TO-DO 158)*. Le proxy rouvre ses relais
> **d'abord** — depuis cette copie, ou depuis son fichier s'il n'en a pas —, puis
> attend le core en fond, sans limite. Ses relais vers des cibles locales
> relaient ; son relais Ducky écoute et refuse franchement, et l'agent passe au
> nœud suivant. Il s'arrêtait au bout de trente secondes sans avoir ouvert un
> port. Le journal dit ce qui manque : `aucun core joint depuis 30s : N relais
> reste(nt) ouvert(s)…`, puis un rappel toutes les cinq minutes. Dès qu'un core
> répond, le proxy s'annonce au cluster de lui-même.
>
> Deux choses ne changent pas : un **premier** démarrage demande un core (sans
> identité, le proxy doit s'enrôler), et un relais du fichier qui ne peut pas
> écouter arrête le proxy.

## Demandé, appliqué, refusé

Le core **demande** ; seul le proxy sait s'il a **obtenu**. Un port est peut-être
déjà pris sur la machine, l'adresse demandée n'est pas la sienne, ou le proxy
tourne sans le droit d'ouvrir un port bas (il n'est pas root : UID 10001 dans le
conteneur `vlt-proxy`).

| État | Ce que cela veut dire |
|---|---|
| **demandé** | le core le veut, le proxy n'a pas encore dit ce qu'il en est |
| **appliqué** | le proxy l'a ouvert, avec cette configuration |
| **refusé** | le proxy ne peut pas ; le motif est celui de sa machine |
| **du fichier** | le core ne pilote pas ce proxy ; le relais vient de son fichier |

```
$ vlt cluster relais proxy1
Relais de proxy1

  révision 4 appliquée par le proxy
  Dernière modification : root, le 2026-10-06 18:34:33
  Dernier compte rendu du proxy : à 18:34:33

Demandés par le core

ÉTAT      RELAIS  TYPE   ÉCOUTE         SOURCE DES CIBLES               CIBLES            ACT./TOTAL  TRAFIC
appliqué  ducky   ducky  0.0.0.0:6666   les cores du cluster            10.0.0.1:6666     12/90       1,4 Gio
appliqué  nexus   https  0.0.0.0:8843   les services « vaultaire_nexus » 10.0.0.9:8443    0/3         3,9 Kio
refusé    web     https  :9443          liste fixe : 10.0.0.20:443      —                 —           —
  web : relais web : écoute sur :9443 impossible : listen tcp :9443: bind: address already in use
```

- **CIBLES** est ce que le proxy essaierait *maintenant* : pour une source
  `cores` ou `service:`, ce sont les adresses apprises du cluster, et non ce qui
  est écrit dans la configuration.
- **Révision** : chaque écriture en prend une. C'est elle que le proxy rapporte ;
  tant qu'il n'a pas rendu compte de la bonne, les relais sont « demandés » et
  un second tableau montre ce qui tourne **en ce moment**.
- Un relais refusé **n'empêche pas les autres** de tourner. Un relais déjà en
  service dont la nouvelle version est refusée **reste en service** dans son
  ancienne version, et le motif le dit.

### Délais

Le core envoie la liste au proxy dès l'écriture, s'il est raccordé à **ce** core :
l'état passe à « appliqué » dans la seconde. Un proxy raccordé à un autre core du
cluster, ou hors ligne, la reçoit à son prochain **compte rendu** — un par
minute. Rien n'est mis en file : la base est la file.

## Ce qui se change, et ce qui ne se change pas

| | |
|---|---|
| cibles, plafonds, délais, type | changés **en place** : le port reste ouvert, les compteurs sont gardés, la connexion suivante prend le nouveau réglage |
| adresse ou port d'écoute | le nouveau port est ouvert d'abord ; l'ancien n'est fermé que si le nouveau est obtenu |
| un relais retiré | cesse d'écouter ; ses connexions en cours vont à leur terme |
| le relais **Ducky** | ne se retire pas et ne change pas de port : c'est le port que le proxy a annoncé au cluster (`-listen-port`), celui que reçoivent les agents. Ses cibles et ses plafonds se règlent |
| **LDAP en clair** | refusé, comme dans le fichier ([pourquoi](./https-et-ldaps.md)) |

Pour sortir un proxy du service sans toucher à ses relais :
`vlt cluster rotation <proxy> out`.

> **En conteneur, un port ouvert n'est pas un port joignable.** Le relais écoute
> DANS le conteneur ; le site ne l'atteint que si ce port est **publié** par
> `docker-compose.yml` (`ports:`). Le core ne le voit pas : un relais
> « appliqué » sur un port non publié tourne, et personne n'y arrive. Publier le
> port demande de recréer le conteneur — c'est la seule partie d'un ajout de
> relais qui se fait encore sur la machine.

## Options de `set`

Sur un relais **qui existe**, une option qu'on ne donne pas ne change pas. Les
noms suivent les clés du fichier YAML.

| Option | Valeur | Défaut à la création |
|---|---|---|
| `--type` | `ducky`, `https`, `ldaps` | obligatoire |
| `--ecoute` | `[adresse]:port` | `:443` (https), `:636` (ldaps) |
| `--source` | `cores`, `liste`, `service:<type>` | `cores` (ldaps) ; obligatoire en https |
| `--adresses` | `hôte:port,hôte:port` | pour `--source liste` |
| `--port-cible` | port à joindre sur les cores | 636 en ldaps |
| `--delai` | secondes pour joindre une cible | 3 |
| `--inactivite` | secondes de silence avant fermeture | 900 |
| `--max` | connexions simultanées | 4000 |
| `--max-par-source` | connexions par adresse cliente | 20 |

Zéro, pour les quatre derniers, veut dire « le défaut du proxy ».

## Un proxy qui garde la main

```yaml
# config.yaml du proxy
pilotage_par_le_core: false
```

Le proxy continue de **rendre compte** : le core affiche tout. Il **refuse** toute
liste, et la commande comme la page le disent — « ce proxy garde la main ». À
employer quand ce qu'une machine expose doit rester décidé par qui l'administre.
La ligne se lit au démarrage du proxy.

## Sécurité

- Changer les relais d'un proxy **déplace un point d'entrée du réseau**. La clé
  `write:relay` est distincte de `write:cluster`, s'accorde sur `*` seulement
  (un proxy n'appartient à aucun domaine), et n'est donnée à personne tant qu'on
  ne la donne pas — sauf au groupe d'amorçage.
- Chaque écriture laisse une ligne `SECURITY` dans le journal du core, avec
  l'état **avant** et l'état **après**.
- Le proxy contrôle tout ce qu'il reçoit comme il contrôle son fichier, et
  refuse **en entier** une liste qui retirerait son relais Ducky ou qu'il ne
  comprend pas complètement. Rien ne bouge alors, et le core l'affiche.
- Un proxy ne peut pas, par son compte rendu, changer ce qu'on lui demande : il
  peut mentir sur son état, pas se donner une configuration.

Détail : [`securite.md`](./securite.md#le-pilotage-par-le-core).

## Versions

Le pilotage demande un core **et** un proxy en 2.2. Un proxy plus ancien ne rend
pas compte : la fiche garde ses compteurs seuls, et toute écriture est refusée
avec le motif. Un proxy 2.2 raccordé à un core plus ancien n'émet rien de
nouveau — il se comporte comme avant.

---

[← Relais](./relais.md) · [Sécurité →](./securite.md)
