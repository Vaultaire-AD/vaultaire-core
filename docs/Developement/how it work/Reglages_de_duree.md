# Durées d'exploitation — `core/reglages`

> **Public : développeurs.** Comment une période de boucle est déclarée, lue et
> changée. Pour la commande, voir [`MAN.md`](../../Utilisation/MAN.md) § settings.

---

## 1. La règle

> **Le défaut est en Go, la valeur courante est en base, et la base l'emporte.**

Le défaut en Go plutôt qu'en base : une base neuve, vide ou injoignable doit
donner un serveur qui tourne. Un défaut en base serait une ligne à insérer à la
création, donc une migration à écrire, et une installation qui l'aurait manquée
démarrerait avec des périodes nulles.

La base plutôt que le fichier : le fichier impose un redémarrage, et un
redémarrage de core coupe le parc. Un réglage de cadence ne vaut pas ça.

---

## 2. Ce qu'il y avait avant

Les périodes étaient dispersées :

- une dans le YAML — `servercheckonlinetimer` ;
- les autres écrites en dur dans le `time.NewTicker` de chaque boucle.

Deux mécanismes pour la même question, aucun consultable, et rien qui dise
quelles durées existent. Changer la cadence du balayage du cluster demandait de
modifier le code et de recompiler ; changer celle de la vérification en ligne
demandait d'éditer un fichier et de redémarrer.

---

## 3. Déclarer une durée

Tout est dans `catalogue`, une seule liste :

```go
{
    Cle: CleVerificationEnLigne, Unite: Minutes, Defaut: 2, Min: 1, Max: 60,
    Libelle: "Vérification des machines en ligne",
    Consequence: "Le core envoie un 02_11 à chaque machine à cette cadence. …",
},
```

| Champ | Rôle |
|---|---|
| `Cle` | l'identifiant en base et en ligne de commande |
| `Unite` | `s`, `min`, `h` ou `j`. La base stocke un **entier dans cette unité** |
| `Defaut` | la valeur si la base ne dit rien |
| `Min`, `Max` | garde-fous de **saisie** |
| `Libelle` | ce que la durée gouverne, en une ligne |
| `Consequence` | ce que change une valeur trop basse ou trop haute |

**L'unité plutôt que des secondes partout** : « 24 » heures se lit et se saisit,
« 86400 » se recopie de travers. L'unité est celle dans laquelle un exploitant
pense au réglage.

**`Consequence` est obligatoire**, et un test le vérifie. Qui règle une cadence
sans savoir ce qu'elle coûte choisit au hasard — et le symptôme apparaît
ailleurs, plus tard.

**Les bornes ne sont pas des limites de sécurité** mais des garde-fous de saisie.
Une valeur absurde — un horodatage collé dans le champ — mettrait une boucle en
sommeil pour des années sans le dire, alors qu'un refus explicite se voit.

---

## 4. Écrire une boucle

```go
go reglages.Boucle(reglages.CleBalayageServices, func() {
    // le travail périodique
})
```

**Pas un `time.Ticker`.** Un ticker lit sa période **une fois**, à la création :
changer le réglage n'aurait alors aucun effet avant un redémarrage du core.

Pire, rien ne le dirait. L'exploitant verrait sa nouvelle valeur en base et dans
l'interface, et le comportement resterait l'ancien. **Un réglage qui s'affiche
sans agir est plus trompeur que pas de réglage du tout.**

`Boucle` relit la période à chaque tour. Elle passe par le cache du paquet, qui
la garde trente secondes : le changement prend effet au tour suivant, sans
interroger la base à chaque fois.

Le premier tour **attend** : toutes ces boucles sont des balayages, et les lancer
au démarrage ferait travailler le core au moment où il a le plus à faire, sur des
tables encore vides.

---

## 5. Le cache

Trente secondes, la même valeur que le cache de la politique de mot de passe —
pour ne pas avoir deux fraîcheurs différentes à expliquer.

- **Sans cache**, la boucle de battement du cluster interrogerait la base toutes
  les trente secondes, pour un réglage qui change une fois par an.
- **Avec un cache long**, « ça ne marche pas » deviendrait « attendez ». Un
  exploitant qui modifie un réglage veut le voir agir, pas se demander s'il a mal
  saisi.

L'écriture invalide l'entrée **immédiatement et localement**. Sur un cluster, les
autres cores gardent leur valeur jusqu'à l'expiration de leur propre cache :
trente secondes de désaccord sur une cadence, sans conséquence.

---

## 6. Ce qui n'est PAS réglable, et pourquoi

Les délais de **protocole** et de **sécurité** restent des constantes du code :

| | |
|---|---|
| `netguard.HandshakeReadTimeout`, `SessionReadTimeout` | échéances de lecture réseau |
| `replayWindow` | fenêtre anti-rejeu de l'API |
| `DureeDeVieDefi` | durée de vie d'un défi d'authentification |
| barème de `core/auth/ratelimit` | limitation de débit |

Ce ne sont pas des préférences d'exploitation mais des **propriétés du
protocole** : une échéance de poignée de main trop longue ouvre un déni de
service, trop courte casse les connexions lentes. Les exposer inviterait à les
régler sans savoir ce qu'on règle, et le symptôme d'un mauvais choix
apparaîtrait ailleurs, longtemps après.

---

## 6 bis. Une durée qui pilote une boucle de l'AGENT

Ce paragraphe disait, jusqu'au réglage `gpo_refresh_minutes` : « les durées de
l'agent ne sont pas réglables, elles vivent sur la machine du parc et n'ont
aucun moyen d'être lues depuis le core ». C'était vrai du mécanisme, pas du
besoin — un parc dont on ne peut pas resserrer la cadence pendant un
déploiement se rafraîchit à l'heure, quoi qu'il arrive.

La recette, éprouvée d'abord par `group_sync_minutes` :

1. le réglage est déclaré ici, dans `catalogue`, comme n'importe quelle durée ;
2. sa valeur est **ajoutée en queue** d'une trame que l'agent reçoit déjà, sur
   une ligne **préfixée** — `sync:` en `03_09`, `refresh:` en `05_02`/`05_03` ;
3. l'agent la lit **par son préfixe, jamais par son rang**, la **borne**, et
   réarme sa boucle.

Chacun de ces trois points paye une dette précise :

- **en queue** : un agent d'une version antérieure lit les champs qu'il connaît
  et ignore le reste ; un core d'une version antérieure n'envoie rien et l'agent
  garde son défaut. Aucune des deux moitiés du parc n'a besoin de l'autre ;
- **par le préfixe** : un champ ajouté plus tard ne déplace pas celui-ci. Lire à
  un rang fixe, c'est se promettre de ne plus jamais toucher au format ;
- **bornée côté agent** : la valeur vient du réseau et pilote une boucle
  infinie. Une cadence à zéro transformerait l'agent en attente active, et une
  cadence d'un mois le ferait disparaître du parc sans que rien ne le signale.

**La valeur n'est pas persistée sur l'agent.** Il repart de son défaut au
démarrage, mais son premier cycle est immédiat et la réponse porte la cadence :
la fenêtre dure un aller-retour. Un fichier de plus à écrire, migrer et protéger
pour couvrir quelques secondes n'en valait pas le prix.

**Le core doit lire le même réglage que celui qu'il envoie.** `gpo status`
juge une machine « en retard » après trois cycles manqués : cette tolérance est
calculée depuis le réglage (`dbgpo.CadenceAgent`, posée au démarrage du core),
pas depuis une constante. Une constante de plus aurait fait mentir la colonne
SUIVI dès le premier changement de cadence — le défaut exact que ce dispositif
existe pour éviter.

Restent hors de portée les durées que l'agent est **seul** à connaître : délais
d'attente d'une réponse, budget d'un cycle utilisateur sur le chemin de
connexion. Elles relèvent des GPO.

---

## 7. Ajouter une durée

1. une entrée dans `catalogue`, avec sa `Consequence` ;
2. une constante `CleXxx` à côté des autres ;
3. remplacer le `time.NewTicker` par `reglages.Boucle` ;
4. rien d'autre — l'action, la commande et la page web parcourent le catalogue.

**Une rétention n'est pas une cadence, mais elle entre ici.** `log_retention_days`
(TO-DO 91) ne pilote aucune boucle : c'est l'âge au-delà duquel la purge du
journal commun supprime une ligne. Elle est au catalogue pour hériter de ce
qu'il apporte — bornes, conséquence affichée, façades sans code — et c'est
pour elle que l'unité `j` existe : une rétention se pense en jours. Sa purge,
elle, est une boucle ordinaire (`log_purge_hours`).

Le point 4 est l'intérêt du dispositif : les trois façades n'énumèrent aucun
réglage. Ajouter une durée ne demande pas de les toucher, donc ne peut pas les
faire diverger.

---

## 8. Le contrôle d'accès

| | |
|---|---|
| lire | `read:log` — « puis-je regarder comment ce serveur est réglé » |
| écrire | `write:server` — la même clé que le mode debug et la purge des sessions |

`read:log` plutôt qu'un `read:server` neuf : créer une clé pour trois actions
l'ajouterait à accorder dans toutes les permissions existantes, donc un droit qui
manque partout jusqu'à ce que quelqu'un s'en aperçoive.

Les trois actions du catalogue portent ces clés :

| Action | Clé | Portée |
|---|---|---|
| `settings.list` | `read:log` | Globale, `FiltreInutile` |
| `settings.set` | `write:server` | Globale |
| `settings.reset` | `write:server` | Globale |

**Les deux clés sont des actions SPÉCIALES**, donc des booléens : `all` ou rien.
Une durée d'exploitation n'appartient à aucun domaine — il n'y a rien selon quoi
restreindre, et leur donner une liste de domaines ne les limite pas, elle les
refuse. Voir `specialActions` dans `core/permission/isValidAction.go`.

Les deux sont exigés **séparément**. `/admin/settings` s'ouvre avec `read:log`
seul, en lecture seule : les valeurs s'affichent, les champs de saisie non. Une
page qui montrerait des champs modifiables refusés à la soumission ferait perdre
du temps sans dire lequel manque.

Le droit d'écriture est porté **par ligne** (`reglageVue.Modifiable`) et non par
page : le gabarit n'a pas à refaire le raisonnement. Masquer un champ n'est de
toute façon pas un contrôle — c'est l'action `settings.set` qui refuse, comme en
ligne de commande.

---

## Voir aussi

| | |
|---|---|
| Le registre d'actions | [`Actions.md`](./Actions.md) |
| Ce que le serveur journalise | [`Journalisation.md`](./Journalisation.md) |
| La commande `settings` | [`MAN.md`](../../Utilisation/MAN.md) |
