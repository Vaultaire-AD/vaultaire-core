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
| `Unite` | `s`, `min` ou `h`. La base stocke un **entier dans cette unité** |
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

Les durées de l'**agent** non plus — `MachineRefreshInterval`, les délais de
commande GPO. Elles vivent sur la machine du parc et n'ont aucun moyen d'être
lues depuis le core. Elles relèvent des GPO.

---

## 7. Ajouter une durée

1. une entrée dans `catalogue`, avec sa `Consequence` ;
2. une constante `CleXxx` à côté des autres ;
3. remplacer le `time.NewTicker` par `reglages.Boucle` ;
4. rien d'autre — l'action, la commande et la page web parcourent le catalogue.

Le point 4 est l'intérêt du dispositif : les trois façades n'énumèrent aucun
réglage. Ajouter une durée ne demande pas de les toucher, donc ne peut pas les
faire diverger.

---

## 8. Le contrôle d'accès

| | |
|---|---|
| lire | `read:log` — « puis-je regarder comment ce serveur est réglé » |
| écrire | `write:server` — la même clé que le mode debug et la purge des sessions |

`read:log` plutôt qu'un `read:server` neuf : créer une clé pour deux actions
l'ajouterait à accorder dans toutes les permissions existantes, donc un droit qui
manque partout jusqu'à ce que quelqu'un s'en aperçoive.

Les deux sont exigés **séparément**, et le bouton n'apparaît pas sans le second.
Une page qui montrerait des champs modifiables refusés à la soumission ferait
perdre du temps sans dire lequel manque.

---

## Voir aussi

| | |
|---|---|
| Le registre d'actions | [`Actions.md`](./Actions.md) |
| Ce que le serveur journalise | [`Journalisation.md`](./Journalisation.md) |
| La commande `settings` | [`MAN.md`](../../Utilisation/MAN.md) |
