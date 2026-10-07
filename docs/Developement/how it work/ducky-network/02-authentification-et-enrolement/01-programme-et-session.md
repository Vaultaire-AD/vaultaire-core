[⌂ Ducky Network](../README.md) › [Chapitre 2 — Authentification et enrôlement (01, 02)](./README.md) › 2.1

# 2.1 — Authentifier le programme et ouvrir la session

[← Sommaire du chapitre](./README.md) · [Enrôlement d'un client service (01_05 à 01_09) →](./02-enrolement-service.md)

---

Dans les tableaux de ce dossier, la colonne **Reçue par** désigne la partie qui
**reçoit** la trame, pas celle qui l'envoie.

## Catégorie 01 — authentification du serveur et enrôlement

| Trame | Reçue par | Nom | Rôle |
|---|---|---|---|
| `01_01` | core | ask server auth | le client ouvre la poignée de main ; le core lie la session à la machine et à son type |
| `01_02` | client | server proof of work | le core prouve son identité et transmet la clé de session, chiffrée pour la clé publique de CETTE machine |
| `01_05` | core | enroll_request | un service présente sa clé d'enrôlement et une clé temporaire |
| `01_06` | client | enroll_ok | le core crée le client et renvoie son identifiant et son type |
| `01_07` | core | enroll_pubkey | le service envoie sa clé publique, sous la clé temporaire |
| `01_08` | client | enroll_confirmed | accusé chiffré pour la clé publique du service (preuve de possession) |
| `01_09` | client | enroll_denied | refus, en clair |

La réponse `01_02` est chiffrée avec la clé publique de l'identifiant annoncé :
un client qui annonce la machine d'un autre ne peut pas la lire, n'obtient pas la
clé de session, et aucune de ses trames suivantes n'est lisible. La possession
est prouvée par construction.

L'enrôlement a sa page : [2.2](./02-enrolement-service.md).

## Catégorie 02 — session du compte de programme

| Trame | Reçue par | Nom | Rôle |
|---|---|---|---|
| `02_01` | core | ask auth | le programme demande à s'authentifier sous le compte de service |
| `02_02` | client | proof of work | défi du core |
| `02_03` | core | check auth | réponse au défi ; en cas de succès la session devient **sûre** |
| `02_04` | client | auth_success | succès |
| `02_05` | core | close session | fermeture de session (déconnexion) |
| `02_07` | client | failed | échec de l'authentification : le compte, puis le motif. **Ferme la session qu'il refuse** |
| `02_11` | client | ask_information | le core demande l'inventaire (nom, versions…). En queue, depuis la 2.2 : `online:<minutes>` — la cadence de ce battement — et `capacites:<liste>` — ce que ce core sait faire |
| `02_12` | core | serveur_information | inventaire d'un programme (services, agents) |
| `02_13` | core | client_information | réservée — jamais émise |

**`02_12` est indispensable à tous les types** : le core répond `02_11` à tout
programme qui s'authentifie sous le compte de service et attend l'inventaire en
retour. Un type qui ne peut pas émettre `02_12` voit sa connexion fermée juste
après l'authentification (`TestSocleDeConnexionCommun`).

> Ces deux catégories authentifient le **programme**. Vérifier le mot de passe
> d'une **personne** se fait en `03_01` (ouverture de session sur une machine) ou
> en `08_01` (pour le compte d'un service).

### Le refus `02_07`, et ce qu'il ferme

*(2.3, TO-DO 159.)* Une seule forme, composée par une seule fonction du core
(`authentification/client/refus.go`, `Refus`) :

```
02_07
serveur_central
<clé d'intégrité>
<compte>            « - » quand le core n'en connaît aucun
<motif>
```

Le poste lisait deux lignes de contenu — le compte, puis le motif — et **neuf
des onze refus du core n'en portaient qu'une**. La lecture sortait du tableau,
le traitement paniquait, et la boucle de réception récupérait la panique en
fermant la connexion : le journal du poste portait « index out of range » là où
il devait porter le motif, et la fermeture d'une session refusée n'était
décidée nulle part — c'était un effet de bord.

| | Règle |
|---|---|
| **Le poste lit toute forme** (`userauth.LireRefus`) | deux lignes ou plus : compte, puis motif. Une ligne : c'est le **motif** — la forme d'un core antérieur. Rien : un motif par défaut |
| **Le refus ferme, par décision** | il pose le motif sur la session (`DuckySession.Refus`) ; `MessageReader` rend `ErrSessionRefusee`, et les boucles de réception s'arrêtent déjà sur toute erreur de cette fonction |
| **Le core ferme aussi** (`DoitFermerApresRefus`) | une fois le refus parti. Un agent antérieur, qui lit sans paniquer les refus d'un core à jour, ne fermerait plus rien : le comportement ne dépend plus de la version d'en face |
| **Jamais une session authentifiée** | un core antérieur émet un `02_07` **dans le tunnel** d'une machine, sur une `03_01` malformée. Fermer ce tunnel couperait la machine : le refus est journalisé, la session reste. Le core à jour répond `03_03` dans ce cas, dès que le compte est lisible |
| **Un refus ne remet pas le délai à zéro** (`userauth.DelaiDeReprise`) | la reconnexion repartait du délai le plus court dès que la **connexion** aboutissait, avant de savoir si le core accepterait : un programme refusé revenait toutes les deux secondes, sans fin, chaque essai coûtant au core une poignée de main RSA. Le délai continue de doubler tant que la session est refusée |

**Qui reçoit un `02_07`.** Pas une personne qui se connecte : PAM passe par
`03_01` dans le tunnel, et son refus est un `03_03`. C'est le **tunnel** d'une
machine et les **services** (proxy, Nexus) — sur un défi inconnu ou expiré, ou
une réponse fausse.

**Le motif n'est pas un oracle.** Le compte renvoyé est celui que la trame
annonçait ; le motif reste `Wrong login Data` pour un compte inconnu, un mot de
passe faux, un compte révoqué ou trop de tentatives. `Password expired…` n'est
rendu qu'après un mot de passe prouvé. Une sentinelle interdit de recomposer un
`02_07` à la main dans ce paquet.

Les quatre combinaisons de versions ont été essayées sur le banc : core à jour
et agent antérieur — plus de panique, le motif se lit, le core ferme, la cadence
reste à 2 s ; core antérieur et agent à jour — le motif se lit, l'agent ferme et
espace ses essais.

### Le tunnel machine, et ce qui le ferme

Un agent tient **une** session `vaultaire` : le tunnel machine. Les
authentifications PAM (`03_01`) passent **dedans** — aucune session Ducky n'est
ouverte au nom d'une personne. Trois règles en découlent :

- **Une déconnexion PAM ne ferme rien.** L'agent n'envoie pas de `02_05` quand
  un utilisateur se déconnecte. Une version le faisait sur le tunnel machine :
  la trame était mal formée, le core la rejetait comme usurpation et coupait la
  connexion, et la machine disparaissait de `status -c`.
- **Le tunnel est supervisé.** Il s'ouvre au démarrage de l'agent, sur un poste
  comme sur un serveur, et se rouvre après toute coupure, avec un délai
  croissant (2 s à 5 min) ; une seule supervision par processus
  (`serveur_communication/superviseur.go`).
- **`02_05` ferme la connexion qui la porte**, et efface la ligne `did_login`
  du couple (compte, machine) — sauf si un **autre** tunnel authentifié de la
  même machine est encore ouvert. C'est le cas du `--fetch-key` de sshd, qui
  ouvre une connexion éphémère à chaque connexion SSH : en se fermant, il
  effaçait la ligne du tunnel principal.

Le battement `02_12` du tunnel machine **recrée** au besoin sa ligne
`did_login`, avec sa propre clé : un tunnel vivant est toujours listé par
`status -c`. Le nettoyage périodique n'efface que les lignes **expirées** — il
effaçait toutes celles du compte dès qu'une expirait, donc tout le parc, puisque
chaque tunnel est connecté sous `vaultaire`.

---

[← Sommaire du chapitre](./README.md) · [Enrôlement d'un client service (01_05 à 01_09) →](./02-enrolement-service.md)
