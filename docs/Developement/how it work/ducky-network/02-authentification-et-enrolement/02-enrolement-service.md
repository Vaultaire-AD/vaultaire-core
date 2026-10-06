[⌂ Ducky Network](../README.md) › [Chapitre 2 — Authentification et enrôlement (01, 02)](./README.md) › 2.2

# 2.2 — Enrôlement d'un client service (01_05 à 01_09)

[← Authentifier le programme et ouvrir la session](./01-programme-et-session.md) · [Chapitre 3 — Poste de travail : SSH, PAM et groupes (03) →](../03-ssh-et-groupes/README.md)

---


L'enrôlement précède l'existence du client : il n'y a ni session, ni identifiant
machine, ni type. Il ne peut donc pas être soumis au contrôle par type de client
— c'est la **clé d'enrôlement** qui autorise la trame, et c'est **son type à
elle** qui décide de ce que le client pourra émettre ensuite.

## Ce que la clé porte, et ce que le client ne choisit pas

La clé d'enrôlement est émise par le core avec un **type**, une **expiration** et
un **quota d'utilisations**. Le client ne déclare donc pas son type : il le
reçoit.

C'est le point de sécurité central de ce flux. Si le client annonçait son type,
n'importe quel service enrôlé pourrait se déclarer `vaultaire_web` et obtenir
`AssertsUser`, c'est-à-dire le droit d'agir au nom de n'importe quel utilisateur.
Le type vient de la clé, la clé vient d'un administrateur : le service n'a aucune
prise sur ses propres privilèges.

## Pourquoi une clé de session temporaire

Une clé publique RSA-4096 pèse environ **800 octets** en PEM, **1116** une fois
en base64 dans une trame. Une charge RSA-OAEP sur clé 4096 en accepte **446**.

Elle ne peut donc pas voyager dans une enveloppe asymétrique, et **aucun encodage
n'y change rien** : même `base64(DER)` d'une clé 2048, la forme la plus compacte
possible, fait 499 octets. Le problème est que la charge utile d'une enveloppe
RSA est plus petite que la clé qu'on veut y mettre.

La clé temporaire tient sans peine en RSA — 32 octets — et ouvre un canal
symétrique qui n'a plus de limite de taille. C'est le mécanisme de `01_02`,
avancé d'un cran pour servir avant même que le client existe.

## Séquence

```
service                                          core
  |-- askkey (non authentifié) ----------------->  |
  |<-- clé publique du core ----------------------  |
  |
  |-- 01_05 clé d'enrôlement + clé TMP --------->  |  valide la clé, crée le client
  |                                                |  (sans clé publique pour l'instant)
  |<-- 01_06 identifiant + type -----------------  |  AES-GCM, clé TMP
  |
  |   écrit client_software.yaml                  |
  |   génère sa paire RSA-4096 localement         |
  |
  |-- 01_07 sa clé publique -------------------->  |  AES-GCM, clé TMP
  |<-- 01_08 ok ---------------------------------  |  RSA, clé publique du service
  |
  |   la connexion se ferme                       |
  |   ... puis 01_01 / 01_02 sur une connexion neuve ...
```

**La preuve de possession est gratuite.** `01_08` est chiffrée avec la clé
publique enregistrée en `01_07` : seul le détenteur de la privée correspondante
peut la lire. Un service qui aurait soumis une clé qu'il ne possède pas le
découvre immédiatement, au lieu d'échouer à la première poignée de main d'une
session ultérieure.

**La connexion est jetable.** Elle a servi à l'enrôlement et n'est pas une
session : ni machine liée, ni type. La laisser ouverte donnerait un canal chiffré
dans l'état que le fail-closed du Spliter existe précisément pour ne pas laisser
traîner.

## Format des trames

### 01_05 — enroll_request (client → serveur)

Chiffrée avec la clé publique du serveur, comme `01_01`.

```
01_05
serveur_central
-
-
-
<clé_enrôlement>
<clé_session_temporaire_base64>    32 octets, AES-256
<libellé>
```

Les trois champs d'en-tête sont vides : il n'y a ni session, ni utilisateur, ni
identifiant machine à ce stade. Le `libellé` est une chaîne libre destinée aux
journaux et à l'affichage (« proxy-preprod-01 ») ; il n'a aucune valeur de
sécurité et n'entre dans aucune décision.

La clé temporaire est **validée avant** que la clé d'enrôlement ne soit
consommée : une clé mal formée ne doit pas coûter un jeton à l'administrateur qui
l'a émis.

### 01_06 — enroll_ok (serveur → client)

Chiffrée en **AES-GCM avec la clé temporaire**. La bascule se fait des deux côtés
dès l'envoi de `01_05` : le core répond déjà sous ce régime.

```
01_06
<destination>
-
<computeur_id_attribué>
<type_de_client>
```

Le client existe alors en base **sans clé publique** — elle vient en `01_07`.
Cet état est inerte : un client sans clé publique ne peut rien faire, puisque la
poignée de main `01_02` lui répondrait un chiffré que personne ne sait lire.

### 01_07 — enroll_pubkey (client → serveur)

Chiffrée en **AES-GCM avec la clé temporaire**.

```
01_07
serveur_central
-
-
<computeur_id>
<clé_publique_pem_base64>
```

L'identifiant est repris de la **session**, jamais de la trame, côté serveur. Le
lire dans la trame laisserait quiconque a passé un enrôlement écraser la clé
publique d'un autre client, donc prendre sa place.

### 01_08 — enroll_confirmed (serveur → client)

Chiffrée avec la **clé publique qui vient d'être enregistrée**.

```
01_08
<destination>
-
ok
```

Le serveur ferme la connexion juste après.

### 01_09 — enroll_denied (serveur → client)

En clair, puis fermeture. Le serveur n'a rien pour chiffrer : pas de clé publique
du client, et pas de clé temporaire utilisable si c'est justement elle qui était
malformée. Le refus ne contient aucun secret.

| Code journalisé | Sens |
|---|---|
| `unknown_key` | clé inconnue |
| `expired_key` | date d'expiration dépassée |
| `exhausted_key` | quota d'utilisations atteint |
| `revoked_key` | clé révoquée |
| `unknown_type` | le type porté par la clé n'est plus au catalogue |
| `bad_public_key` | clé publique illisible ou trop faible |
| `invalid_request` | trame malformée, ou clé temporaire de taille inattendue |

**Les cinq premiers sont distincts dans les journaux mais indistincts pour le
client**, qui reçoit `invalid_key` dans les cinq cas. Une réponse détaillée
transformerait le point d'enrôlement en oracle : un attaquant apprendrait qu'une
clé existe mais est expirée, donc qu'elle a existé, donc que le format est le
bon. Le journal serveur, lui, porte la vraie raison.

**Numérotation : 01_01, 01_02, puis 01_05 à 01_09. Libre à partir de 01_10.**

## Traçabilité

Chaque consommation écrit une ligne dans `service_enrollment_use` :
identifiant de clé, `computeur_id` créé, adresse source, horodatage.

Sans cette table, on ne peut pas répondre à « quels services sont entrés par cette
clé ? » le jour où l'on découvre qu'elle a fuité — et c'est précisément le jour où
la question se pose.

---

[← Authentifier le programme et ouvrir la session](./01-programme-et-session.md) · [Chapitre 3 — Poste de travail : SSH, PAM et groupes (03) →](../03-ssh-et-groupes/README.md)
