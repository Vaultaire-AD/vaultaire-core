[⌂ Ducky Network](../README.md) › [Chapitre 5 — Transport des GPO (05)](./README.md) › 5.1

# 5.1 — Principe, numérotation et séquence

[← Sommaire du chapitre](./README.md) · [Les trames 05_01 à 05_18 →](./02-trames.md)

---

| Trame | Reçue par | Nom | Rôle |
|---|---|---|---|
| `05_01` | core | ask_gpo_machine | GPO machine, avec l'empreinte déjà appliquée |
| `05_02` | client | gpo_machine_manifest | version, empreinte, découpage |
| `05_03` | client | gpo_machine_unchanged | rien à appliquer |
| `05_04` | client | gpo_machine_error | erreur |
| `05_05` | core | ask_gpo_user | GPO user, après authentification — seules celles des groupes communs à la machine ET au compte |
| `05_06` | client | gpo_user_manifest | version, empreinte, découpage |
| `05_07` | client | gpo_user_unchanged | rien à appliquer |
| `05_08` | client | gpo_user_error | erreur |
| `05_09` | core | ask_gpo_chunk | un fragment de la politique annoncée |
| `05_10` | client | gpo_chunk | le fragment |
| `05_11` | client | gpo_chunk_error | empreinte périmée, index invalide, transfert inconnu |
| `05_12` | core | gpo_apply_report | résultat de l'application, module par module |
| `05_13` | client | gpo_apply_report_ack | accusé |
| `05_14` | client | gpo_apply_report_error | rapport malformé ou empreinte inconnue |
| `05_15` | core | gpo_drift_report | résultat d'un scan de conformité |
| `05_16` | client | gpo_drift_report_ack | accusé |
| `05_17` | client | gpo_drift_report_error | rapport malformé ou non enregistré |
| `05_18` | **client** | gpo_refresh_now | « rafraîchis maintenant » — poussée par le core, hors du tour |

Plage utilisée : `05_01` à `05_18`. Le mécanisme côté serveur et client est
décrit dans [`GPO.md`](../../GPO.md).

---


> **Statut : proposition v2, en attente de validation.** Réordonnée pour que chaque
> demande soit immédiatement suivie de ses réponses (succès, puis cas « rien à
> faire », puis erreur). Aucune implémentation avant accord.

## Règle de numérotation appliquée

Une demande et ses réponses possibles sont contiguës. Le **numéro de trame porte
donc le scope** pour tout ce qui est spécifique à un scope, ce qui évite de
répéter l'information dans le contenu — une information dupliquée finit toujours
par diverger.

```
05_01  demande machine
  05_02  réponse : manifeste
  05_03  réponse : rien à faire
  05_04  réponse : erreur

05_05  demande user
  05_06  réponse : manifeste
  05_07  réponse : rien à faire
  05_08  réponse : erreur

05_09  demande de fragment            (partagée entre les deux scopes)
  05_10  réponse : fragment
  05_11  réponse : erreur

05_12  rapport d'application           (partagé entre les deux scopes)
  05_13  réponse : accusé
  05_14  réponse : erreur

05_15  rapport de conformité          (partagé entre les deux scopes)
  05_16  réponse : accusé
  05_17  réponse : erreur

05_18  « rafraîchis maintenant »       (serveur → client, sans réponse)
```

`05_18` est la seule trame de la catégorie qui n'ait ni demande ni réponse : le
core l'émet de lui-même, et l'agent y répond en repartant sur une `05_01`
ordinaire. Elle n'entre donc pas dans la règle de contiguïté ci-dessus, qui
ordonne des demandes et leurs réponses.

Les blocs 05_09, 05_12 et 05_15 sont **partagés** entre les deux scopes : la logique de
transfert de fragment et de rapport est rigoureusement identique, la dédoubler
donnerait deux fois le même code à maintenir et à tester. Pour ces trames
uniquement, le scope voyage donc dans le contenu (première ligne).

Slots libres pour la suite : **05_19 et au-delà**.

## Principe

Modèle **pull**, comme Puppet : c'est toujours le client qui initie. Le serveur ne
pousse jamais une politique de lui-même. Deux moments de sollicitation :

| Moment | Scope demandé | Portée |
|--------|---------------|--------|
| Démarrage du service client, une fois la session mère `vaultaire` établie, puis rafraîchissement périodique | machine | toutes les GPO machine de **tous** les groupes de la machine |
| Authentification réussie d'un utilisateur via PAM | user | les GPO user des groupes **partagés** entre la machine et l'utilisateur |

Le comportement est identique pour un client serveur et un client poste : seule la
liste des groupes diffère.

**Intersection en scope user.** Une GPO user ne s'applique que si son groupe
contient à la fois l'utilisateur et la machine. Sans cette intersection, un
utilisateur emporterait la configuration d'un groupe sur une machine qui n'en fait
pas partie — ce qui reviendrait à laisser l'utilisateur choisir la configuration de
la machine.

## Contrainte de taille : pourquoi un découpage

La couche de transport annonce la taille du message sur **2 octets**
(`CompileMessageSize` → `uint16`), et la charge est chiffrée en AES-GCM puis encodée
en base64. Le plafond réel par trame est donc :

```
65535 octets sur le fil
  → base64  : 65535 / 4 * 3          = 49151 octets chiffrés
  → AES-GCM : - nonce(12) - tag(16)  = 49123 octets de texte clair
```

Or un seul module `file_deploy` accepte jusqu'à 256 Kio de contenu. Une politique
réaliste dépasse donc une trame. Le découpage n'est pas une optimisation : sans
lui, la fonctionnalité casse dès le premier fichier volumineux, et de façon
silencieuse — l'écriture de la taille tronque sur `uint16`.

Marge retenue : **fragments de 32 Kio de texte clair**, pour laisser de la place à
l'en-tête de trame et ne pas frôler la limite.

## Séquence — scope machine

```
client                                              serveur
  |                                                    |
  |-- 05_01  ask_gpo_machine ---------------------->    |  empreinte appliquée localement
  |                                                    |  résout les GPO, calcule l'empreinte
  |                                                    |
  |   cas A : empreinte identique                      |
  |<-------------------- 05_03  gpo_machine_unchanged --|  rien à appliquer, fin
  |                                                    |
  |   cas B : empreinte différente                     |
  |<-------------------- 05_02  gpo_machine_manifest --|  version, empreinte, nb de fragments
  |-- 05_09  ask_gpo_chunk (machine, index 0) ----->    |
  |<------------------------------- 05_10  gpo_chunk --|
  |-- 05_09  ask_gpo_chunk (machine, index 1) ----->    |
  |<------------------------------- 05_10  gpo_chunk --|
  |   réassemblage, vérification de l'empreinte        |
  |   application des seuls modules modifiés           |
  |-- 05_12  gpo_apply_report (machine) ----------->    |
  |<--------------------- 05_13  gpo_apply_report_ack --|
  |                                                    |
  |   cas C : erreur serveur                           |
  |<--------------------- 05_04  gpo_machine_error ----|
```

Le manifeste ne transporte **jamais** de fragment, même quand il n'y en a qu'un.
Un format conditionnel économiserait deux trames sur le cas courant mais
doublerait les chemins de code à écrire et à tester, pour un échange qui a lieu au
démarrage et à la connexion — pas dans une boucle chaude.

La séquence du scope **user** est identique, avec `05_05` → `05_06` / `05_07` /
`05_08` à la place de `05_01` → `05_02` / `05_03` / `05_04`.

---

[← Sommaire du chapitre](./README.md) · [Les trames 05_01 à 05_18 →](./02-trames.md)
