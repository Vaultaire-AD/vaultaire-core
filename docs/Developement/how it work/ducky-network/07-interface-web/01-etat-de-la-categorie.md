[⌂ Ducky Network](../README.md) › [Chapitre 7 — Interface web (07)](./README.md) › 7.1

# 7.1 — État de la catégorie 07

[← Sommaire du chapitre](./README.md) · [Chapitre 8 — Authentification par un service (08) →](../08-authentification-service/README.md)

---

| Trame | Émise par | État |
|---|---|---|
| `07_01` | `vaultaire_web` | **déclarée** au catalogue, **non traitée** par le core |
| `07_04` | `vaultaire_web` | **déclarée** au catalogue, **non traitée** par le core |

La catégorie 07 est réservée à l'interface web enrôlée comme service, qui
authentifie des administrateurs et **relaie leurs commandes** au core. C'est le
seul type qui porte `AssertsUser` : il peut déclarer agir au nom d'un compte
qu'il a lui-même authentifié.

**Rien ne la traite aujourd'hui.** `Spliter.go` n'a pas de cas `07` : une trame
de cette catégorie, même autorisée par le type, est journalisée
« Unknown service » et reste sans réponse. Le portail web actuel tourne dans le
processus du core et n'utilise pas le réseau Ducky.

## Ce qui la distingue de la catégorie 08

| | 07 — interface web | 08 — authentification par un service |
|---|---|---|
| Qui l'émet | `vaultaire_web` seul | tout type service qui le déclare (Nexus…) |
| Ce que le service obtient | le droit d'agir **au nom** d'un compte | la **vérification** d'un compte et ses clés de service |
| Privilège au catalogue | `AssertsUser` | `UserRights` (liste filtrée) |
| État | réservée | implémentée |

Un service qui n'a besoin que de savoir **qui** se connecte et **ce qu'il peut
faire chez lui** utilise la catégorie 08, jamais la 07.

## Avant de l'implémenter

- Numéroter demande et réponses de façon contiguë (`07_01` → `07_02`/`07_03`,
  `07_04` → `07_05`/`07_06`), puis mettre à jour le catalogue.
- Écrire le gestionnaire, le brancher dans `Spliter.go`.
- Faire évaluer le RBAC sur l'identité déclarée **et** refuser toute déclaration
  d'un type sans `AssertsUser` (`clienttype.MayAssertUser`).

---

[← Sommaire du chapitre](./README.md) · [Chapitre 8 — Authentification par un service (08) →](../08-authentification-service/README.md)
