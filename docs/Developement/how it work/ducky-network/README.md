[⌂ Accueil du dépôt](../../../../README.md) · [Index de la documentation](../../../README.md) · [Dossier développeurs](../README.md)

# Ducky Network — le protocole

**Public : développeurs.** Le réseau Ducky relie le core à tout ce qui l'entoure :
agents des postes, proxies, services du cluster (interface web, Nexus). Ce
dossier décrit ses trames `CC_SS` — format, ordre, contrôles — catégorie par
catégorie.

8 chapitres, un par famille de trames. Chaque page tient en une lecture.

---

## Comment le lire

- Commencez par le **chapitre 1** : chiffrement, format des lignes, contrôles
  appliqués avant toute trame. Le reste s'appuie dessus.
- Ensuite, allez directement à la catégorie qui vous concerne.
- Chaque chapitre a son dossier et son sommaire ; chaque page a en tête un fil
  d'Ariane (**⌂ Ducky Network › Chapitre › Page**) et des liens
  **précédent / suivant**.
- Dans les tableaux, la colonne **Reçue par** désigne la partie qui **reçoit**
  la trame, pas celle qui l'envoie.
- Le code fait foi : chaque page nomme les fichiers qui l'implémentent.

## Les chapitres

| # | Chapitre | Trames | Code côté core |
|---|---|---|---|
| 1 | [Le socle : canal, format, contrôles](./01-socle/README.md) | — | `ducky-network/trames_manager`, `sessionmgr`, `core/clienttype` |
| 2 | [Authentification et enrôlement](./02-authentification-et-enrolement/README.md) | `01_01`–`01_09`, `02_01`–`02_13` | `ducky-network/authentification/{serveur,client}` |
| 3 | [Poste de travail : SSH, PAM et groupes](./03-ssh-et-groupes/README.md) | `03_01`–`03_10` | `ducky-network/authentification/ssh` |
| 4 | [Cluster et découverte](./04-cluster/README.md) | `04_01`–`04_14` (réservée → `04_19`) | `ducky-network/host_handler`, `cluster/` |
| 5 | [Transport des GPO](./05-gpo/README.md) | `05_01`–`05_17` | `ducky-network/gpo_manager`, `core/gpo` |
| 6 | [Révocation — kill switch](./06-revocation/README.md) | `06_01`–`06_06` | `ducky-network/revocation_manager`, `core/revocation` |
| 7 | [Interface web](./07-interface-web/README.md) | `07_01`, `07_04` — **réservées** | *aucun* |
| 8 | [Authentification par un service](./08-authentification-service/README.md) | `08_01`–`08_06` (réservée → `08_19`) | `ducky-network/serviceauth` |

## Qui émet quoi

| Type de client | 01 | 02 | 03 | 04 | 05 | 06 | 07 | 08 |
|---|---|---|---|---|---|---|---|---|
| `vaultaire_client` (agent) | `01_01` | ✔ | ✔ | `04_03` | ✔ | ✔ | — | — |
| `vaultaire_proxy` | + enrôlement | ✔ | — | nœud (`04_01 03 05 07`) | — | — | — | — |
| `vaultaire_web` | + enrôlement | ✔ | — | service (`04_09 12 14`) | — | — | `07_01 07_04` | — |
| `vaultaire_nexus` | + enrôlement | ✔ | — | service (`04_09 12 14`) | — | — | — | `08_01 08_04` |

Détail exact : [1.3 — Types de client, ordre et contrôles](./01-socle/03-types-ordre-et-controles.md).

## Voir aussi

| Sujet | Page |
|---|---|
| Créer un nouveau service du cluster | [`Nouveau_service.md`](../Nouveau_service.md) |
| Clés RBAC, dont celles des services | [`Permissions_RBAC.md`](../Permissions_RBAC.md) |
| Second facteur et expiration | [`MFA_et_Expiration.md`](../MFA_et_Expiration.md) |
| Mécanisme des GPO | [`GPO.md`](../GPO.md) |
| Versions annoncées par les programmes | [`Versions.md`](../Versions.md) |
| Types de client et migration | [`migrations/clienttype_catalogue.md`](../../../migrations/clienttype_catalogue.md) |

**Commencer : [Chapitre 1 — Le socle](./01-socle/README.md)**
