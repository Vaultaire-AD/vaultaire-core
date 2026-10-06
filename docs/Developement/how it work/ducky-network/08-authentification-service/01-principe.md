[⌂ Ducky Network](../README.md) › [Chapitre 8 — Authentification par un service (08)](./README.md) › 8.1

# 8.1 — Principe et séquence

[← Sommaire du chapitre](./README.md) · [Les trames 08_01 à 08_06 →](./02-trames.md)

---

Un service du cluster — le dépôt **Nexus** aujourd'hui, un service d'API ou un
portail demain — authentifie **ses propres utilisateurs**. Plutôt que de tenir
une base de comptes, il demande au core : *ce mot de passe (et ce code) est-il
bon, et que peut faire ce compte chez moi ?*

La catégorie est **générique** : rien n'y est propre à Nexus. Ce qu'un type de
service apprend sur un compte est déclaré dans le catalogue
(`clienttype.Definition.UserRights`).

| Trame | Reçue par | Nom | Rôle |
|---|---|---|---|
| `08_01` | core | service_user_auth | identifiant, mot de passe, code TOTP facultatif |
| `08_02` | service | service_user_auth_ok | compte, nom affiché, groupes, clés de service |
| `08_03` | service | service_user_auth_failed | code et raison |
| `08_04` | core | service_user_refresh | relire un compte déjà vérifié |
| `08_05` | service | service_user_refresh_ok | même contenu que `08_02` |
| `08_06` | service | service_user_refresh_denied | le compte ne doit plus avoir de droits |
| `08_07` … `08_19` | — | réservées | |

Code : `src/vaultaire_serveur/ducky-network/serviceauth/` (core),
`src/vaultaire_nexus/internal/clusterlink/serviceauth.go` (exemple de client).

## Pourquoi une catégorie et pas 02, 03 ou LDAP

| Porte | Vérifie | Pour |
|---|---|---|
| `02_0x` | le **programme** | ouvrir une session Ducky |
| `03_01` | une personne | ouvrir une session **sur une machine** : clés SSH, `is_admin`, droit de connexion au poste |
| bind LDAP | une personne | une application LDAP ; **ne sait pas porter le second facteur** |
| `08_01` | une personne | le compte d'un **service** : ni clés SSH, ni machine, mais le second facteur et les clés RBAC du service |

La restriction par sous-trame reste précise : l'agent n'émet pas `08`, un
service n'émet pas `03_01`.

## Séquence

```
utilisateur              service (Nexus)                         core
    |  identifiant + mdp      |                                        |
    |------------------------>|-- 08_01 id, mdp, ref:r1 -------------->|  débit, mot de passe,
    |                         |<-- 08_03 ref:r1 code:mfa_required -----|  révocation, expiration
    |<-- « saisissez le code »|                                        |
    |  code 123456            |                                        |
    |------------------------>|-- 08_01 id, mdp, otp:123456, ref:r2 -->|  TOTP + anti-rejeu,
    |                         |<-- 08_02 ref:r2 user: groups: rights: -|  permission « auth »,
    |<-- session ouverte -----|                                        |  clés du service
    |                         |                                        |
    |                         |   (toutes les 5 min, par compte actif) |
    |                         |-- 08_04 ref:r3 user:alice ------------>|
    |                         |<-- 08_05 … (ou 08_06 revoked) ---------|
```

Le mot de passe voyage **dans la session Ducky**, déjà chiffrée (AES-GCM) et
authentifiée des deux côtés — comme sur les autres portes du core.

## Et en LDAP ?

Un service qui ne parle que LDAP lit les mêmes clés dans l'attribut
opérationnel **`vaultaireServiceRights`** de l'entrée du compte, à condition de
le demander nommément. Les deux chemins voient donc la même décision, prise dans
la matrice des permissions. Détails : [`vaultaireLDAP.md`](../../../../Utilisation/vaultaireLDAP.md).

---

[← Sommaire du chapitre](./README.md) · [Les trames 08_01 à 08_06 →](./02-trames.md)
