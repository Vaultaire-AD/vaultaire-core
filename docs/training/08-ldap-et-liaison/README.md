[⌂ Formation](../README.md) › Chapitre 8

# Chapitre 8 — LDAP et liaison d'applications

[← Chapitre 7 — DNS](../07-dns/README.md) · [Chapitre 9 — Sécurité et exploitation →](../09-securite-et-exploitation/README.md)

---

Brancher une application tierce sur l'annuaire Vaultaire par LDAP, puis
LDAPS, avec Keycloak comme exemple.

## Prérequis

- chapitres [2](../02-groupes-et-utilisateurs/README.md) et
  [4](../04-permissions-et-delegation/README.md) terminés ;
- `ldapsearch` (paquet `openldap-clients` ou `ldap-utils`) sur votre poste ;
- le jalon 3 utilise le conteneur Keycloak de la pile.

## Jalons

| # | Jalon | Fait |
|---|---|---|
| 8.1 | [Un compte de service LDAP](./01-compte-de-service.md) | ☐ |
| 8.2 | [Interroger l'annuaire](./02-interroger-l-annuaire.md) | ☐ |
| 8.3 | [LDAPS et Keycloak](./03-ldaps-et-keycloak.md) | ☐ |

Chaque jalon suit le même plan : **objectif**, **étapes**, **vous avez réussi
si**, puis un **exercice** avec sa solution repliée.

**Commencer : [Un compte de service LDAP](./01-compte-de-service.md)**

---

[← Chapitre 7 — DNS](../07-dns/README.md) · [Chapitre 9 — Sécurité et exploitation →](../09-securite-et-exploitation/README.md)
