[⌂ Formation](../README.md) › [Chapitre 8 — LDAP et liaison d'applications](./README.md) › Jalon 8.1

# Jalon 8.1 — Un compte de service LDAP

[← Sommaire du chapitre](./README.md) · [Interroger l'annuaire →](./02-interroger-l-annuaire.md)

---

## Objectif

Créer le compte avec lequel une application interrogera l'annuaire, avec juste
les droits nécessaires.

## Ce qu'il faut savoir

- LDAP écoute sur **389**, LDAPS sur **636** (`ldap_enable`, `ldaps_enable`).
- La **base DN** se déduit de l'arbre des domaines :
  `acme.lan` → `dc=acme,dc=lan`.
- Deux actions gouvernent LDAP :

| Action | Pour |
|---|---|
| `auth` | ouvrir une session (bind) |
| `search` | lire l'annuaire (search) |

## Étapes

1. Créez un groupe et un compte dédiés :

   ```bash
   vlt create -g Services svc.acme.lan
   vlt create -u svc_keycloak svc.acme.lan 'Ancre-Violon-Galet-91' 01/01/2000 --permanent
   vlt add -u svc_keycloak -g Services
   ```

   > 🔑 **`--permanent`** : sans lui, le mot de passe serait **provisoire**,
   > comme celui des personnes du jalon 2.2 — il cesserait de fonctionner au
   > bout de 24 h, et Keycloak ne pourrait plus se lier. Un compte de service
   > n'a personne pour le changer sur le portail : son mot de passe est
   > **définitif** dès la création. C'est une dérogation, et le journal la
   > garde, avec votre nom :
   >
   > ```bash
   > vlt logs --level WARNING --since 1h
   > ```
   >
   > Le jour où il faudra renouveler ce secret, `--permanent` se place
   > **avant** `-p` — sans lui, le nouveau serait provisoire :
   >
   > ```bash
   > vlt update -u svc_keycloak --permanent -p 'Marbre-Pelican-Opale-38'
   > ```
   >
   > Sur le portail, c'est la liste **Nature du mot de passe** des formulaires
   > de création et de la fiche du compte.
   >
   > C'est `Ancre-Violon-Galet-91` que vous donnerez à `ldapsearch`
   > (jalon 8.2) et à Keycloak (jalon 8.3).

2. Donnez-lui le bind et la lecture de tout `acme.lan` :

   ```bash
   vlt create -p ldap-lecture non --desc "Lecture LDAP pour applications"
   vlt update -pu ldap-lecture auth   -a 1 acme.lan
   vlt update -pu ldap-lecture search -a 1 acme.lan
   vlt add -gu Services -p ldap-lecture
   ```

3. Relevez la base DN :

   ```bash
   vlt eyes -g
   ```

## ✅ Vous avez réussi si

`get -g Services` montre le compte et la permission `ldap-lecture`, et
`vlt logs --level WARNING --since 1h` porte la ligne `SECURITY` « user.create :
svc_keycloak@svc.acme.lan créé par … avec un mot de passe DÉFINITIF ».

## 🧪 Exercice

L'application ne doit voir **que** l'équipe de développement. Que changer ?

<details><summary>Solution</summary>

Restreindre `search` à `dev.acme.lan` (avec propagation) et utiliser la base DN
`dc=dev,dc=acme,dc=lan` côté application :

```bash
vlt update -pu ldap-lecture search -r 1 acme.lan
vlt update -pu ldap-lecture search -a 1 dev.acme.lan
```
</details>

---

[← Sommaire du chapitre](./README.md) · [Interroger l'annuaire →](./02-interroger-l-annuaire.md)
