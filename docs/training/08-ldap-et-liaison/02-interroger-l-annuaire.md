[⌂ Formation](../README.md) › [Chapitre 8 — LDAP et liaison d'applications](./README.md) › Jalon 8.2

# Jalon 8.2 — Interroger l'annuaire

[← Un compte de service LDAP](./01-compte-de-service.md) · [LDAPS et Keycloak →](./03-ldaps-et-keycloak.md)

---

## Objectif

Valider le compte de service et la structure de l'annuaire avec `ldapsearch`.

## Étapes

1. Un bind et une recherche sur tout Acme :

   ```bash
   ldapsearch -x -H ldap://<IP-serveur>:389 \
     -D "uid=svc_keycloak,dc=svc,dc=acme,dc=lan" -W \
     -b "dc=acme,dc=lan" "(objectClass=inetOrgPerson)" uid mail
   ```

2. Les groupes :

   ```bash
   ldapsearch -x -H ldap://<IP-serveur>:389 \
     -D "uid=svc_keycloak,dc=svc,dc=acme,dc=lan" -W \
     -b "dc=acme,dc=lan" "(objectClass=groupOfNames)" cn member
   ```

3. Un mauvais mot de passe : vérifiez que le bind échoue (`Invalid credentials`).

## Les formes de bind DN acceptées

| Forme | Exemple |
|---|---|
| `uid=` | `uid=svc_keycloak,dc=svc,dc=acme,dc=lan` |
| `cn=` | `cn=svc_keycloak,dc=acme,dc=lan` |

## ✅ Vous avez réussi si

- la première recherche rend `alice.martin`, `bob.durand`, `chloe.petit` ;
- la seconde rend les groupes et leurs membres.

## 🧪 Exercice

Cherchez uniquement les membres de `Dev`, sous-domaines compris.

<details><summary>Solution</summary>

```bash
ldapsearch -x -H ldap://<IP-serveur>:389 \
  -D "uid=svc_keycloak,dc=svc,dc=acme,dc=lan" -W \
  -b "dc=dev,dc=acme,dc=lan" "(objectClass=inetOrgPerson)" uid
```
</details>

> LDAP n'a pas de second facteur. Quand le réglage `RefuseBindWhenMFARequired`
> est activé (il ne l'est pas par défaut), le bind d'un compte soumis au **MFA**
> est refusé. Gardez les comptes de service hors des groupes à MFA obligatoire.

---

[← Un compte de service LDAP](./01-compte-de-service.md) · [LDAPS et Keycloak →](./03-ldaps-et-keycloak.md)
