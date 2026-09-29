[⌂ Formation](../README.md) › [Chapitre 8 — LDAP et liaison d'applications](./README.md) › Jalon 8.3

# Jalon 8.3 — LDAPS et Keycloak

[← Interroger l'annuaire](./02-interroger-l-annuaire.md) · [Chapitre 9 — Sécurité et exploitation →](../09-securite-et-exploitation/README.md)

---

## Objectif

Fédérer les utilisateurs d'Acme dans Keycloak, en LDAPS.

## Ce qu'il faut savoir

Deux causes font échouer LDAPS, avec le même message (`SSLHandshakeFailed`) :

1. le certificat ne porte pas le **nom** par lequel Keycloak joint le serveur
   (les clients Java exigent un SAN) ;
2. le certificat n'est pas dans le **magasin de confiance** de Keycloak.

## Étapes

1. Couvrez le nom du conteneur, puis régénérez :

   ```bash
   vlt certificate regenerate ldaps --dns vaultaire-ad,vaultaire.acme.lan
   vlt certificate show ldaps
   ```

2. Copiez le bloc PEM affiché dans `deployments/pre-prod/vaultaire-ldaps.pem`
   (le compose le monte dans Keycloak), puis :

   ```bash
   docker compose -f deployments/pre-prod/docker-compose.yml restart vaultaire-ad vaultaire-keycloak
   ```

3. Dans Keycloak (`http://<IP-serveur>:8080/auth`), **User federation → Add
   LDAP provider** :

   | Champ | Valeur |
   |---|---|
   | Connection URL | `ldaps://vaultaire-ad:636` |
   | Bind type | `simple` |
   | Bind DN | `uid=svc_keycloak,dc=svc,dc=acme,dc=lan` |
   | Bind credentials | le mot de passe du compte |
   | Edit mode | `READ_ONLY` |
   | Users DN | `dc=acme,dc=lan` |
   | Username / RDN / UUID attribute | `uid` |
   | User object classes | `inetOrgPerson, organizationalPerson, person, user` |
   | Search scope | `Subtree` |

   > ⚠️ **`Search scope` était `One Level` dans la version précédente de ce
   > support.** Le serveur élargissait alors silencieusement ces recherches à
   > toute l'arborescence ; il ne le fait plus (point 127). Avec des comptes dans
   > `dev.acme.lan` et `svc.acme.lan` sous un « Users DN » de `dc=acme,dc=lan`,
   > `One Level` ne remonterait plus personne — sans erreur. `Subtree` est la
   > façon juste de demander une arborescence.

   > ⚠️ Si vous avez suivi ce support avant la 2.2, la ligne « User object
   > classes » contenait `posixaccount`. Le serveur ne l'annonce plus : il ne
   > servait aucun attribut POSIX (`uidNumber`, `gidNumber`…), et l'annoncer
   > faisait chercher chez le client un défaut qui était côté serveur. Keycloak
   > compose ces classes en **conjonction** — avec `posixaccount`, la
   > synchronisation ne remonte plus aucun utilisateur. Retirez-le de la
   > configuration avant de mettre le core à jour.

   Cliquez **Test connection** puis **Test authentication**.

4. Ajoutez un mapper **group-ldap-mapper** : Groups DN `dc=acme,dc=lan`, name
   attribute `cn`, object class `groupOfNames`, membership attribute `member`,
   type `UID`, *Preserve group inheritance* **OFF**. Lancez une synchronisation.

## ✅ Vous avez réussi si

- les deux tests Keycloak passent ;
- **Users** liste les comptes d'Acme, **Groups** leurs groupes.

## 🧪 Exercice

Keycloak répond `SSLHandshakeFailed`. Comment savoir laquelle des deux causes est
en jeu, sans Keycloak ?

<details><summary>Solution</summary>

```bash
openssl s_client -connect <IP-serveur>:636 -servername vaultaire-ad </dev/null \
  | openssl x509 -noout -ext subjectAltName
```

Si `vaultaire-ad` n'apparaît pas dans le SAN, c'est la cause 1. Sinon, vérifiez
le magasin de confiance (cause 2).
</details>

## 📚 Référence

[`ldaps_keycloak.md`](../../exploitation/ldaps_keycloak.md) — pas à pas
détaillé selon la version de Keycloak ·
[`vaultaireLDAP.md`](../../Utilisation/vaultaireLDAP.md)

---

[← Interroger l'annuaire](./02-interroger-l-annuaire.md) · [Chapitre 9 — Sécurité et exploitation →](../09-securite-et-exploitation/README.md)
