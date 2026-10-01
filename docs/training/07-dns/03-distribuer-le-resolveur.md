[⌂ Formation](../README.md) › [Chapitre 7 — DNS](./README.md) › Jalon 7.3

# Jalon 7.3 — Distribuer le résolveur au parc

[← Zones et enregistrements](./02-zones-et-enregistrements.md) · [Chapitre 8 — LDAP et liaison d'applications →](../08-ldap-et-liaison/README.md)

---

## Objectif

Faire utiliser le DNS de Vaultaire par les machines du parc, via une GPO.

## Étapes

1. Créez une GPO machine et liez-la à `Infra` :

   ```bash
   vlt create -gpo dns-acme --scope machine --desc "Résolveur Acme"
   vlt add -gpo dns-acme -g Infra
   ```

2. Dans le portail, ajoutez le module **Résolution DNS** :
   - Serveurs DNS : `<IP-serveur>`
   - Domaine de recherche : `acme.lan`

3. Sur `web01` :

   ```bash
   systemctl restart vaultaire_client
   getent hosts www
   ```

## ✅ Vous avez réussi si

`getent hosts www` résout `www.acme.lan` sans que vous ayez écrit le domaine.

## 🧪 Exercice

`web01` a perdu sa résolution après un redémarrage du serveur DNS. Que vérifier
en premier côté Vaultaire ?

<details><summary>Solution</summary>

`vlt gpo status <computeur_id>` pour voir si le module est toujours appliqué et
conforme, puis `vlt dns zone show acme.lan` pour vérifier que les
enregistrements existent.
</details>

## 📚 Référence

[`DNS.md`](../../Utilisation/DNS.md) · [`MAN.md` §14](../../Utilisation/MAN.md)

---

[← Zones et enregistrements](./02-zones-et-enregistrements.md) · [Chapitre 8 — LDAP et liaison d'applications →](../08-ldap-et-liaison/README.md)
