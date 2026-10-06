[⌂ Formation](../README.md) › [Chapitre 10 — Cluster et proxy](./README.md) › Jalon 10.1

# Jalon 10.1 — Clés d'enrôlement

[← Sommaire du chapitre](./README.md) · [Déployer un proxy →](./02-deployer-un-proxy.md)

---

## Objectif

Comprendre comment un **service** (proxy, portail externe) rejoint le cluster
sans que sa clé privée ne voyage.

## Ce qu'il faut savoir

- Une **machine** du parc se crée avec `create -c` : le core génère sa clé.
- Un **service** s'**enrôle lui-même** avec une **clé d'enrôlement** : il génère
  sa paire sur son propre hôte.
- Une clé est bornée en **nombre d'usages** et en **durée**.

## Syntaxe

```text
enroll create --type <type> [--uses N] [--expires 30m] [--label texte] [--groups a,b]
enroll list | show <id> | revoke <id> | types
```

## Étapes

1. Le catalogue des types :

   ```bash
   vlt enroll types
   ```

2. Une clé pour un proxy, valable 1 h, 1 usage :

   ```bash
   vlt enroll create --type vaultaire_proxy --uses 1 --expires 1h --label proxy-lab
   vlt enroll list
   ```

   Notez la clé (`VLT-ENR-…`).

## ✅ Vous avez réussi si

`enroll list` montre la clé, active, avec 1 usage restant.

## 🧪 Exercice

Une clé a fuité dans un ticket. Neutralisez-la sans perdre la trace de ce qui
s'est enrôlé avec.

<details><summary>Solution</summary>

```bash
vlt enroll revoke <id>
vlt enroll show <id>      # l'historique reste consultable
```
</details>

---

[← Sommaire du chapitre](./README.md) · [Déployer un proxy →](./02-deployer-un-proxy.md)
