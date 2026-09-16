[⌂ Formation](../README.md) › [Chapitre 4 — Permissions et délégation](./README.md) › Jalon 4.1

# Jalon 4.1 — Une permission utilisateur

[← Sommaire du chapitre](./README.md) · [Déléguer un domaine →](./02-deleguer-un-domaine.md)

---

## Objectif

Créer une permission, lui donner un droit, l'attacher à un groupe.

## Ce qu'il faut savoir

- Les droits ne s'attribuent **jamais** à un compte : une **permission** est
  attachée à un **groupe**, et ses membres en héritent.
- Une permission naît **sans aucun droit**.
- Un droit est une **action** avec une **portée** :

| Portée | Signification |
|---|---|
| `nil` | refusé |
| `all` | tous les domaines |
| `-a 1 <domaine>` | ce domaine **et ses sous-domaines** |
| `-a 0 <domaine>` | ce domaine seul |

- Actions RBAC : `read:get:<objet>`, `read:status:<objet>`,
  `write:create|delete|update|add:<objet>` avec l'objet `user`, `group`,
  `client`, `permission` ou `gpo`. Actions historiques : `web_admin`, `auth`,
  `search`, `compare`.

## Étapes

1. Créez une permission de consultation, sans accès au portail :

   ```bash
   vlt create -p lecture-annuaire non --desc "Consultation de l'annuaire"
   ```

2. Donnez-lui la lecture des utilisateurs et des groupes sur tout `acme.lan` :

   ```bash
   vlt update -pu lecture-annuaire read:get:user  -a 1 acme.lan
   vlt update -pu lecture-annuaire read:get:group -a 1 acme.lan
   vlt get -p -u lecture-annuaire
   ```

3. Attachez-la au groupe RH :

   ```bash
   vlt add -gu RH -p lecture-annuaire
   ```

## ✅ Vous avez réussi si

`get -p -u lecture-annuaire` montre les deux actions avec `(1:acme.lan)`, et
`get -g RH` liste la permission.

## 🧪 Exercice

Retirez à cette permission la lecture des **groupes**, sans toucher au reste.

<details><summary>Solution</summary>

```bash
vlt update -pu lecture-annuaire read:get:group -r 1 acme.lan
```

Quand le dernier domaine est retiré, l'action repasse à `nil`.
</details>

---

[← Sommaire du chapitre](./README.md) · [Déléguer un domaine →](./02-deleguer-un-domaine.md)
