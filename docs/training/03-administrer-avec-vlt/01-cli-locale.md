[⌂ Formation](../README.md) › [Chapitre 3 — Administrer Vaultaire via vlt](./README.md) › Jalon 3.1

# Jalon 3.1 — La CLI locale

[← Sommaire du chapitre](./README.md) · [vlt à distance par l'API →](./02-vlt-a-distance.md)

---

## Objectif

Être à l'aise avec `vaultaire_cli`, la CLI qui parle au core par son socket.

## Ce qu'il faut savoir

- `vaultaire_cli` s'exécute **sur le serveur** et dialogue par le socket
  `/opt/vaultaire/vaultaire.sock` : pas de mot de passe, l'accès au socket fait
  foi.
- Deux modes : **une commande** en argument, ou une **invite** interactive
  `vaultaire>` (quitter avec `exit`).
- `-h` sur chaque commande donne la syntaxe à jour. En cas de désaccord avec le
  manuel, **c'est l'aide qui a raison**.

## Étapes

1. Mode invite :

   ```bash
   docker exec -it vaultaire-ad /opt/vaultaire/bin/vaultaire_cli
   vaultaire> help
   vaultaire> create -h
   vaultaire> status -u
   vaultaire> exit
   ```

2. Mode commande (celui de l'alias `vlt`) :

   ```bash
   vlt get -g Dev
   vlt settings list
   ```

## Les familles de commandes

| Famille | Commandes |
|---|---|
| Annuaire | `create`, `get`, `add`, `remove`, `delete`, `update`, `eyes` |
| Sessions | `status`, `clear` |
| Parc | `gpo`, `cluster`, `enroll` |
| Services | `dns`, `certificate` |
| Sécurité | `kill`, `mfa` |
| Serveur | `settings`, `version` |

## ✅ Vous avez réussi si

Vous trouvez seul, avec `-h`, la syntaxe pour **lister les clients d'un groupe**.

<details><summary>Réponse</summary>

`get -g -c <groupe>` — voir `get -h`.
</details>

## 🧪 Exercice

Qui est connecté en ce moment au portail ou aux machines ?

<details><summary>Solution</summary>

```bash
vlt status -u
```
</details>

---

[← Sommaire du chapitre](./README.md) · [vlt à distance par l'API →](./02-vlt-a-distance.md)
