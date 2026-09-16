[⌂ Formation](../README.md) › [Chapitre 1 — Installer le serveur](./README.md) › Jalon 1.1

# Jalon 1.1 — Préparer l'hôte

[← Sommaire du chapitre](./README.md) · [Démarrer la pile →](./02-demarrer-la-pile.md)

---

## Objectif

Disposer d'une machine prête à recevoir la pile Vaultaire.

## Ce qu'il faut savoir

La pile de démonstration est celle de la **préproduction** : trois conteneurs
décrits dans `deployments/pre-prod/docker-compose.yml`.

| Conteneur | Rôle | Ports publiés |
|---|---|---|
| `vaultaire-ad` | le core Vaultaire | 6666, 4443, 6643, 389, 636 |
| `vaultaire-db` | MariaDB | 3306 |
| `vaultaire-keycloak` | Keycloak, pour le chapitre LDAP | 8080 |

Les binaires ne sont **pas** dans le dépôt : un script les télécharge depuis les
releases GitHub.

## Étapes

1. Vérifiez Docker :

   ```bash
   docker version --format '{{.Server.Version}}'
   docker compose version
   ```

2. Vérifiez qu'aucun service n'occupe déjà les ports :

   ```bash
   sudo ss -ltnp | grep -E ':(6666|4443|6643|389|636|3306|8080)\b' || echo "ports libres"
   ```

3. Clonez le dépôt :

   ```bash
   git clone https://github.com/Vaultaire-AD/vaultaire-core.git
   cd vaultaire-core
   ```

4. Notez l'adresse IP de la machine, elle servira tout au long de la formation :

   ```bash
   hostname -I | awk '{print $1}'
   ```

## ✅ Vous avez réussi si

- `docker compose version` répond ;
- les sept ports sont libres ;
- vous êtes à la racine du dépôt cloné.

## 🧪 Exercice

Listez les releases disponibles **sans rien installer**.

<details><summary>Solution</summary>

```bash
./deployments/pre-prod/docker-update.sh --list
```

Le script interroge l'API GitHub et affiche les tags `vX.Y.Z` conservés (les
cinq derniers).
</details>

---

[← Sommaire du chapitre](./README.md) · [Démarrer la pile →](./02-demarrer-la-pile.md)
