[⌂ Formation](../README.md) › [Chapitre 6 — Première GPO](./README.md) › Jalon 6.2

# Jalon 6.2 — Lier et appliquer

[← Créer une GPO machine](./01-creer-une-gpo-machine.md) · [Dérive, audit, et GPO utilisateur →](./03-derive-et-gpo-utilisateur.md)

---

## Objectif

Appliquer la GPO aux machines du groupe `Infra` et le vérifier.

## Étapes

1. Liez la GPO au groupe :

   ```bash
   vlt add -gpo ssh-baseline -g Infra
   ```

2. Sans attendre le cycle horaire, relancez l'agent sur `web01` :

   ```bash
   systemctl restart vaultaire_client
   ```

3. Vérifiez côté machine :

   ```bash
   cat /etc/ssh/sshd_config.d/99-vaultaire-gpo.conf
   cat /etc/ssh/vaultaire-banner
   ```

4. Vérifiez côté serveur :

   ```bash
   vlt gpo status
   vlt gpo status <computeur_id>
   ```

   Ou **Admin → Conformité** dans le portail.

## Lire `gpo status`

| Colonne | Question |
|---|---|
| **Suivi** | la machine parle-t-elle encore ? `à jour`, `en retard`, `jamais` |
| **Application** | la politique a-t-elle **pu être posée** ? |
| **Conformité** | est-elle **encore en place** ? |

## ✅ Vous avez réussi si

- une nouvelle connexion SSH à `web01` affiche la bannière ;
- `gpo status` montre `web01` à jour et appliquée.

## 🧪 Exercice

Où voir, en une seule page, toutes les GPO qui s'appliquent au groupe `Infra` ?

<details><summary>Solution</summary>

`vlt get -g Infra`, ou le détail du groupe dans **Admin → Groupes**.
</details>

---

[← Créer une GPO machine](./01-creer-une-gpo-machine.md) · [Dérive, audit, et GPO utilisateur →](./03-derive-et-gpo-utilisateur.md)
