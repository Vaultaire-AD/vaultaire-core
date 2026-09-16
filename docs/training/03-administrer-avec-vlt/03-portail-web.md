[⌂ Formation](../README.md) › [Chapitre 3 — Administrer Vaultaire via vlt](./README.md) › Jalon 3.3

# Jalon 3.3 — Le portail web

[← vlt à distance par l'API](./02-vlt-a-distance.md) · [Chapitre 4 — Permissions et délégation →](../04-permissions-et-delegation/README.md)

---

## Objectif

Savoir retrouver dans le portail tout ce que vous faites en ligne de commande.

## Correspondances

| Ligne de commande | Portail |
|---|---|
| `get -u`, `create -u`, `update -u` | **Admin → Utilisateurs** |
| `get -g`, `add`, `remove` | **Admin → Groupes** (détail d'un groupe) |
| `get -c`, `get -c <id> --targets` | **Admin → Clients** |
| `get -p`, `update -pu` | **Admin → Permissions** |
| `create -gpo`, modules | **Admin → GPO** — les modules **ne s'éditent qu'ici** |
| `gpo status`, `gpo drift` | **Admin → Conformité** |
| `dns …` | **Admin → DNS** |
| `enroll …` | **Admin → Enrôlement** |
| `cluster …` | **Admin → Cluster** |
| `certificate …` | **Admin → Certificats** |
| `settings …` | **Admin → Durées** |
| `eyes -g` | **Admin → Arborescence** |
| `mfa -g`, `mfa policy` | **Admin → Authentification** |
| journal du serveur | **Admin → Logs** |
| son propre second facteur | **Profil** |

## Étapes

1. Dans **Admin → Groupes**, ouvrez `Infra` : membres, machines, permissions et
   GPO sont sur une seule page, chacun avec son ajout et son retrait.
2. Ajoutez `chloe.petit` à `Infra` depuis cette page, puis vérifiez en ligne de
   commande :

   ```bash
   vlt get -g -u Infra
   ```

3. Retirez-la depuis la ligne de commande et rechargez la page.
4. Ouvrez **Admin → Logs** : les deux opérations y figurent, avec leur
   auteur.

## ✅ Vous avez réussi si

Une modification faite d'un côté est visible de l'autre, et tracée.

## 🧪 Exercice

Quelle opération du chapitre 6 **ne peut pas** se faire en ligne de commande ?

<details><summary>Solution</summary>

L'ajout et le paramétrage des **modules** d'une GPO : `create -gpo` crée la GPO
vide, les formulaires des modules sont générés par le portail depuis le
catalogue.
</details>

---

[← vlt à distance par l'API](./02-vlt-a-distance.md) · [Chapitre 4 — Permissions et délégation →](../04-permissions-et-delegation/README.md)
