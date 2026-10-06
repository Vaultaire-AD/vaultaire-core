[⌂ Formation](../README.md) › [Chapitre 2 — Premiers groupes et utilisateurs](./README.md) › Jalon 2.3

# Jalon 2.3 — Rattacher, consulter, retirer

[← Créer groupes et comptes](./02-creer-groupes-et-comptes.md) · [Chapitre 3 — Administrer Vaultaire via vlt →](../03-administrer-avec-vlt/README.md)

---

## Objectif

Placer les comptes dans leurs groupes et savoir défaire ce qu'on a fait.

## Étapes

1. Rattachez chaque compte à son groupe :

   ```bash
   vlt add -u alice.martin -g Infra
   vlt add -u bob.durand   -g Dev
   vlt add -u chloe.petit  -g RH
   ```

2. Consultez un groupe, puis ses seuls membres :

   ```bash
   vlt get -g Infra
   vlt get -g -u Infra
   vlt get -u -g Dev
   ```

3. Retirez puis remettez un membre :

   ```bash
   vlt remove -u bob.durand -g Dev
   vlt add    -u bob.durand -g Dev
   ```

## `remove` n'est pas `delete`

| Commande | Effet |
|---|---|
| `remove -u X -g G` | **détache** X du groupe ; le compte existe toujours |
| `delete -u X` | **supprime** le compte et le révoque sur toutes les machines |

## ✅ Vous avez réussi si

- chaque groupe contient son membre ;
- vous avez vu, dans le portail, la page **Admin → Groupes → Infra** qui
  rassemble membres, machines, permissions et GPO.

## 🧪 Exercice

Bob rejoint aussi l'équipe web. Faites-le **sans** le retirer de Dev, puis
vérifiez qu'il apparaît dans les deux groupes.

<details><summary>Solution</summary>

```bash
vlt add -u bob.durand -g Dev-Web
vlt get -u bob.durand
```

Un compte peut appartenir à plusieurs groupes : ses domaines sont alors
`dev.acme.lan` **et** `web.dev.acme.lan`.
</details>

## 💡 Aller plus loin

Le script `src/vaultaire_cli/autocreateData.sh` peuple un annuaire de test
complet — à n'utiliser que sur une base jetable.

---

[← Créer groupes et comptes](./02-creer-groupes-et-comptes.md) · [Chapitre 3 — Administrer Vaultaire via vlt →](../03-administrer-avec-vlt/README.md)
