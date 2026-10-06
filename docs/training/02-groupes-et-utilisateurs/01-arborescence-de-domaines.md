[⌂ Formation](../README.md) › [Chapitre 2 — Premiers groupes et utilisateurs](./README.md) › Jalon 2.1

# Jalon 2.1 — Penser l'arborescence de domaines

[← Sommaire du chapitre](./README.md) · [Créer groupes et comptes →](./02-creer-groupes-et-comptes.md)

---

## Objectif

Comprendre comment Vaultaire organise l'annuaire avant de créer quoi que ce soit.

## Ce qu'il faut savoir

- Un **groupe** porte un **domaine** DNS : `infra.acme.lan`.
- Les domaines forment un **arbre** : `infra.acme.lan` est sous `acme.lan`.
- Un utilisateur ou une machine appartient aux domaines de **ses groupes**.
- Les droits se délèguent **par domaine**, avec ou sans les sous-domaines
  (chapitre 4). Un bon arbre simplifie donc toute la délégation.
- Côté LDAP, l'arbre devient une base DN : `infra.acme.lan` →
  `dc=infra,dc=acme,dc=lan`.

## L'arbre d'Acme

```
acme.lan
├── infra.acme.lan        groupe Infra        les administrateurs système
├── dev.acme.lan          groupe Dev          les développeurs
│   └── web.dev.acme.lan  groupe Dev-Web      l'équipe web
└── rh.acme.lan           groupe RH           les ressources humaines
```

## Étapes

1. Affichez l'arbre actuel :

   ```bash
   vlt eyes -g
   ```

   Seul `vaultaire.fr`, le domaine du groupe d'amorçage, existe.

## ✅ Vous avez réussi si

Vous savez dire, pour chaque groupe d'Acme, quel domaine il portera.

## 🧪 Exercice

Une équipe « Sécurité » rattachée à l'infrastructure doit être administrable par
les délégués de l'infrastructure. Quel domaine lui donner ?

<details><summary>Solution</summary>

`secu.infra.acme.lan` : sous `infra.acme.lan`, un droit accordé sur
`infra.acme.lan` **avec propagation** la couvrira automatiquement.
</details>

---

[← Sommaire du chapitre](./README.md) · [Créer groupes et comptes →](./02-creer-groupes-et-comptes.md)
