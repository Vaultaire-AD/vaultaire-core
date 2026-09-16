[⌂ Formation](../README.md) › [Chapitre 2 — Premiers groupes et utilisateurs](./README.md) › Jalon 2.2

# Jalon 2.2 — Créer groupes et comptes

[← Penser l'arborescence de domaines](./01-arborescence-de-domaines.md) · [Rattacher, consulter, retirer →](./03-rattacher-et-consulter.md)

---

## Objectif

Créer les groupes et les premiers utilisateurs d'Acme.

## Syntaxe

```text
create -g <nom> <domaine>
create -u <identifiant> <domaine> <motdepasse> <jj/mm/aaaa> [prénom] [nom]
```

- le domaine d'un utilisateur sert à construire son adresse
  (`identifiant@domaine`) ;
- avec un identifiant `prénom.nom`, prénom et nom sont déduits ;
- la date de naissance est vérifiée.

## Étapes

1. Créez les groupes :

   ```bash
   vlt create -g Infra   infra.acme.lan
   vlt create -g Dev     dev.acme.lan
   vlt create -g Dev-Web web.dev.acme.lan
   vlt create -g RH      rh.acme.lan
   ```

2. Créez trois comptes :

   ```bash
   vlt create -u alice.martin infra.acme.lan 'Alice-2026!' 14/03/1990
   vlt create -u bob.durand   dev.acme.lan   'Bob-2026!'   02/11/1994
   vlt create -u chloe.petit  rh.acme.lan    'Chloe-2026!' 21/07/1988
   ```

3. Vérifiez :

   ```bash
   vlt get -g
   vlt get -u
   vlt eyes -g
   ```

## ✅ Vous avez réussi si

- `eyes -g` montre l'arbre `acme.lan` du jalon précédent ;
- `get -u` liste les trois comptes.

## 🧪 Exercice

Créez `david.leroy` dans `web.dev.acme.lan` en fournissant explicitement le
prénom « David » et le nom « Le Roy », puis retrouvez-le.

<details><summary>Solution</summary>

```bash
vlt create -u david.leroy web.dev.acme.lan 'David-2026!' 05/05/1996 David 'Le Roy'
vlt get -u david.leroy
```
</details>

---

[← Penser l'arborescence de domaines](./01-arborescence-de-domaines.md) · [Rattacher, consulter, retirer →](./03-rattacher-et-consulter.md)
