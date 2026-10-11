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
   vlt create -u alice.martin infra.acme.lan 'Lune-Orange-Velo-42'   14/03/1990
   vlt create -u bob.durand   dev.acme.lan   'Pluie-Sapin-Train-17'  02/11/1994
   vlt create -u chloe.petit  rh.acme.lan    'Cerise-Nuage-Phare-63' 21/07/1988
   ```

   > 🔑 **La politique de mots de passe** refuse un mot de passe de moins de
   > **12 caractères**, ou qui contient le nom du compte, un libellé de son
   > domaine (`infra`, `acme`…), « vaultaire » ou un grand classique
   > (« password », « azerty »…). D'où ces phrases de passe : quatre mots sans
   > rapport avec le compte. « Alice-2026! » serait refusé deux fois.
   >
   > Ils sont aussi **provisoires** : ils ouvrent la session pendant **24 h**,
   > puis cessent de fonctionner tant que le titulaire ne l'a pas changé sur le
   > portail. Si vous reprenez la formation un autre jour, reposez-en un avec
   > `vlt update -u <compte> -p '<phrase de passe>'` (provisoire lui aussi).

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
vlt create -u david.leroy web.dev.acme.lan 'Tulipe-Canal-Brume-58' 05/05/1996 David 'Le Roy'
vlt get -u david.leroy
```
</details>

---

[← Penser l'arborescence de domaines](./01-arborescence-de-domaines.md) · [Rattacher, consulter, retirer →](./03-rattacher-et-consulter.md)
