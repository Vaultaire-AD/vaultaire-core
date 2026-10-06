[⌂ Formation](../README.md) › [Chapitre 10 — Cluster et proxy](./README.md) › Jalon 10.4

# Jalon 10.4 — Décider ce qu'un proxy expose

[← Topologie : exposition, affinité, rotation](./03-topologie.md) · [Fin de la formation ⌂](../README.md)

---

## Objectif

Lire, depuis le core, ce qu'un proxy relaie — et lui ajouter, changer puis
retirer un relais **sans toucher à sa machine**.

## Ce qu'il faut savoir

Un proxy ouvre des **relais** : un port, un type (`ducky`, `https`, `ldaps`) et
des cibles. Au départ ils viennent de son fichier. Dès que le core écrit une
liste pour lui, c'est elle qui fait foi ; le proxy l'applique sans redémarrer et
**rend compte** de ce qu'il a obtenu. Le core demande, seul le proxy sait si le
port était libre.

## Syntaxe

```text
cluster relais <proxy>
cluster relais <proxy> set <nom> [--type … --ecoute … --source … --max …]
cluster relais <proxy> remove <nom>
cluster relais <proxy> release
```

## Étapes

1. Lisez ce que le proxy du jalon 10.2 expose :

   ```bash
   vlt cluster relais <nœud-proxy>
   ```

   Un relais `ducky`, état **du fichier** : le core ne pilote pas encore.

2. Ajoutez un relais LDAPS vers les cores :

   ```bash
   vlt cluster relais <nœud-proxy> set ldaps --type ldaps --ecoute :1636
   vlt cluster relais <nœud-proxy>
   ```

   Deux relais, **appliqué** l'un et l'autre : le premier ajout a pris la main
   en gardant ce qui tournait. La révision est passée à 1.

3. Changez un seul réglage, puis demandez une écoute que le proxy ne peut pas
   ouvrir — une adresse que sa machine ne porte pas :

   ```bash
   vlt cluster relais <nœud-proxy> set ldaps --max 200
   vlt cluster relais <nœud-proxy> set web --type https --ecoute 203.0.113.9:8443 --source liste --adresses 10.0.0.20:443
   vlt cluster relais <nœud-proxy>
   ```

   `web` est **refusé**, avec le motif de la machine. Les deux autres tournent.

4. Retirez-le, puis rendez la main au fichier :

   ```bash
   vlt cluster relais <nœud-proxy> remove web
   vlt cluster relais <nœud-proxy> release
   vlt cluster relais <nœud-proxy>
   ```

   Retour à l'état **du fichier** : le relais `ldaps` a été refermé.

Les mêmes gestes se font sur **Admin → Cluster**, en cliquant le proxy.

## ✅ Vous avez réussi si

Chaque écriture se lit dans la minute — en pratique dans la seconde — sur la
ligne « révision N appliquée par le proxy », et le journal du core porte une
ligne `SECURITY` par changement.

## 🧪 Exercice

Le relais `ldaps` de l'étape 2 est « appliqué », mais une application du site ne
parvient pas à s'y connecter. Pourquoi, et où cela se corrige-t-il ?

<details><summary>Solution</summary>

Le proxy écoute sur 1636 **dans son conteneur**. Le site ne l'atteint que si ce
port est publié par `docker-compose.yml` :

```yaml
    ports:
      - "6667:6666"
      - "1636:1636"
```

Le core ne voit pas ce que la machine publie : c'est la seule partie d'un ajout
de relais qui se fait encore chez le proxy. Hors conteneur, le relais serait
joignable aussitôt.
</details>

> Changer un relais ouvre ou ferme un port sur une machine d'un autre site : le
> droit est **`write:relay`**, distinct de `write:cluster`. Un proxy peut aussi
> refuser d'être piloté (`pilotage_par_le_core: false` dans son fichier).

## 📚 Référence

[`proxy/pilotage.md`](../../proxy/pilotage.md) ·
[`MAN.md` §21](../../Utilisation/MAN.md) ·
[protocole, page 4.4](../../Developement/how%20it%20work/ducky-network/04-cluster/04-relais-pilotes.md)

---

[← Topologie : exposition, affinité, rotation](./03-topologie.md) · [Fin de la formation ⌂](../README.md)
