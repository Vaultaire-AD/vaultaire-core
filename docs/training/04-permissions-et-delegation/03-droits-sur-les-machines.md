[⌂ Formation](../README.md) › [Chapitre 4 — Permissions et délégation](./README.md) › Jalon 4.3

# Jalon 4.3 — Droits sur les machines

[← Déléguer un domaine](./02-deleguer-un-domaine.md) · [Chapitre 5 — Ajouter un client →](../05-ajouter-un-client/README.md)

---

## Objectif

Comprendre comment un utilisateur accède à une machine, et comment il en devient
administrateur.

## Ce qu'il faut savoir

- **Accès** : un utilisateur peut se connecter à une machine dès qu'ils sont
  **dans un groupe commun** — sans privilège par défaut.
- **Administration** : une **permission client** attachée à ce groupe donne des
  droits sur les machines du groupe. Ce n'est pas le même privilège que le
  `web_admin` d'une permission utilisateur.

```text
create -pc <nom> <oui|non>          # oui = administration des machines
add -gc <groupe> -p <nom>           # l'attacher à un groupe
get -p -c [<nom>]                   # la consulter
```

## Étapes

1. Créez la permission d'administration des serveurs :

   ```bash
   vlt create -pc serveurs-admin oui
   vlt add -gc Infra -p serveurs-admin
   vlt get -p -c serveurs-admin
   ```

2. Vous l'éprouverez au [chapitre 5](../05-ajouter-un-client/README.md), une fois
   une machine dans le groupe `Infra`.

## ✅ Vous avez réussi si

`get -g Infra` montre à la fois `admin-infra` (utilisateur) et `serveurs-admin`
(client).

## 🧪 Exercice

Les développeurs doivent **se connecter** aux machines de `Dev` sans en être
administrateurs. Que faut-il créer ?

<details><summary>Solution</summary>

Rien de plus qu'un groupe commun : placer les machines dans `Dev` suffit. Une
permission client n'est nécessaire que pour **élever** les droits.
</details>

## 📚 Référence

[`Group-Permission.md`](../../Utilisation/Group-Permission.md) ·
[`Actions_et_Permissions.md`](../../Utilisation/Actions_et_Permissions.md)

---

[← Déléguer un domaine](./02-deleguer-un-domaine.md) · [Chapitre 5 — Ajouter un client →](../05-ajouter-un-client/README.md)
