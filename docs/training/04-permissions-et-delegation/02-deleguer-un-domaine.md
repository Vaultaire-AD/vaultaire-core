[⌂ Formation](../README.md) › [Chapitre 4 — Permissions et délégation](./README.md) › Jalon 4.2

# Jalon 4.2 — Déléguer un domaine

[← Une permission utilisateur](./01-permission-utilisateur.md) · [Droits sur les machines →](./03-droits-sur-les-machines.md)

---

## Objectif

Faire d'Alice l'administratrice du seul domaine de l'infrastructure, et le
vérifier depuis son propre accès.

## Ce qu'il faut savoir

| Pour… | il faut le droit sur… |
|---|---|
| **lister** | un domaine quelconque — la liste est réduite à votre périmètre |
| **consulter** une entité | **un** de ses domaines |
| **modifier** une entité | **tous** ses domaines |

Certains droits ne se délèguent pas par domaine et s'accordent en `all` ou pas
du tout : `web_admin`, `read:log`, `read:dns`, `write:dns`, `read:cluster`,
`write:cluster`, `read:certificate`, `write:certificate`, `write:server`.

La **création** d'un compte exige un droit global : le compte n'a encore aucun
domaine, il ne peut donc pas être rattaché au périmètre d'un délégué.

## Étapes

1. Créez la permission et réglez-la :

   ```bash
   vlt create -p admin-infra oui --desc "Administration de infra.acme.lan"
   for a in read:get:user read:get:group read:get:client \
            write:add:user write:update:user write:add:client; do
     vlt update -pu admin-infra "$a" -a 1 infra.acme.lan
   done
   vlt add -gu Infra -p admin-infra
   ```

   Le `oui` ouvre le portail aux membres (`web_admin`).

2. Depuis la configuration `vlt` d'Alice (chapitre 3, jalon 2) :

   ```bash
   vlt get -u                       # Alice ne voit que les comptes d'infra.acme.lan
   vlt get -u bob.durand            # refusé : Bob n'est pas dans son périmètre
   ```

## ✅ Vous avez réussi si

Alice voit son périmètre, et seulement lui — y compris sur le portail.

## 🧪 Exercice

Le groupe `Secu` (`secu.infra.acme.lan`) est créé. Alice peut-elle en consulter
les membres ? Et si la permission avait été réglée avec `-a 0` ?

<details><summary>Solution</summary>

Avec `-a 1`, oui : `secu.infra.acme.lan` est un sous-domaine de
`infra.acme.lan`. Avec `-a 0`, non : le droit ne couvre que
`infra.acme.lan` lui-même.

```bash
vlt create -g Secu secu.infra.acme.lan
```
</details>

> Plusieurs groupes, plusieurs permissions : un `nil` n'a **pas** la priorité. Si
> un seul des groupes accorde l'action, elle est accordée.

---

[← Une permission utilisateur](./01-permission-utilisateur.md) · [Droits sur les machines →](./03-droits-sur-les-machines.md)
