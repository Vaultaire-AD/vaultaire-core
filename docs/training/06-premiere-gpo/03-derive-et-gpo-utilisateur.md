[⌂ Formation](../README.md) › [Chapitre 6 — Première GPO](./README.md) › Jalon 6.3

# Jalon 6.3 — Dérive, audit, et GPO utilisateur

[← Lier et appliquer](./02-lier-et-appliquer.md) · [Chapitre 7 — DNS →](../07-dns/README.md)

---

## Objectif

Provoquer une dérive, choisir entre corriger et constater, puis écrire une GPO
utilisateur.

## Partie A — la dérive

1. Sur `web01`, modifiez la bannière à la main :

   ```bash
   echo "modifié à la main" > /etc/ssh/vaultaire-banner
   systemctl restart vaultaire_client
   ```

2. Côté serveur :

   ```bash
   vlt gpo drift
   ```

   La machine apparaît en écart. En mode **enforce** (le défaut), le module est
   **réappliqué au cycle suivant** — relancez l'agent une seconde fois et la
   bannière revient.

3. Passez la GPO en **audit**, et recommencez :

   ```bash
   vlt gpo mode ssh-baseline audit
   ```

   L'écart est signalé, **rien n'est corrigé**. Revenez ensuite en `enforce`.

## Partie B — une GPO utilisateur

1. Créez une GPO `user` et liez-la :

   ```bash
   vlt create -gpo env-infra --scope user --desc "Variables des admins"
   vlt add -gpo env-infra -g Infra
   ```

2. Dans le portail, ajoutez le module **Variable d'environnement
   utilisateur** : nom `ACME_ENV`, valeur `lab`.

3. Reconnectez-vous en `alice.martin` sur `web01` :

   ```bash
   echo "$ACME_ENV"
   ```

## ✅ Vous avez réussi si

- `gpo drift` a montré l'écart, puis plus rien après correction ;
- `ACME_ENV` vaut `lab` dans la session d'Alice.

## 🧪 Exercice

Pourquoi le module **Configuration SSH serveur** n'est-il pas proposé dans
`env-infra` ?

<details><summary>Solution</summary>

Parce que le scope `user` n'accepte que des modules sans effet sur les
privilèges. La règle est vérifiée par le serveur **et** par l'agent.
</details>

> ⚠️ La dérive des GPO **utilisateur** n'est pas encore vérifiée
> (TO-DO 33) : seul le scope machine est scanné.

## 📚 Référence

[`MAN.md` §5.6 et §20](../../Utilisation/MAN.md) ·
[`GPO.md`](../../Developement/how%20it%20work/GPO.md)

---

[← Lier et appliquer](./02-lier-et-appliquer.md) · [Chapitre 7 — DNS →](../07-dns/README.md)
