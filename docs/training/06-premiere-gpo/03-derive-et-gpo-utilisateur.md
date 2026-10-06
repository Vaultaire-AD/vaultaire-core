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

> Depuis la 2.2, la dérive des GPO **utilisateur** est vérifiée elle aussi, à
> la connexion du compte — au plus une fois toutes les cinq minutes par compte
> (`gpo_user_check_minutes`), pour ne pas scanner à chaque déverrouillage
> d'écran. L'environnement est remis en état avant que le shell ne démarre.
>
> Essayez : dans la session d'Alice, `rm ~/.vaultaire_env`, déconnectez-vous,
> attendez cinq minutes — ou `vlt settings set gpo_user_check_minutes 1` — et
> reconnectez-vous. `ACME_ENV` vaut de nouveau `lab`, et `vlt gpo status`
> affiche `ok` sur la ligne d'Alice. Ajouter un alias à son `.bashrc`, en
> revanche, n'est pas un écart : seul le bloc que Vaultaire y tient est
> surveillé.

## 📚 Référence

[`MAN.md` §5.6 et §20](../../Utilisation/MAN.md) ·
[`GPO.md`](../../Developement/how%20it%20work/GPO.md)

---

[← Lier et appliquer](./02-lier-et-appliquer.md) · [Chapitre 7 — DNS →](../07-dns/README.md)
