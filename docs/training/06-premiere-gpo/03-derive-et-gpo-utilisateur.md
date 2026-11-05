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
   vlt gpo status
   vlt logs --level WARNING --since 10m
   ```

   En mode **enforce** (le défaut), tout s'est joué dans le même cycle : l'agent
   a vu l'écart, **reposé** la bannière, puis constaté que tout était en place.
   `gpo status` dit `ok`, et `gpo drift` ne montre rien. L'écart n'est pas
   perdu pour autant — il est au journal : `gpo: dérive machine sur web01 —
   1 écart(s)…`.

3. Passez la GPO en **audit**, faites-le savoir à la machine, puis recommencez
   l'étape 1 :

   ```bash
   vlt gpo mode ssh-baseline audit
   vlt gpo refresh --gpo ssh-baseline   # le mode voyage avec la politique : il lui faut un cycle
   # … étape 1 sur web01 …
   vlt gpo drift
   vlt gpo status <computeur_id>
   ```

   Cette fois l'écart est signalé et **rien n'est corrigé** : la machine reste
   dans `gpo drift`, et le détail de l'écart commence par
   `[audit : signale, non corrige]`. C'est à cela qu'on reconnaît les deux
   modes : un écart qui **reste** affiché est en audit — ou n'a pas pu être
   corrigé.

   Revenez ensuite en `enforce`. Lisez la réponse de la commande : elle dit
   **quand** les machines appliqueront le changement — à leur prochain cycle —
   et comment ne pas attendre : le bouton « Demander un cycle » de la fiche de
   la GPO, ou `vlt gpo refresh --gpo ssh-baseline`.

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

4. Une valeur **par personne** : ajoutez deux modules **Configuration git** —
   `user.name` = `%n`, `user.email` = `%m` — puis reconnectez-vous :

   ```bash
   git config --global --list     # user.name=Alice Martin, user.email=alice.martin@acme.lan
   ```

   Chaque membre d'`Infra` reçoit **son** nom et **son** adresse, tirés de
   l'annuaire, avec la même GPO. Marqueurs : `%u` (compte court), `%U`
   (compte complet), `%d` (domaine), `%n` (nom), `%m` (adresse), `%%` (un `%`).
   Un autre marqueur est refusé à l'enregistrement.

## ✅ Vous avez réussi si

- en `enforce` la bannière est revenue seule et le journal garde l'écart ; en `audit` la machine reste dans `gpo drift` ;
- `ACME_ENV` vaut `lab` dans la session d'Alice.
- `git config --global user.name` rend le nom d'Alice, pas `%n`.

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
> compte Alice parmi les comptes `ok` de `web01` (un compte n'a sa propre ligne,
> sous sa machine, que s'il a un écart). Ajouter un alias à son `.bashrc`, en
> revanche, n'est pas un écart : seul le bloc que Vaultaire y tient est
> surveillé.

## 🧪 Exercice — le fragment intact, l'effet perdu

Sur `web01`, sans toucher au fragment de Vaultaire, faites appliquer à sshd
`MaxAuthTries 10` au lieu des 3 de `ssh-baseline`. Que dit `vlt gpo status`,
en audit puis en enforce ? Et pourquoi le fragment s'appelle-t-il `00-…` ?

<details><summary>Solution</summary>

sshd retient la **première** valeur qu'il lit : une ligne en tête de
`sshd_config`, avant sa ligne `Include`, l'emporte sur tous les fragments.

```bash
sudo sed -i '1i MaxAuthTries 10' /etc/ssh/sshd_config && sudo systemctl reload sshd
sudo sshd -T | grep maxauthtries          # 10
vlt gpo refresh <computeur_id>
vlt gpo status <computeur_id>
```

- **audit** : un écart `system_state sshd` — « sshd maxauthtries : 3 attendu,
  10 constaté — une directive lue avant … l'emporte ». Rien n'est corrigé.
- **enforce** : le module est rejoué et **échoue** — « fragment écrit mais sans
  effet ». Réécrire le fragment ne sert à rien tant que la ligne qui le masque
  est là : c'est sur le poste qu'il faut la retirer (`sed -i '1d'`), et le cycle
  suivant le dit appliqué.

`00-` le fait passer avant les fragments des distributions (`40-redhat-…`,
`50-cloud-init.conf`) : nommé `99-`, il était lu le dernier, donc masqué par
n'importe lequel. Ce contrôle par `sshd -T` vient de la 2.3 (TO-DO 182).
</details>

## 📚 Référence

[`MAN.md` §5.6 et §20](../../Utilisation/MAN.md) ·
[`GPO.md`](../../Developement/how%20it%20work/GPO.md)

---

[← Lier et appliquer](./02-lier-et-appliquer.md) · [Chapitre 7 — DNS →](../07-dns/README.md)
