[⌂ Formation](../README.md) › [Chapitre 6 — Première GPO](./README.md) › Jalon 6.1

# Jalon 6.1 — Créer une GPO machine

[← Sommaire du chapitre](./README.md) · [Lier et appliquer →](./02-lier-et-appliquer.md)

---

## Objectif

Créer une GPO qui ajoute une bannière et limite les tentatives SSH sur les
serveurs de l'infrastructure.

## Ce qu'il faut savoir

- Une GPO ne contient **jamais** de script : c'est une liste de **modules** pris
  dans un catalogue (SSH, sysctl, paquets, services, pare-feu, fichiers…).
- Le **scope** est définitif :

| Scope | Appliquée | Modules |
|---|---|---|
| `machine` | au démarrage de l'agent puis toutes les heures | tous |
| `user` | à l'ouverture de session | seulement ceux sans effet sur les privilèges |

- Les modules s'ajoutent **dans le portail** (Admin → GPO → détail).

## Étapes

1. Créez la GPO :

   ```bash
   vlt create -gpo ssh-baseline --scope machine --desc "Bannière et limites SSH"
   vlt get -gpo
   ```

2. Dans le portail, **Admin → GPO → ssh-baseline**, ajoutez le module
   **Configuration SSH serveur** :
   - Bannière de connexion : `Serveur Acme — accès réservé`
   - MaxAuthTries : `3`
   - laissez **PasswordAuthentication** à sa valeur actuelle : le passer à `no`
     couperait les connexions par mot de passe du chapitre 5.

3. Relisez le détail et son **empreinte** :

   ```bash
   vlt get -gpo ssh-baseline
   ```

## ✅ Vous avez réussi si

`get -gpo ssh-baseline` montre le module et une empreinte SHA-256.

## 🧪 Exercice

Ajoutez un deuxième module qui garantit que le paquet `chrony` est installé.
L'empreinte change-t-elle ?

<details><summary>Solution</summary>

Module **Paquet logiciel**, paquet `chrony`, état `present`. Oui : l'empreinte
change dès qu'un module, un paramètre ou la version bouge — c'est elle qui
déclenche la réapplication côté agent.

Si `chrony` n'est pas proposé, il faut d'abord l'autoriser dans **Admin → GPO →
Restrictions** (réservé au groupe `vaultaire`).
</details>

---

[← Sommaire du chapitre](./README.md) · [Lier et appliquer →](./02-lier-et-appliquer.md)
