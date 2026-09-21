[⌂ Formation](../README.md) › [Chapitre 5 — Ajouter un client](./README.md) › Jalon 5.3

# Jalon 5.3 — Première connexion d'un utilisateur

[← Intégrer la machine](./02-integrer-la-machine.md) · [Chapitre 6 — Première GPO →](../06-premiere-gpo/README.md)

---

## Objectif

Ouvrir une session sur `web01` avec un compte du domaine, puis vérifier les
droits d'administration.

## Ce qu'il faut savoir

- Alice et `web01` sont tous deux dans `Infra` : Alice peut se connecter.
- `Infra` porte la permission client `serveurs-admin` (chapitre 4) : Alice est
  placée dans le groupe d'administration local (`wheel` sur Rocky).
- Le compte local est **créé à la première connexion**, avec son répertoire
  personnel.
- On se connecte sous `compte@domaine`, où le domaine est le **domaine
  principal** d'un groupe du compte — les deux derniers labels : Alice, membre
  de `infra.acme.lan`, se connecte comme `alice.martin@acme.lan`. Un nom sans
  domaine désigne un compte **local** de la machine, et
  `alice.martin@infra.acme.lan` est refusé.

## Étapes

1. Depuis votre poste :

   ```bash
   ssh -l alice.martin@acme.lan <IP-web01>
   id
   sudo -l
   ```

2. Pendant la session, côté serveur, vérifiez que la machine est en ligne :

   ```bash
   vlt status -c
   ```

   `status -u` ne liste pas encore les sessions ouvertes par PAM : elles passent
   dans le tunnel de la machine (TO-DO 68).

3. Essayez avec `chloe.petit`, qui n'est pas dans `Infra` : la connexion est
   refusée.

## ✅ Vous avez réussi si

- Alice obtient un shell, `id` montre `wheel` ;
- Chloé est refusée ;
- `alice.martin@infra.acme.lan` est refusée : ce n'est pas un domaine principal ;
- `web01` figure dans `status -c`, et y reste après la déconnexion d'Alice.

## 🧪 Exercice

Retirez à Alice l'accès à `web01` **sans** supprimer son compte, puis
rendez-le-lui.

<details><summary>Solution</summary>

```bash
vlt remove -u alice.martin -g Infra     # plus de groupe commun : accès refusé
vlt add    -u alice.martin -g Infra
```

Pour couper **tous** ses accès d'un coup, voir `kill` au
[chapitre 9](../09-securite-et-exploitation/README.md).
</details>

## En cas de problème

| Symptôme | Piste |
|---|---|
| `Invalid user` sans rien dans le journal Vaultaire | SELinux bloque le module NSS sous `sshd` : [`docs/exploitation/selinux.md`](../../exploitation/selinux.md), script `deployments/selinux/install.sh` |
| l'agent ne se connecte pas | adresse dans `client_conf.json`, port 6666 filtré, `journalctl -u vaultaire_client` |
| « Permission denied » pour un compte du domaine | pas de groupe commun avec la machine : `get -u <compte>`, `get -g -c <groupe>` |

---

[← Intégrer la machine](./02-integrer-la-machine.md) · [Chapitre 6 — Première GPO →](../06-premiere-gpo/README.md)
