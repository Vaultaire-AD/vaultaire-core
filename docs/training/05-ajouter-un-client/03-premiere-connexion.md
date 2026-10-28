[⌂ Formation](../README.md) › [Chapitre 5 — Ajouter un client](./README.md) › Jalon 5.3

# Jalon 5.3 — Première connexion d'un utilisateur

[← Intégrer la machine](./02-integrer-la-machine.md) · [Chapitre 6 — Première GPO →](../06-premiere-gpo/README.md)

---

## Objectif

Ouvrir une session sur `web01` avec un compte du domaine, puis vérifier les
droits d'administration.

## Ce qu'il faut savoir

- Alice et `web01` sont tous deux dans `Infra`, et `Infra` porte
  `connexion-infra` (droit `auth`, jalon 4.3) : Alice peut se connecter.
- `Infra` porte la permission client `serveurs-admin` (chapitre 4) : Alice est
  placée dans le groupe d'administration local (`wheel` sur Rocky, `sudo` sur
  Debian et Ubuntu). Le droit suit l'annuaire dans les **deux** sens : retirez
  la permission, et Alice quitte ce groupe à sa connexion suivante.
- Le compte local est **créé à la première connexion** par l'agent, avec son
  répertoire personnel et ses clés publiques dans `~/.ssh/authorized_keys`.
- On se connecte sous `compte@domaine`, où le domaine est le **domaine
  principal** d'un groupe du compte — les deux derniers labels : Alice, membre
  de `infra.acme.lan`, se connecte comme `alice.martin@acme.lan`. Un nom sans
  domaine désigne un compte **local** de la machine, et
  `alice.martin@infra.acme.lan` est refusé.
- Le mot de passe posé au jalon 2.2 est **provisoire** et ne vaut que **24 h**.
  S'il date de plus d'un jour, la connexion est refusée, et l'écran le dit
  (« Votre mot de passe a expiré… ») : reposez-le avec
  `vlt update -u alice.martin -p 'Lune-Orange-Velo-42'`. La session s'ouvre, et
  rappelle de le changer sur le portail.

## Étapes

1. Depuis votre poste :

   ```bash
   ssh -l alice.martin@acme.lan <IP-web01>
   id
   sudo -l
   cat ~/.ssh/authorized_keys
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

- Alice obtient un shell, `id` montre `wheel` (ou `sudo` sur Debian) ;
- `~/.ssh/authorized_keys` porte les clés publiques d'Alice — il était vide
  avant la version 2.3 ;
- Chloé est refusée — sans autre précision : un refus ordinaire ne dit jamais
  pourquoi ;
- avec un mot de passe expiré, Alice lit « Votre mot de passe a expiré » au lieu
  d'un refus sec ;
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
| `Invalid user` sans rien dans le journal Vaultaire | SELinux bloque le module NSS sous `sshd` : [`docs/exploitation/selinux.md`](../../exploitation/selinux.md), script `deployments/selinux/install.sh`. Politique installée : `ps -eZ \| grep vaultaire_clien` doit montrer **`vaultaire_t`** — sinon `restorecon /usr/bin/vaultaire_client` et redémarrer l'agent |
| l'agent ne se connecte pas | adresses dans `client_conf.json`, port 6666 filtré, `journalctl -u vaultaire_client` ; pour un état complet, lancez l'agent avec `-debug` et lisez `/var/log/vaultaire/vlt_client-Debug.log` ([détail](../../exploitation/Agent_configuration_et_debug.md)) |
| la connexion met de longues secondes à aboutir | activez le mode debug de l'agent et lisez `/var/log/vaultaire/vlt_client-Debug-connexions.log` : une ligne par étape, en millisecondes ([détail](../../exploitation/Agent_configuration_et_debug.md#le-journal-des-connexions-to-do-199)). ✅ Vous avez réussi si une connexion d'Alice y laisse ses lignes `fetch-key`, `ouverture` et `pam` |
| « Permission denied » pour un compte du domaine | pas de groupe commun avec la machine : `get -u <compte>`, `get -g -c <groupe>` |

---

[← Intégrer la machine](./02-integrer-la-machine.md) · [Chapitre 6 — Première GPO →](../06-premiere-gpo/README.md)
