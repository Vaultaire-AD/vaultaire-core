[⌂ Ducky Network](../README.md) › [Chapitre 6 — Révocation — kill switch (06)](./README.md) › 6.1

# 6.1 — Principe et séquence

[← Sommaire du chapitre](./README.md) · [Les trames 06_01 à 06_06 →](./02-trames.md)

---

| Trame | Reçue par | Nom | Rôle |
|---|---|---|---|
| `06_01` | client | revoke_order | verrouiller, déverrouiller ou supprimer un compte local |
| `06_02` | core | revoke_ack | ordre appliqué |
| `06_03` | core | revoke_error | ordre non appliqué |
| `06_04` | core | ask_revocations | ordres en attente (démarrage, reconnexion) |
| `06_05` | client | revocations_list | ordres non acquittés |
| `06_06` | client | revocations_error | erreur |

Plage utilisée : `06_01` à `06_06`, libre à partir de `06_07`.

---


> **Statut : validé et implémenté.** Numérotation, bascule de `delete -u` en mode
> hard et confirmation par saisie du nom pour le mode destructeur : les trois ont
> été validés. Le point ouvert n° 4 (lecture des groupes par domaine) était un
> défaut et a été corrigé — voir `migrations/rbac_groupes_stricts.md`.

## Pourquoi une catégorie séparée des GPO

Le transport est très proche de celui des GPO — ordre déclaratif, jamais de
commande shell — mais trois différences justifient de ne pas le loger dans 05 :

| | GPO (05) | Révocation (06) |
|---|---|---|
| Initiative | Le client tire, quand il veut | Le serveur pousse, tout de suite |
| Délai acceptable | Le prochain cycle (1 h) | Immédiat |
| Cible | La machine ou l'utilisateur connecté | Un compte nommé, sur des machines où il n'est pas connecté |
| Cumul | La politique remplace la précédente | Chaque ordre est un événement distinct, à tracer |

Mélanger les deux ferait dépendre une révocation d'urgence du cycle de
rafraîchissement des GPO. C'est précisément ce qu'un kill switch doit éviter.

## Les trois ordres

| Mode | Annuaire | Machines | Réversible |
|------|----------|----------|------------|
| `soft` | Compte marqué révoqué : plus aucune authentification, plus aucune permission | `usermod -L` + `chage -E 1` — compte verrouillé, home intact | Oui, via `unlock` |
| `unlock` | Marque levée | `usermod -U` + `chage -E -1` | — |
| `hard` | Compte **supprimé** de l'annuaire | `userdel -r` — compte et répertoire personnel supprimés | **Non** |

**Pourquoi le verrouillage local est indispensable, y compris en `soft`.** Le
module PAM écrit le mot de passe dans le `/etc/shadow` de chaque machine où
l'utilisateur se connecte (`pam_common.c`, `ensure_local_user_with_password`).
Une révocation limitée au serveur laisserait donc le compte utilisable en local
sur toutes ces machines. Un kill switch qui ne coupe pas l'accès n'est pas un
kill switch.

**Le mode `hard` détruit le répertoire personnel** (`userdel -r`), conformément
au choix retenu. À garder en tête : sur un compte compromis, cela détruit aussi
les traces de la compromission. Si un jour l'analyse post-incident devient un
besoin, c'est ici qu'il faudra revenir.

## Quelles machines reçoivent l'ordre

Celles qui partagent au moins un groupe avec l'utilisateur — la même règle que
les GPO utilisateur, et la fonction existe déjà (`HasSharedGroup`). C'est
exactement l'ensemble des machines où l'utilisateur a pu se connecter, donc
l'ensemble où un compte local a pu être créé.

En `hard`, la liste est **figée au moment du déclenchement**, avant la
suppression du compte en base : après la suppression, l'appartenance aux groupes
n'existe plus et la liste serait vide.

## Machines hors ligne

Un ordre est **durable**, pas un message éphémère. Il est écrit en base avec la
liste de ses cibles, poussé immédiatement aux machines connectées, et rejoué
tant qu'il n'est pas acquitté. Une machine éteinte au moment de la révocation
reçoit l'ordre à sa prochaine connexion, via 06_04.

Sans cette persistance, éteindre son poste suffirait à échapper à une
révocation — le seul cas où la précaution compte vraiment.

## Séquence

```
 Déclenchement (CLI, web ou API)
        │
        ├─ écriture en base : ordre + liste des machines cibles
        ├─ marquage du compte / suppression selon le mode
        ├─ fermeture immédiate des sessions Ducky de l'utilisateur
        │
        └─ pour chaque machine EN LIGNE :
                serveur ──── 06_01 revoke_order ────► client
                serveur ◄─── 06_02 revoke_ack ─────── client      cible passée à « acquittée »
                        ◄─── 06_03 revoke_error ─────            cible passée à « en échec », réessai au cycle suivant

 Machine qui se (re)connecte
                serveur ◄─── 06_04 ask_revocations ── client      après authentification
                serveur ──── 06_05 revocations_list ► client
                serveur ◄─── 06_02 revoke_ack ─────── client      un acquittement par ordre
```

---

[← Sommaire du chapitre](./README.md) · [Les trames 06_01 à 06_06 →](./02-trames.md)
