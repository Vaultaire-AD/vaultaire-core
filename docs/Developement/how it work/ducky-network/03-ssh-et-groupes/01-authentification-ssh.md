[⌂ Ducky Network](../README.md) › [Chapitre 3 — Poste de travail : SSH, PAM et groupes (03)](./README.md) › 3.1

# 3.1 — Authentification SSH / PAM

[← Sommaire du chapitre](./README.md) · [Synchronisation des groupes de la machine →](./02-synchronisation-des-groupes.md)

---

| Trame | Reçue par | Nom | Rôle |
|---|---|---|---|
| `03_01` | core | client ask if user can login | l'agent envoie identifiant et mot de passe |
| `03_02` | client | success | `is_admin`, la ligne `groups:`, puis les clés publiques du compte |
| `03_03` | client | failed | refus et raison |
| ~~`03_04`~~ | core | **obsolète** | demandait le sel d'un compte — refusée par « obsolete client » |
| ~~`03_05`~~ | client | **obsolète** | rendait sel + nonce — journalisée en WARNING par l'agent |
| `03_06` | core | fetch_pubkey | clés publiques seules, sans authentifier personne |
| `03_07` | client | fetch_pubkey_response | réponse à `03_06` |
| `03_08` | core | group_sync_request | liste des groupes des domaines de la machine — contenu vide |
| `03_09` | client | group_sync_list | `sync:<minutes>` puis une ligne `<nom>:<id_group>` par groupe |
| `03_10` | client | group_sync_denied | refus : l'agent garde ses groupes |

Plage utilisée : `03_01` à `03_10`.

---


## Ce qui a changé, et pourquoi

L'échange comptait DEUX allers-retours :

```
03_04  le poste demande le sel du compte
  03_05  le serveur rend sel + nonce
03_01  le poste renvoie HMAC(clé = SHA-256(sel‖mot de passe), nonce)
  03_02  le serveur rend is_admin + clés publiques
  03_03  refus
```

Le mot de passe ne traversait jamais le réseau — mais le serveur devait
recalculer le même HMAC, donc **stocker la clé qui servait à le produire**.
L'empreinte en base était par conséquent directement rejouable : la lire
suffisait à ouvrir une session SSH sur n'importe quel compte, sans connaître le
mot de passe et sans rien casser. Le hachage ne protégeait rien sur ce chemin,
et interdisait de passer à argon2id — le poste aurait dû le calculer à
l'identique, et l'empreinte serait restée la clé.

## Échange actuel

```
03_01  <utilisateur@domaine>\n<mot de passe>
  03_02  <utilisateur@domaine>\n<is_admin>\ngroups:<g1>,<g2>\n<clé pub 1>\n<clé pub 2>…
  03_03  <utilisateur@domaine>\n<raison>

03_06  <utilisateur@domaine>              demande des clés publiques seules
  03_07  vaultaire\n\n<utilisateur@domaine>\n<clés>

03_08  (vide)                            synchronisation des groupes du domaine
  03_09  sync:<minutes>\n<nom>:<id_group>…
  03_10  <raison>

03_04  OBSOLÈTE — refusée par « obsolete client, update required »
03_05  OBSOLÈTE — l'agent la journalise en WARNING
```

`03_08` à `03_10` ont leur propre page : [3.2 — Synchronisation des
groupes de la machine](./02-synchronisation-des-groupes.md).

## La ligne des groupes dans `03_02`

Les clés publiques occupent « tout le reste » du contenu : il n'existait donc
aucune position libre APRÈS elles. La liste des groupes se place avant, et se
reconnaît à son **préfixe** `groups:` plutôt qu'à son rang.

Compter les lignes aurait lié l'agent à une version précise du serveur : face à
un serveur qui n'envoie pas encore la ligne, tout serait décalé et la première
clé serait lue comme une liste de groupes. Avec le préfixe, son absence est
simplement un contenu sans groupes.

**La compatibilité ne va que dans un sens, et c'est assumé.** Un agent à jour
fonctionne avec un serveur ancien : il n'applique aucune appartenance, soit
l'ancien comportement. L'inverse ne tient pas — un agent ancien prend la ligne
pour une clé et l'écrit dans `authorized_keys`, où sshd l'ignore comme entrée
malformée. Le fichier étant réécrit à chaque connexion, l'artefact disparaît dès
la mise à jour. Ce chemin porte déjà une contrainte de version du même ordre :
voir `03_04`.

Le préfixe est déclaré **des deux côtés** — l'agent et le serveur sont des
modules Go distincts, et aucune compilation ne peut les tenir liés. Deux tests
jumeaux figent la chaîne (`sshauth/groupes_trame_test.go` et
`ssh_client_test.go`) : sans eux, un changement d'un seul côté échouerait en
silence, puisque sshd ne signale pas les lignes qu'il ignore.

### Ce que l'agent en fait

Il **ne retire que ce qu'il a lui-même posé**. `/etc/group` porte aussi les
appartenances de l'administrateur local, d'un paquet, d'un installeur : aligner
naïvement sur la liste du serveur les effacerait toutes, silencieusement, à la
première connexion et sur tout le parc à la fois.

La mémoire de ce qu'il a posé est `/etc/vaultaire/user_groups.map`, sur le modèle
de `uid.map`. État illisible ⇒ **aucun retrait** : retirer sans savoir ce qu'on a
posé reviendrait exactement à ce que le fichier existe pour éviter.

Il ne **crée** aucun groupe : un groupe du domaine absent de la machine est
ignoré, et le journal le dit. C'est l'objet de la [page suivante](./02-synchronisation-des-groupes.md).

Le mot de passe transite à l'intérieur de la session Ducky, déjà chiffrée et
authentifiée, exactement comme sur les trois autres portes du serveur : portail
web, bind LDAP, et trame `02_03`. L'empreinte stockée redevient vérifiable sans
être rejouable.

`03_04` et `03_05` ne sont pas simplement effacées : chaque camp répond
explicitement quand l'autre est resté à l'ancienne version. Sans cela, un agent
non mis à jour attendrait sept secondes puis rendrait « timeout » à PAM, et
l'administrateur chercherait une panne réseau.

## Ordre des contrôles dans `SSH_SEND_Pubkey_AUTH`

L'ordre n'est pas indifférent :

1. **limitation de débit** — avant tout, y compris avant de savoir si le compte
   existe. Cette porte-ci n'en avait pas ; elle prend désormais un mot de passe ;
2. **compte inconnu** — même refus, même message qu'un mot de passe faux ;
3. **mot de passe** — une panne de lecture de la base n'est PAS comptée comme un
   échec, sinon une base indisponible freinerait tout le parc ;
4. **kill switch** — APRÈS la vérification, pour ne pas révéler l'état d'un
   compte à qui n'en détient pas les identifiants ;
5. **droit sur le domaine**, puis **droit sur la machine** ;
6. clés publiques et statut administrateur.

### Le domaine de connexion

Le domaine tapé (`alice@test.fr`) doit être un **domaine principal** du compte :
les deux derniers labels du domaine d'un de ses groupes. Un membre de
`infra.cloud.test.fr` se connecte comme `alice@test.fr`, et sous rien d'autre —
ni `alice@infra.cloud.test.fr`, ni un domaine où il n'a aucun groupe, même
existant. Le domaine s'écrit en minuscules : `Alice@Test.FR` créerait un second
compte local pour la même personne. Un compte présent sous deux domaines
principaux a deux identités, donc deux comptes locaux distincts.

Le droit `auth` est ensuite évalué sur les domaines des groupes du compte situés
sous ce domaine principal — un seul suffit.

Avant, le domaine n'était comparé qu'à l'annuaire **entier** : un compte portant
`auth` partout (un administrateur) se connectait sous n'importe quel domaine
existant. Et `03_06` (clés publiques pour sshd) ne contrôlait pas le domaine du
tout : `alice@nimporte.quoi` recevait les clés d'alice. Les deux trames
appliquent désormais la même règle (`permission.CanUserConnectToDomain`).

Tous les refus rendent `03_03` avec le même libellé : distinguer les motifs
transformerait cette trame en oracle.

---

[← Sommaire du chapitre](./README.md) · [Synchronisation des groupes de la machine →](./02-synchronisation-des-groupes.md)
