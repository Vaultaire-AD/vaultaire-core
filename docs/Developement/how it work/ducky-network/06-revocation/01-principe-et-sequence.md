[⌂ Ducky Network](../README.md) › [Chapitre 6 — Révocation — kill switch (06)](./README.md) › 6.1

# 6.1 — Principe et séquence

[← Sommaire du chapitre](./README.md) · [Les trames 06_01 à 06_06 →](./02-trames.md)

---

| Trame | Reçue par | Nom | Rôle |
|---|---|---|---|
| `06_01` | client | revoke_order | verrouiller, déverrouiller ou supprimer un compte local |
| `06_02` | core | revoke_ack | ordre appliqué |
| `06_03` | core | revoke_error | ordre non appliqué |
| `06_04` | core | ask_revocations | ordres en attente (démarrage, tunnel rétabli, puis toutes les dix minutes) |
| `06_05` | client | revocations_list | ordres non acquittés — en réponse à `06_04`, **ou poussée par le core** qui rejoue |
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
| `soft` | Compte marqué révoqué : plus aucune authentification, plus aucune permission | `usermod -L` + `chage -E 1`, **puis** fermeture des sessions et arrêt des processus du compte — home intact | Oui, via `unlock` |
| `unlock` | Marque levée | `usermod -U` + `chage -E -1` | — |
| `hard` | Compte **supprimé** de l'annuaire | même coupure, puis `userdel -r` — compte et répertoire personnel supprimés | **Non** |

**Pourquoi le verrouillage local est indispensable, y compris en `soft`.** Le
module PAM écrit le mot de passe dans le `/etc/shadow` de chaque machine où
l'utilisateur se connecte (`pam_common.c`, `ensure_local_user_with_password`).
Une révocation limitée au serveur laisserait donc le compte utilisable en local
sur toutes ces machines. Un kill switch qui ne coupe pas l'accès n'est pas un
kill switch.

**Verrouiller ne fait sortir personne** *(TO-DO 133)*. Les deux verrous sont
deux écritures dans `/etc/shadow` : ils empêchent d'**entrer**. Une fois `sshd`
fourché et le shell lancé, plus rien ne relit `/etc/shadow`, et la session vivait
jusqu'au `exit` — ou indéfiniment sous `tmux`. L'agent coupe donc, **après**
avoir verrouillé (l'inverse laisserait le temps de se reconnecter) :

1. `loginctl terminate-user <uid>` quand `systemd-logind` tourne — il ferme les
   sessions et le gestionnaire utilisateur, y compris un shell passé root par
   `sudo`, qui garde son appartenance à la session ;
2. `pkill -KILL` par uid réel puis effectif, dans tous les cas ;
3. puis il **compte** ce qui reste, dans `/proc`. S'il reste un processus, l'ordre
   est en échec (`06_03`) : le core le voit, et rejoue.

**Tout ce qui tourne sous le compte s'arrête**, pas seulement ses terminaux : un
`tmux` détaché, un `nohup`, une tâche planifiée. C'est une décision. Sur un
compte compromis, ce qui survit à la fermeture du terminal est précisément ce
que l'attaquant a laissé pour revenir. La contrepartie est assumée : un
verrouillage pour départ interrompt aussi le calcul long que la personne avait
lancé.

**Deux refus, avant toute commande** : jamais l'uid 0, jamais le compte sous
lequel tourne l'agent. L'ordre vient du réseau, et un `pkill -KILL -U 0` ne se
rattrape pas.

**Le mode `hard` détruit le répertoire personnel** (`userdel -r`), conformément
au choix retenu. À garder en tête : sur un compte compromis, cela détruit aussi
les traces de la compromission. Si un jour l'analyse post-incident devient un
besoin, c'est ici qu'il faudra revenir.

## Quelles machines reçoivent l'ordre

Deux ensembles, réunis :

- celles qui **partagent au moins un groupe** avec l'utilisateur — la même règle
  que les GPO utilisateur. C'est l'ensemble des machines où il a pu se connecter,
  donc où un compte local a pu être créé ;
- celles où il a **une session ouverte** au moment du déclenchement, quels que
  soient ses groupes *(TO-DO 133)*.

Les groupes disent où la personne **pouvait** se connecter, pas où elle **est** :
la retirer d'un groupe ne ferme pas la session qu'elle y tenait. La machine la
plus urgente à joindre — celle où le compte travaille en ce moment — pouvait
donc être la seule à ne pas recevoir l'ordre, pendant que la commande affichait
un succès. Le compte rendu dit combien de cibles portent une session ouverte, et
combien ne sont visées que pour cela.

En `hard`, la liste est **figée au moment du déclenchement**, avant la
suppression du compte en base : après la suppression, l'appartenance aux groupes
n'existe plus et la liste serait vide. Les sessions sont lues au même moment,
avant que le core n'efface leurs lignes.

## Quel compte, sur la machine

Le compte local d'une personne s'appelle `nom@domaine` : c'est le module PAM qui
le crée, sous le nom tapé pour se connecter. L'annuaire ne connaît que `nom`, et
c'est ce nom-là qu'un exploitant tape — `vlt kill -u bob.durand`.

*(TO-DO 133.)* L'agent cherchait un compte local de ce nom **exact**, n'en
trouvait pas, journalisait « ordre sans objet » et **acquittait** : rien n'était
verrouillé, sur aucune machine, et le core rangeait l'ordre comme traité. Seule
la forme complète, tapée à la main, atteignait le compte — et le rejeu d'un
ordre en attente relit le nom en base, où il est court.

Un nom **sans domaine** désigne désormais tous les comptes locaux de cette
personne, `nom@<n'importe quel domaine>`, parmi ceux que l'agent a lui-même
provisionnés (`/etc/vaultaire/uid.map`, recoupé avec `/etc/passwd`). Un nom
**avec domaine** désigne ce compte-là. Jamais un compte que l'agent n'a pas
créé : un compte Unix local qui porterait le nom d'une personne de l'annuaire
n'est pas le sien. La comparaison s'arrête à l'arobase — `bob.durand` ne désigne
pas `bob.durandal@…`.

> ⚠️ **Un agent antérieur à ce correctif n'applique rien à un nom court.** Tant
> que tout le parc n'est pas à jour, taper la forme complète, et savoir qu'une
> machine hors ligne au moment de l'ordre ne sera pas traitée à son retour.

## Machines hors ligne

Un ordre est **durable**, pas un message éphémère. Il est écrit en base avec la
liste de ses cibles, poussé immédiatement aux machines connectées, et rejoué
tant qu'il n'est pas acquitté. Une machine éteinte au moment de la révocation
reçoit l'ordre à sa prochaine connexion, via 06_04.

Sans cette persistance, éteindre son poste suffirait à échapper à une
révocation — le seul cas où la précaution compte vraiment.

## Quand l'agent réclame ses ordres

*(TO-DO 134.)* Ce chapitre disait « démarrage, reconnexion ». La demande `06_04`
ne partait qu'**une fois**, d'une goroutine lancée à l'amorçage de l'agent : un
ordre émis pendant que le tunnel était tombé attendait le **redémarrage du
service**. Couper le réseau d'un poste une minute au bon moment suffisait à le
soustraire à une révocation.

`revocation.SurveillerLesOrdres` réclame désormais :

| Quand | Pourquoi |
|---|---|
| au **démarrage** de l'agent | rattraper ce qui a été émis pendant qu'il était arrêté |
| à chaque **tunnel rétabli** — la clé de session a changé | rattraper ce qui a été émis pendant la coupure |
| **toutes les dix minutes**, tant que la session tient | rejouer un ordre poussé en vain à une machine connectée, ou appliqué en échec |

Le rappel est une constante (`RappelDesOrdres`), pas un réglage : c'est la durée
maximale pendant laquelle un compte coupé peut rester ouvert sur une machine
pourtant connectée, et l'allonger pour économiser une trame par machine
allongerait exactement cela. Depuis que le core rejoue lui-même (ci-dessous),
ce rappel est la ceinture ; le rejeu, les bretelles — et le plus rapide des deux.

Le tunnel est scruté, comme le fait déjà le cycle GPO : il est remonté par un
paquet qui n'expose aucune notification, et la clé de session se lit en mémoire.

## Quand le core rejoue de lui-même

*(TO-DO 49.)* Un ordre était poussé **une fois**, au déclenchement, puis le core
attendait qu'on vienne le lui redemander. Trois cas restaient donc ouverts : un
envoi perdu vers une machine pourtant connectée ; un ordre **en échec** — des
processus qui ne meurent pas — que le journal disait « rejoué » sans que rien ne
le rejoue ; une machine tenue par un **autre core** que celui où la commande a
été tapée. Dix minutes d'attente avec un agent à jour, le redémarrage du service
avec un agent antérieur.

`revocationmanager.RejouerLesOrdres` tourne en fond sur chaque core :

| | |
|---|---|
| **Qui** | les machines connectées **à ce core** à qui il reste un ordre non acquitté. La base est commune : chaque nœud sert les siennes |
| **Quoi** | la liste **entière** de ce que la machine n'a pas acquitté, dans l'ordre, par une `06_05` |
| **Quand** | un tour toutes les 5 s ; un ordre est dû 10 s après son premier envoi, puis 20 s, 40 s… plafonné à 5 min |
| **Jusqu'à quand** | l'acquittement. Il n'y a **pas** d'abandon |

**La liste entière, et pas le seul ordre dû.** L'ordre chronologique n'est pas
négociable : un verrouillage puis sa levée, rejoués à l'envers, laissent la
machine fermée. Remettre un ordre en sautant un plus ancien casserait cela.
D'où la `06_05` : c'est la liste que l'agent applique déjà dans l'ordre, qu'il
l'ait demandée ou non — plusieurs `06_01` à la suite auraient dépendu de
l'ordre d'arrivée. Un ordre déjà appliqué est ré-acquitté sans être rejoué.

**Pas d'abandon.** Un kill switch qui renonce au bout de N essais laisse un
compte ouvert sans le dire. Au cinquième essai sans acquittement, le journal
écrit en WARNING que la révocation n'est **pas** effective sur cette machine ;
les rejeux suivants continuent, en DEBUG.

Chaque remise — poussée initiale, réponse à une `06_04`, rejeu — incrémente
`attempts` et date `last_attempt` sur la cible. C'est ce qui espace les essais,
et ce que le suivi montre (plus bas).

### Un verrouillage levé n'est plus rejoué

Le banc a montré ce cas, avec le core d'avant : un verrouillage **en échec** sur
un poste ; l'exploitant le lève (`--unlock`, acquitté) ; l'agent redémarre et
réclame ses ordres. Le verrouillage, toujours « en échec », repartait **seul**
et aboutissait cette fois : le compte se refermait sur le poste alors que
l'annuaire le disait ouvert, et aucun ordre ne restait pour le rouvrir.

À la levée, les cibles qui n'avaient pas acquitté le verrouillage passent donc
au statut **`lifted`** : l'ordre n'a plus d'objet, il ne sera plus remis, et un
compte rendu d'échec arrivé après coup ne le ranime pas. Conséquence : une
machine restée hors ligne pendant tout un verrouillage ne reçoit, à son retour,
que la levée.

Et la levée vise, en plus des machines des groupes du compte, **celles qui sont
encore sous verrou** : une machine verrouillée puis retirée du groupe ne
recevait jamais l'ordre d'ouvrir.

> ⚠️ **Le client Windows n'acquitte aucun ordre** *(TO-DO 79, 167)*. Un poste
> Windows visé reste « en attente », et le core le sollicite toutes les cinq
> minutes sans fin. Il en va de même d'un **service** : un proxy rangé dans un
> groupe avec des comptes est une cible, et n'acquitte rien. Le suivi les
> montre — « remis N fois, aucune réponse de la machine ».

## Où en est un ordre, machine par machine

*(2.3, TO-DO 164.)* Le compte rendu de `kill -u` dit combien de machines ont
**reçu** l'ordre. Ce qu'elles en ont fait s'écrivait en base, cible par cible,
et ne se lisait que dans le journal du core — alors que c'est la question d'un
incident : « où ce compte travaille-t-il encore ? ».

`vlt kill -u <compte> --status` et la fiche du compte du portail y répondent,
par la même action (`revocation.get_status`) et la même décision
(`db_revocation/suivi.go`) : le tri, les libellés, le décompte et le
commentaire. Une sentinelle interdit à la page de trier, de nommer un état ou
de lire la base.

| Statut en base | Libellé | Commentaire |
|---|---|---|
| `failed` | en échec | le motif rendu par la machine (`06_03`) |
| `pending`, `attempts = 0` | en attente | « jamais remis : machine hors ligne depuis l'ordre » |
| `pending`, `attempts > 0` | en attente | « remis N fois, aucune réponse de la machine » |
| `lifted` | levé avant application | — |
| `acked` | appliqué | « ordre appliqué sur la machine » |

**« En attente » se départage par le nombre de remises**, et c'est le rejeu qui
le permet : une machine hors ligne et une machine qui reçoit sans répondre ne
sont pas le même incident, et les deux se lisaient pareil.

**L'âge vient de la base** (`TIMESTAMPDIFF`), comme pour le rejeu : la date est
écrite par `NOW()`, dans le fuseau du serveur de base.

**Une clé de lecture, `read:status:user`** — voir
[6.3](./03-rbac-schema-et-decisions.md). La vue est réduite au périmètre de qui
lit : un ordre vise des machines qui ne lui sont pas toutes visibles ; celles
hors périmètre sont retirées et **comptées**, ordre par ordre.

`--status` ne se combine avec rien : `kill -u bob --hard --status` pourrait se
lire « supprime, puis dis-moi » ; il est refusé, et rien ne part.

## Séquence

```
 Déclenchement (CLI, web ou API)
        │
        ├─ écriture en base : ordre + liste des machines cibles
        ├─ marquage du compte / suppression selon le mode
        ├─ fermeture immédiate des sessions que le SERVEUR tient (Ducky, portail)
        │
        └─ pour chaque machine EN LIGNE :
                serveur ──── 06_01 revoke_order ────► client      verrouille, puis coupe sessions et processus
                serveur ◄─── 06_02 revoke_ack ─────── client      cible passée à « acquittée »
                        ◄─── 06_03 revoke_error ─────            cible passée à « en échec », rejouée par le core

 Machine qui démarre, dont le tunnel revient, ou toutes les dix minutes
                serveur ◄─── 06_04 ask_revocations ── client      après authentification
                serveur ──── 06_05 revocations_list ► client
                serveur ◄─── 06_02 revoke_ack ─────── client      un acquittement par ordre

 Le core, toutes les 5 s, pour chaque machine connectée qui n'a pas tout acquitté
                serveur ──── 06_05 revocations_list ► client      si un ordre est dû (10 s, 20 s, 40 s… 5 min)
                serveur ◄─── 06_02 revoke_ack ─────── client
```

---

[← Sommaire du chapitre](./README.md) · [Les trames 06_01 à 06_06 →](./02-trames.md)
