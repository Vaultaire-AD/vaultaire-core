# Analyse — l'ouverture d'une session SSH (TO-DO 190)

> 14/10/2026. **Lecture du code, pas mesure.** Rien n'a tourné sur la VM de la
> recette ; les durées données ici sont des **planchers** et des **bornes**
> lus dans le code, jamais des chronométrages. Le § 5 dit comment mesurer, et
> c'est par là qu'il faut continuer (`A_TESTER.md`, § 86).

## 0. Le constat

Recette du 12/10 (§ 53) : les GPO de compte s'appliquent bien, mais il faut
**environ 20 secondes** pour obtenir le terminal d'une connexion SSH, avec cinq
modules de compte, sans `HOME` en réseau, sur une VM peu chargée.

Sur le banc du point 135 (agent réel, authentifications jouées à la main sur
le socket PAM, sans `sshd`), le cycle GPO de compte prenait **0,2 à 1,1 s**.
Le cycle GPO seul n'explique donc pas 20 s, sauf s'il atteint une de ses bornes
(§ 3, H2). Le reste est à chercher **autour** de lui : dans `sshd`, dans les
appels répétés de l'agent, et dans le travail système fait à chaque connexion.

## 1. Le chemin, étape par étape

Configuration posée par `rocky.sh` / `debian.sh` :

```
AuthenticationMethods publickey,keyboard-interactive
AuthorizedKeysCommand /usr/bin/vaultaire_client --fetch-key %u
```

Une connexion passe donc par **deux** authentifications successives, puis la
session.

| # | Étape | Qui | Où dans le code | Coût fixe | Borne |
|---|---|---|---|---|---|
| A | Résolution du compte (`getpwnam`) | `sshd` → NSS | `nss_vaultaire.c` | négligeable si le compte est dans `/etc/passwd` | 300 ms (`VAULTAIRE_UID_TIMEOUT_MS`), première connexion seulement |
| B | **Clé publique** : `sshd` lance `vaultaire_client --fetch-key` | nouveau processus | `main.go`, `serveur_communication/waitForSSHFetch.go` | voir § 2.1 — **≈ 1,2 s par appel au minimum** | 1 + 5 + 10 s par appel |
| C | **keyboard-interactive** : invites « Password » puis code TOTP | `pam_ssh_auth_module.c` | `pam_get_authtok`, `pam_prompt` | **le temps de frappe de la personne** | — |
| D | Le module envoie la demande au socket de l'agent | `pam_common.c` `vaultaire_socket_send_recv` | — | **aucune** : `recv` sans délai, jusqu'à ce que l'agent ferme |
| E | L'agent envoie `03_01` dans le tunnel machine, attend `03_02` | `pam_communication/PAM_Handler.go` | 1 aller-retour + vérification argon2id au core (19 Mio, 2 tours : quelques dizaines de ms) | 7 s |
| F | À la réception de `03_02` : provisionnement du compte | `sshauth/sshAuthManager.go` → `ProvisionVaultaireUser` | écriture de `authorized_keys`, **`restorecon -RF` sur tout le `HOME`**, groupes | proportionnel à la taille du `HOME` | — |
| G | **Cycle GPO de compte**, avant de rendre la main à PAM | `gpo.RunUserCycle` | rattrapage d'inventaire, scan d'écart (si dû), `05_05` → manifeste → un aller-retour **par fragment**, application, rapport `05_12`, constat `05_15` | 0,2 à 1,1 s mesurés au banc | 6 s pour la politique (`UserFetchTimeout`) **+ 10 s par commande** de module (`UserCommandTimeout`) |
| H | Retour au module PAM : **provisionnement, une seconde fois** | `pam_ssh_auth_module.c` | `useradd` (première fois), `chpasswd` (si le mot de passe a changé), **`usermod -aG` ou `gpasswd -d` du groupe sudo à chaque connexion**, réécriture de `authorized_keys`, **`restorecon -RF` sur tout le `HOME`, de nouveau** | 2 à 3 `fork`/`exec`, plus le `restorecon` | — |
| I | Phase `account` | `pam_sm_acct_mgmt` | contrôle local, sans réseau | négligeable | — |
| J | Phase `session` : `pam_systemd`, `pam_selinux`, motd, lastlog | pile du système | démarrage de `user@UID.service` à la première session du compte | hors Vaultaire | — |

## 2. Ce qu'une connexion coûte, sur le papier

### 2.1 `--fetch-key` : une session Ducky complète à chaque appel

C'est le constat le plus net. À chaque appel, `sshd` lance un **nouveau
processus** `vaultaire_client`, qui :

1. lit sa configuration et son identité ;
2. ouvre **sa propre** connexion TCP au premier pair de la liste, refait la
   poignée de main Ducky et l'authentification machine (`02_01` → `02_04`),
   et envoie l'inventaire `02_12` — c'est-à-dire tout ce que le tunnel du démon,
   déjà ouvert, a fait au démarrage ;
3. **attend une seconde, sans condition** (`time.Sleep(1 * time.Second)` dans
   `WaitForSSHFetch`), puis interroge le registre des sessions toutes les
   200 ms (`WaitForVaultaireSession`, abandon à 5 s) ;
4. envoie `03_06`, attend les clés (abandon à 10 s), les écrit sur la sortie
   standard, envoie `02_05` et se termine.

La poignée de main se fait pendant la seconde d'attente : le coût d'un appel est
donc d'environ **max(1 s, poignée de main) + jusqu'à 200 ms + un aller-retour**,
soit **≈ 1,2 s au minimum**.

Et `sshd` n'appelle pas `AuthorizedKeysCommand` une seule fois. D'ordinaire, il
l'appelle **deux fois pour la clé acceptée** (le sondage, puis la requête
signée) et **une fois pour chaque clé refusée** que le client présente avant
elle. Un client dont l'agent SSH porte trois clés peut donc en déclencher
quatre : **≈ 5 s** avant même l'invite du mot de passe. *À confirmer sur la VM*
en comptant les lignes `Fin du WaitForSSHFetch` d'une seule connexion.

Bornes d'un appel : 1 + 5 s pour obtenir une session, puis 10 s pour la
réponse. Aucun délai de lecture n'est posé dans la poignée de main du socle
(`ducky-network-sdk-service`) : un pair qui accepte la connexion sans répondre
retient l'appel jusqu'à ces bornes. C'est aussi le mécanisme du **186**.

### 2.2 Le travail système fait à chaque connexion, et fait deux fois

Les étapes F et H font le même travail, l'une dans l'agent, l'autre dans le
module PAM :

| Travail | Agent (F) | Module PAM (H) |
|---|---|---|
| écrire `authorized_keys` | oui, avec les clés de `03_02` | oui, avec la liste rendue par l'agent — **vide**, voir § 4.1 |
| `restorecon -RF` | sur **tout** le `HOME` | sur **tout** le `HOME`, de nouveau |
| groupe sudo | édition directe du fichier de groupes (admin seulement) | `usermod -aG` ou `gpasswd -d` **à chaque connexion**, admin ou non |

`restorecon -RF` parcourt **toute** l'arborescence du dossier personnel et lit
les attributs étendus de chaque fichier. Sur un `HOME` neuf, c'est négligeable.
Sur un dossier de développeur (dépôts, `node_modules`, caches), cela peut
prendre plusieurs secondes, et c'est payé **deux fois**. Seuls le dossier
lui-même et `~/.ssh` ont besoin de ce relabel.

`usermod` et `gpasswd` réécrivent `/etc/group` et `/etc/gshadow`. Sur une
distribution construite avec la prise en charge de sssd, ils invalident aussi
les caches (`sss_cache`, `nscd`) quand ces outils sont présents. Coût à mesurer,
mais payé à chaque connexion pour un résultat qui ne change presque jamais.

### 2.3 Aucun budget global

Les bornes s'additionnent sans plafond commun :

- le module PAM attend l'agent **sans délai** (`recv` en boucle jusqu'à la
  fermeture) ;
- l'agent attend `03_02` jusqu'à 7 s ;
- puis la politique de compte jusqu'à 6 s ;
- puis chaque commande de module jusqu'à 10 s (`systemctl --user` par
  `runuser`, `chage`, `usermod`, `git config`) ;
- le module `user_resource_limits` lance un `systemctl daemon-reload` **du système** à
  chaque application — de l'ordre de la seconde sur une VM.

Une connexion peut donc durer bien au-delà de 20 s sans qu'aucune de ces bornes
ne soit franchie, ni qu'aucune erreur ne soit journalisée.

### 2.4 Ce que le journal permet de voir aujourd'hui

- `vaultaire_pam.log` (module PAM) : **aucun horodatage** — impossible d'y
  situer une étape dans le temps ;
- `vaultaire.log` (agent, et aussi les processus `--fetch-key`) : horodaté **à
  la seconde** ;
- la seule durée journalisée est celle du cycle GPO
  (`GPO: cycle user/<compte> termine en …`).

On ne peut donc pas, avec les journaux de Vaultaire seuls, dire où sont passées
les 20 s. Le § 5 contourne ce manque avec `strace` et le journal de `sshd`.

## 3. Hypothèses, de la plus probable à la moins probable

| | Hypothèse | Ce qui la confirme | Ordre de grandeur |
|---|---|---|---|
| **H1** | `--fetch-key` appelé 2 à 4 fois, chaque appel avec sa session Ducky et sa seconde d'attente | nombre de `Fin du WaitForSSHFetch` par connexion ; `strace` (§ 5.3) | 2,5 à 5 s |
| **H2** | Le cycle GPO de compte atteint sa borne de 6 s : politique, ou fragment, sans réponse | `GPO: aucune reponse du serveur en 6s pour le scope user` | 6 s pile |
| **H3** | `restorecon -RF` sur un `HOME` volumineux, deux fois | `strace` : durée des deux `execve("restorecon")` ; `find ~ | wc -l` | 0 à plusieurs secondes, ×2 |
| **H4** | Un module lance une commande qui attend : `systemctl --user` (`user_cron`) sans bus de session à ce stade, `daemon-reload` (`user_resource_limits`) | `strace` : la commande et sa durée ; `cycle user/… termine en` élevé | jusqu'à 10 s par commande |
| **H5** | Hors Vaultaire : temps de frappe du mot de passe **et** du code, `GSSAPIAuthentication`, DNS inverse, premier démarrage de `user@UID.service` | `ssh -vvv` horodaté (§ 5.2) | 1 à 10 s |

**À éliminer d'abord : H5, le temps de frappe.** La chaîne demande un mot de
passe **puis** un code TOTP. Un « terminal en 20 s » mesuré depuis
`Entrée` sur la commande `ssh` compte la saisie des deux. Le chiffre à suivre
est le temps entre la **validation du code** et l'invite du shell, plus le
temps avant la **première invite**.

Ce qui semble exclu : le core lui-même. La vérification argon2id coûte quelques
dizaines de millisecondes, il n'y a aucune attente fixe sur le chemin `03` ni
sur le chemin `05` du core, et le freinage n'agit qu'après des échecs.

## 4. Constats annexes

### 4.1 Cause très probable du 188 : `authorized_keys` réécrit vide

Le 188 dit : les clés publiques du compte ne sont pas écrites dans
`authorized_keys`. Le code explique pourquoi, sans aucun réglage en cause :

1. à la réception de `03_02`, l'agent écrit **bien** les clés
   (`ProvisionVaultaireUser` → `EcrireClesAutorisees`) ;
2. il réveille ensuite le gestionnaire PAM avec un `pamstate.AuthResult`
   **sans le champ `SSHKeys`** (`sshauth/sshAuthManager.go`, cas `"02"`) ;
3. `PAM_Handler.go` en tire une liste **vide**, et la renvoie au module ;
4. le module PAM lit une liste vide mais lisible. Il **réécrit**
   `authorized_keys`, et ne laisse rien : c'est la règle voulue (« l'annuaire
   fait foi, une liste vide vide le fichier »), appliquée à une liste qui
   n'aurait pas dû être vide.

La connexion réussit quand même : avec `AuthorizedKeysCommand`, `sshd` ne lit
pas le fichier, il interroge `--fetch-key`. Le défaut ne se voit donc que dans
le fichier, et sur tout ce qui s'en sert hors de `sshd`.

### 4.2 `--fetch-key` et le premier pair (186)

`EstablishDuckySession` parcourt bien la liste des pairs, mais :

- `net.DialTimeout` donne **10 s** à chaque pair qui ne répond pas, alors que
  `WaitForSSHFetch` abandonne au bout de **6 s** au total ;
- la poignée de main n'a **aucun délai de lecture** : un pair qui accepte la
  connexion sans répondre bloque l'appel jusqu'à cet abandon.

Un premier pair muet suffit donc à faire échouer chaque appel de `sshd`. C'est
ce que décrit le 186, et le **187** (une liste de pairs jamais relue) le
déclenche.

## 5. Mesurer, sur la VM de la recette

Le protocole complet est dans `A_TESTER.md`, § 86. En résumé :

1. **Noter les cinq modules** de la GPO de compte, et l'éventuel
   `gpo_user_check_minutes`.
2. **Côté client**, horodater ce que voit `ssh` :
   `ssh -vvv -o GSSAPIAuthentication=no <compte>@<poste> 2>&1 | ts -s '%.s'`
   (`ts` : paquet `moreutils`). Repérer : l'acceptation de la clé, l'invite du
   mot de passe, l'invite du code, `Authenticated to`, la première invite du
   shell.
3. **Côté poste, la mesure qui tranche** : tracer tout ce que `sshd` et l'agent
   lancent, avec l'heure à la milliseconde :
   ```
   strace -f -tt -e trace=execve,exit_group -o /tmp/ouverture.trace \
          -p "$(pgrep -o -x sshd)" -p "$(pgrep -o vaultaire_client)"
   ```
   Chaque `vaultaire_client --fetch-key`, `restorecon`, `usermod`, `gpasswd`,
   `runuser`, `systemctl` y apparaît avec son début et sa fin.
4. Le journal de l'agent pendant la même connexion : nombre de
   `Fin du WaitForSSHFetch`, ligne `cycle user/<compte> termine en …`, et toute
   ligne `aucune reponse du serveur en 6s`.
5. **Mesures isolées** : `time vaultaire_client --fetch-key <compte@domaine>`
   en root ; `time restorecon -RFn /home/<compte@domaine>` et
   `find /home/<compte@domaine> | wc -l`.
6. Rejouer la connexion **sans GPO de compte** (le groupe retiré de la GPO),
   puis **avec une seule clé** (`-o IdentitiesOnly=yes -i <clé>`) : les deux
   écarts disent ce que coûtent G et B.

Le résultat attendu de cette mesure est une ligne par étape du § 1, en
secondes. Il confirme ou écarte H1 à H5, et fixe l'ordre des corrections.

## 6. Ce qui en sort

| TO-DO | Objet |
|---|---|
| **188** | cause établie (§ 4.1) : transmettre les clés jusqu'au module, ou ne plus faire réécrire le fichier par le module |
| **186** | précisé (§ 4.2) : délai de lecture dans la poignée de main, et un délai de connexion par pair compatible avec l'attente totale |
| **196** | `--fetch-key` : passer par le tunnel du démon, sur son socket local, au lieu d'ouvrir une session Ducky à chaque appel, et retirer la seconde d'attente fixe |
| **197** | provisionnement fait deux fois : un seul responsable ; `restorecon` sur le dossier et `~/.ssh` seulement ; groupe sudo touché seulement s'il change |
| **198** | un budget global pour l'ouverture de session : délai de réception dans le module PAM, plafond du cycle GPO de compte, le reste poursuivi après l'octroi |
| **199** | journaux mesurables : horodatage dans `vaultaire_pam.log`, millisecondes dans `vaultaire.log`, une ligne de synthèse par connexion |

L'ordre conseillé tient en une phrase : **mesurer (§ 5), corriger le 188, puis
le 196 et le 197**, qui retirent du chemin des coûts certains, et seulement
ensuite le 198, qui borne ce qui reste.
