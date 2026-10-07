# Mettre à jour le parc d'agents

> Conception arrêtée le **28/09/2026**, à partir de la question du TO-DO 40.
> Ce fichier porte la **stratégie et ses arbitrages** ; les tâches qui en
> découlent sont les points **111 à 118** de [`TO-DO.md`](./TO-DO.md).
>
> Rien de tout cela n'est écrit à ce jour. Ce document dit ce qu'on va faire, et
> surtout **pourquoi pas autrement** — c'est la partie qu'une entrée de liste ne
> peut pas porter.

---

## Ce qui existe aujourd'hui

Aucun mécanisme. Un agent se met à jour en repassant `vlt create -c … --join`
dessus, c'est-à-dire en réinstallant.

Et il n'y a **rien à quoi se raccrocher** :

| | État |
|---|---|
| Version **constatée** | remontée par `02_12`, stockée dans `id_logiciels.agent_version` et `sdk_version` |
| Version **attendue** | **n'existe nulle part** — aucune table, aucun réglage, aucune comparaison |
| Canal de mise à jour | aucun ; les canaux poussés sont les GPO (`05`) et la révocation (`06`) |
| Client Nexus dans l'agent | aucun |
| Sauvegarde des fichiers remplacés | aucune |
| Retour arrière | aucun |

Le commentaire du schéma est explicite, et il faut le lire comme une limite
assumée jusqu'ici :

> « Le core les **STOCKE** et les **AFFICHE** ; il ne les interprète jamais —
> aucun refus, aucun seuil, aucune comparaison. »

---

## 1. La contrainte qui décide de tout : une mise à jour ratée coupe la machine

C'est le point de départ, et il doit rester en tête à chaque arbitrage qui suit.

`rocky.sh` pose trois piles PAM, et les trois sont en `default=die` — `default=bad`
pour GDM — **sans aucun repli** :

```
auth [success=done ignore=ignore default=die] pam_login_custom_module.so
```

Le module rend `PAM_AUTHINFO_UNAVAIL` quand il ne joint pas le socket de l'agent.
`PAM_AUTHINFO_UNAVAIL` tombe dans `default`. La pile meurt. Il n'y a pas de
retour vers `system-auth`.

Donc : **un agent arrêté, un binaire corrompu ou un `.so` qui ne se charge pas
rend la machine inaccessible à tous les comptes du domaine**, sur console, SSH et
GDM à la fois.

Deux choses seulement sauvent la machine :

1. le module rend `PAM_IGNORE` pour un compte **hors du domaine** — la pile
   continue vers `system-auth`, donc **root et les comptes locaux passent** ;
2. rien d'autre.

Et l'unité systemd de l'agent n'a que `Restart=on-failure` : **pas de
`RestartSec`, pas de `StartLimitBurst`, pas d'`ExecStartPre`**. Un binaire qui
meurt au démarrage boucle sans borne, sans que rien ne s'arrête ni ne le signale.

> **Ce que cela impose.** Un mécanisme capable de faire cela sur tout le parc en
> même temps est **pire que pas de mécanisme du tout**. La difficulté de ce lot
> n'est pas de télécharger un fichier : c'est de **revenir en arrière tout seul**,
> sur une machine où plus personne ne peut se connecter pour réparer.

Le `PAM_IGNORE` des comptes locaux est donc un **invariant de sécurité**, pas un
détail d'implémentation. Il doit être tenu par un test-sentinelle sur le gabarit
de la pile PAM : le jour où quelqu'un le retire, la dernière porte de secours
disparaît, et plus rien ne le dira.

---

## 2. Les quatre décisions, et leur raison

Prises le 28/09.

### 2.1 Signature — une clé distincte, posée comme celle des GPO

Le transport n'a aucune importance une fois qu'il y a une signature. C'est la
signature, et elle seule, qui empêche qu'une release falsifiée s'installe.

**Clé `pkg_signing`**, distincte de `gpo_signing`, déposée à l'installation par
le même canal — le SCP authentifié de `--join` — et **jamais apprise en route**.
C'est le raisonnement du point 52, mot pour mot : faire demander à l'agent la clé
qui sert à juger ce qu'on lui envoie n'aurait aucun sens.

**Pourquoi une clé de plus plutôt que réutiliser celle des GPO.** Ce n'est pas
une question d'exposition : un core compromis peut **déjà** exécuter du code root
sur tout le parc, par un `file_deploy` de scope machine — la validation y est une
liste noire pure, et `/etc/cron.d/`, `/usr/local/bin/` et `/etc/profile.d/` n'y
sont pas. Réutiliser `gpo_signing` n'ajouterait donc presque rien au risque.

La raison est ailleurs : **deux rôles de gravité différente ne doivent pas
dépendre d'une seule clé**. Le jour où l'une doit être révoquée — fuite,
rotation, changement d'algorithme — on ne peut pas casser l'autre en même temps.
Et le coût est nul : la mécanique de dépôt existe déjà, il n'y a qu'à la
dupliquer pour un second nom.

**Domaine de signature séparé**, comme pour les GPO :

```
vaultaire-pkg-v1        et non  vaultaire-gpo-v1
```

Une clé ne peut ainsi jamais signer quelque chose qui passerait pour le rôle de
l'autre, même si les deux clés venaient à être confondues par erreur.

**La clé privée vit sur le core par défaut**, dans la table `certificates`, comme
`gpo_signing` — donc partagée par le cluster sans réplication à écrire, et
fonctionnelle dès l'installation. Un exploitant qui veut la garder hors ligne
signe ailleurs et ne dépose que la partie publique : à documenter, pas à imposer.

### 2.2 Déclenchement — une version attendue portée par le groupe

On pose une **version cible** ; les agents s'y conforment à leur rythme.

Le porteur est le **groupe**, comme `mfa_required` — c'est le modèle du produit,
et c'est ce qui permet un **déploiement par anneaux** : un groupe pilote reçoit
la version, on regarde, puis le reste suit. Sans anneaux, une release fautive
atteint toutes les machines le même jour, et le §1 dit ce que cela veut dire.

Une machine éteinte trois semaines se met à jour **à son retour**, sans file
d'attente à tenir côté core : c'est l'agent qui demande.

S'y ajoute `vlt agent update <machine>` pour forcer une machine, sur le modèle
de `gpo refresh`.

### 2.3 Périmètre — le binaire ET les modules natifs

Les cinq fichiers de l'archive de release, ensemble :

```
vaultaire_client
pam_login_custom_module.so
pam_logout_custom_module.so
pam_ssh_auth_module.so
libnss_vaultaire.so.2
```

**Ils ne peuvent pas bouger séparément.** Le protocole du socket PAM a changé
deux fois dans la seule semaine du 26/09 — champ `otp` (TO-DO 95), champ `notice`
(TO-DO 99). Un binaire neuf avec de vieux modules ne saurait pas demander le code
du second facteur, et personne ne verrait pourquoi.

L'archive `vaultaire_client-vX.Y.Z-linux-amd64.tar.gz` contient **exactement** ce
jeu : c'est l'unité de remplacement naturelle, elle existe déjà, elle n'est pas à
inventer.

### 2.4 Configuration système — l'agent réconcilie

L'agent embarque la configuration que **sa version** attend, et la remet en état.

**Le point 95 est la preuve que c'est nécessaire, pas une hypothèse.** L'invite du
second facteur a besoin de `KbdInteractiveAuthentication yes` dans `sshd_config`.
Seul `rocky.sh` l'écrit, à l'installation. Toutes les machines installées avant la
2.2 ne verront donc **jamais** l'invite — et rien ne le signalera : le second
facteur sera simplement absent, en silence, sur un chemin d'authentification.

**Pourquoi pas par GPO.** `/etc/pam.d/` est en `path_deny` dans le seed, avec son
motif écrit : « pile d'authentification : modifiable = contournement de l'auth ».
En faire un module GPO — même typé — rendrait la pile d'authentification pilotable
par une politique, donc potentiellement par un délégué de domaine. C'est
exactement ce que le seed interdit, et pour la bonne raison.

**Pourquoi pas « constater et signaler ».** C'était l'option sûre, et elle a un
défaut rédhibitoire : le parc reste désynchronisé tant que personne n'agit — ce
qui est la situation d'aujourd'hui, celle qu'on cherche à sortir.

La configuration suit donc le **code qui en a besoin**, versionnée avec lui. C'est
le seul moyen qu'ils ne divergent pas.

---

## 3. L'architecture

```
   RELEASE (CI)
       │ signe le manifeste avec pkg_signing
       ▼
   NEXUS  dépôt de type « vaultaire », LECTURE ANONYME
       ▲                         │
       │ upload manuel           │ HTTPS
       │ (site sans Internet)    │
       │                         ▼
   CORE ──── 04_16 : où est Nexus ────►  AGENT
        ──── 09_02 : version attendue ─►    │
        ◄─── 09_04 : compte rendu ──────    │
                                            ├─ télécharge le manifeste et les fichiers
                                            ├─ VÉRIFIE LA SIGNATURE et les empreintes
                                            ├─ dlopen() chaque .so — avant toute bascule
                                            ├─ garde la version en place
                                            ├─ bascule par rename() atomique
                                            ├─ redémarre
                                            └─ PORTE DE SANTÉ, sinon RETOUR ARRIÈRE
```

### 3.1 Lecture anonyme, et pourquoi c'est un choix de sûreté

Le dépôt de mise à jour se lit **sans authentification**. C'est ce que dit déjà le
TO-DO 40, et c'est ce que fait tout gestionnaire de paquets.

Trois conséquences, toutes bonnes :

- **aucun secret à distribuer au parc.** Donner un jeton Nexus à chaque machine
  serait un problème de distribution de secrets pour ne rien gagner ;
- **le site sans Internet est résolu sans rien écrire.** On télécharge les
  archives ailleurs, on les verse dans le Nexus local par `/api/v1/repos/{repo}/upload`.
  La signature rend le transport indifférent ;
- **`vlt-upm` n'a plus de raison d'être.** La troisième piste du TO-DO 40 —
  un service dédié aux parcs sans Internet — disparaît. C'est un service de moins
  à écrire, à enrôler, à superviser et à mettre à jour lui-même.

> L'intégrité vient de la **signature**, pas du contrôle d'accès. Un dépôt en
> lecture libre qui sert des paquets signés est plus sûr qu'un dépôt authentifié
> qui sert des paquets nus : dans le second cas, qui entre sert ce qu'il veut.

### 3.2 Où est Nexus — par la découverte de service, déjà écrite

L'agent **n'a pas d'URL Nexus dans sa configuration**. Il la demande au cluster,
par les trames `04_15`/`04_16` — celles-là mêmes que le proxy emploie déjà pour
trouver les Nexus vers qui relayer en HTTPS (TO-DO 72).

Rien à écrire côté découverte : `decouverte.AdressesService` existe. Il faut
seulement accorder `04_15` au type de client `Client`, qui ne l'a pas aujourd'hui.

Repli : une URL dans `client_conf.json` si le cluster n'en annonce aucun. Un parc
peut vouloir un miroir local qui n'est pas un service enrôlé.

---

## 4. Le format signé

### 4.1 Un manifeste, pas cinq signatures

```
vaultaire-pkg-v1
2.2.0
linux-amd64
vaultaire_client             <sha256>
pam_login_custom_module.so   <sha256>
pam_logout_custom_module.so  <sha256>
pam_ssh_auth_module.so       <sha256>
libnss_vaultaire.so.2        <sha256>
```

Signé en **RSA-PSS SHA-256**, comme les politiques GPO : même algorithme, même
bibliothèque standard, aucune dépendance ajoutée — l'agent sait déjà le faire.

**Un manifeste plutôt que cinq signatures** parce qu'il lie le **jeu** de
fichiers. Cinq signatures indépendantes laisseraient composer un jeu mixte, fait
de fichiers authentiques pris dans deux versions — exactement l'incompatibilité
que le §2.3 cherche à rendre impossible.

### 4.2 Le manifeste ne nomme AUCUNE machine

Contrairement à la signature d'une politique GPO, qui lie `computeur_id`, `scope`
et `username` — parce qu'une politique est destinée à une machine, et qu'il faut
empêcher de la rejouer ailleurs.

Un paquet, lui, est **le même pour tout le monde**. Le lier à une machine
obligerait à signer à chaque téléchargement, donc à mettre le core dans le chemin
de chaque mise à jour — et tuerait la propriété qui rend le site sans Internet
gratuit : pouvoir recopier le dépôt tel quel.

### 4.3 Ce que cela laisse ouvert, et comment c'est fermé

Un manifeste non lié à une machine est **rejouable** : un attaquant en position
de servir le dépôt peut proposer une **ancienne** version, authentiquement
signée, pour ramener une faille corrigée. C'est une attaque par rétrogradation,
et elle est réelle.

Elle est fermée par la séparation des rôles :

| | Porte quoi | Garanti par |
|---|---|---|
| **L'ordre** (`09_02`) | *quelle* version installer | le tunnel Ducky, authentifié et lié à cette machine |
| **Le manifeste** | *l'intégrité* des octets | la signature `pkg_signing` |

L'agent n'installe **que** la version que l'ordre nomme, et **refuse toute
version inférieure à celle qu'il porte** sauf si l'ordre demande explicitement la
rétrogradation — laquelle est journalisée en `SECURITY` des deux côtés.

Autrement dit : le dépôt dit *ce que valent les octets*, le core dit *lesquels
prendre*. Aucun des deux seul ne suffit à installer quoi que ce soit.

---

## 5. Les trames — catégorie `09`

Les catégories `01` à `08` sont prises. `09` est libre.

```
09_01  demander l'ordre de mise à jour     client → core    au démarrage et à chaque reconnexion
  09_02  ordre : version attendue, dépôt   core → client
  09_03  rien à faire                      core → client
09_04  compte rendu                        client → core    version, résultat, motif
  09_05  accusé                            core → client
09_06  ordre poussé                        core → client    « va te mettre à jour maintenant »
```

**C'est le modèle de la révocation, repris tel quel**, et c'est délibéré. La
catégorie `06` a résolu exactement ce problème :

- **poussée opportuniste** vers qui est connecté — un échec d'envoi n'est *pas*
  une erreur, personne ne tient de file ;
- **rattrapage par demande** à chaque reconnexion — c'est ce qui rend la poussée
  non fiable acceptable.

Une machine éteinte, coupée du réseau ou en cours de redémarrage se met à jour à
son retour, sans que le core ait eu à se souvenir d'elle.

Droits : `09_01` et `09_04` s'ajoutent au type de client `Client` dans
`core/clienttype`, avec `04_15` (§3.2).

---

## 6. Le basculement survivable

C'est le cœur du lot. Tout le reste est de la plomberie.

### 6.1 Un programme séparé fait la bascule

`vaultaire_update`, installé dans `/usr/libexec/vaultaire/` — pas dans
`/usr/bin/`, ce n'est pas une commande pour un humain.

**Il ne peut pas être l'agent lui-même** : le programme qui remplace un fichier ne
peut pas être ce fichier, et il doit survivre au redémarrage du service. Il est
donc lancé détaché, par une unité systemd transitoire :

```bash
systemd-run --unit=vaultaire-update --collect /usr/libexec/vaultaire/vaultaire_update …
```

C'est le même problème que `deployments/pre-prod/docker-update.sh` a déjà résolu
en se recopiant dans un `mktemp` avant de se ré-exécuter — bash lisant un script
au fil de l'exécution.

L'updater est lui-même mis à jour, par l'updater **précédent**. La version qui
tourne est l'ancienne ; elle installe la nouvelle, qui servira au tour d'après.

### 6.2 L'ordre des opérations

1. **Télécharger** le manifeste, puis les fichiers.
2. **Vérifier la signature** du manifeste, puis **le SHA-256 de chaque fichier**.
   Un seul écart : on s'arrête, rien n'a été touché.
3. **Éprouver les `.so` par `dlopen()`**, dans le processus de l'updater, qui les
   referme aussitôt. C'est le contrôle qui compte : le mode de défaillance réel
   d'un module PAM est l'édition de liens — une glibc trop récente, un `-lcrypt`
   manquant — et il se voit à ce moment-là, **avant** que sshd n'ait à le charger.
4. **Garder la version en place** dans `/var/lib/vaultaire/updates/<version>/`.
5. **Basculer.** Chaque fichier est écrit sous un nom temporaire **dans son
   répertoire de destination**, puis `rename()`. `rename()` n'est atomique qu'au
   sein d'un système de fichiers : écrire dans `/var/lib` puis déplacer vers
   `/usr/bin` ne l'est pas, et c'est le genre de détail qui ne se voit qu'en
   production.
   Un `.so` déjà chargé par un processus vivant n'est pas affecté : l'ancien
   inode reste projeté. Les sessions en cours continuent, les nouvelles prennent
   le nouveau module.
6. **Redémarrer** le service.
7. **Porte de santé** (§6.3).
8. **Retour arrière** si elle échoue : les fichiers gardés reviennent par le même
   `rename()`, le service redémarre, et un compte rendu `09_04` part avec le
   motif.

### 6.3 La porte de santé

Trois conditions, dans l'ordre, sous une échéance :

| # | Ce qu'on vérifie | Ce que cela prouve |
|---|---|---|
| 1 | le service tient, au-delà de la fenêtre de relance | le binaire démarre |
| 2 | le tunnel Ducky est rétabli et authentifié | l'identité et la configuration sont intactes |
| 3 | le socket PAM répond à une sonde | **le chemin d'authentification fonctionne** |

La troisième est celle qui compte. Les deux premières ne disent rien du socket,
et c'est précisément le socket dont dépendent toutes les ouvertures de session.

La sonde est une requête sans identifiants — elle ne doit pas exiger un compte
pour être exécutée — qui traverse le socket et le traitement de trame.

> `dlopen()` **avant** la bascule et la sonde **après** couvrent les deux moitiés :
> « le module se charge » et « le binaire répond ». Aucune des deux n'est
> suffisante seule.

### 6.4 Ce que l'updater ne fait jamais

- **Toucher à la configuration système dans la même opération.** Si la
  configuration est fausse, le retour arrière du binaire ne la répare pas. La
  réconciliation (§7) a lieu **après** que la porte de santé a été franchie, dans
  un second temps.
- **Toucher à `/etc/vaultaire_client/`.** L'identité, les clés privées et
  l'empreinte du core ne font pas partie d'une mise à jour. Les perdre oblige à
  réenrôler la machine à la main.
- **Toucher à `/var/lib/vaultaire/applied_policies.json`.** Le perdre ferait
  réappliquer toutes les GPO au cycle suivant : réinstallations de paquets,
  redémarrages de services. Non destructif, mais bruyant à l'échelle d'un parc.

### 6.5 Le préalable : durcir l'unité systemd

> **Fait en 2.3 (TO-DO 112).** `vaultaire_client --check` existe, et l'unité
> porte la relance bornée. Un point a changé par rapport à ce qui suit, et il
> compte pour le §6.2 : **c'est l'agent qui écrit son unité**
> (`vaultaire_client --install-unit`). Un binaire antérieur sort en erreur sur
> `--check` ; l'unité nouvelle posée devant lui empêche le service de démarrer.
> L'updater devra donc poser le binaire **puis** lui faire écrire l'unité, et en
> cas de retour arrière remettre **les deux** — `--install-unit` garde l'ancienne
> en `.precedente` pour cela. Détail :
> [Agent_configuration_et_debug.md § 3](../exploitation/Agent_configuration_et_debug.md#3-le-service--contrôle-de-démarrage-et-relance-bornée).
> Le cloisonnement de l'unité reste à décider (TO-DO 168).

Sans cela, le §6.3 ne peut pas fonctionner : un binaire qui meurt boucle sans
borne, et rien ne distingue « en cours de démarrage » de « ne démarrera jamais ».

```ini
RestartSec=5s
StartLimitBurst=3
StartLimitIntervalSec=60
ExecStartPre=/usr/bin/vaultaire_client --check
```

`--check` valide que le binaire s'exécute, lit sa configuration et trouve ses
clés — sans ouvrir de socket ni de tunnel. C'est ce que fait déjà l'unité de
Nexus (`ExecStartPre=… -check`), et l'agent est très en retard sur elle.

**Ce durcissement vaut par lui-même**, indépendamment de la mise à jour : il
devrait être fait en premier, et séparément.

---

## 7. La configuration système

### 7.1 Ce qui est concerné

| Fichier | Écrit aujourd'hui par | Risque |
|---|---|---|
| `/etc/pam.d/login` | `rocky.sh`, réécriture intégrale ; `debian.sh` (2.3), **insertion** d'une ligne marquée `# vaultaire`, original gardé | **le plus élevé** — aucun validateur n'existe |
| `/etc/pam.d/sshd` | idem | idem, plus la perte de l'accès distant |
| `/etc/pam.d/gdm-password` | idem, si le fichier préexiste | idem, poste graphique |
| `/etc/ssh/sshd_config` | `sed -i` destructif puis `>>` | validable par `sshd -t` |
| `/etc/nsswitch.conf` | ajout idempotent | faible |
| `/etc/dconf/db/gdm.d/10-vaultaire-userlist` | création + `dconf update` | faible |

Aucun n'est sauvegardé aujourd'hui, et aucun n'est écrit de façon atomique.

### 7.2 La règle

L'agent porte les gabarits que **sa version** attend, chacun marqué :

```
# vaultaire-conf v3 — ne pas modifier à la main
```

À chaque démarrage, **après** que la porte de santé de la mise à jour a été
franchie, il compare le marqueur et ne fait rien si la version correspond. Sinon :

1. **sauvegarde** : `<fichier>.vaultaire-bak-<horodatage>` ;
2. écriture **atomique** — fichier temporaire dans le même répertoire, puis
   `rename()` ;
3. pour `sshd_config` : **`sshd -t -f <candidat>` avant de basculer**. S'il refuse,
   on ne touche à rien et on remonte l'écart ;
4. compte rendu au core, visible dans `vlt agent`.

### 7.3 Ce qui n'a pas de validateur, et ce qu'on fait à la place

**Il n'existe pas de `pam -t`.** Une pile PAM fausse ne se découvre qu'en tentant
une authentification — c'est-à-dire trop tard.

Deux protections, et il faut les deux :

- **l'invariant du `PAM_IGNORE`.** Le module rend `PAM_IGNORE` pour un compte hors
  du domaine, donc la pile continue vers `system-auth` et **root reste joignable**
  quoi qu'il arrive. C'est la seule porte de secours du produit. Un
  **test-sentinelle** sur les gabarits doit refuser toute pile qui retirerait ce
  passage — le jour où quelqu'un l'enlève, plus rien ne le dira ;
- **la sauvegarde horodatée**, qui rend la réparation possible en une commande
  pour qui a un accès console.

### 7.4 Le cas concret à traiter en premier

`KbdInteractiveAuthentication yes` dans `sshd_config`, pour l'invite du second
facteur (TO-DO 95). C'est le gabarit `v2` → `v3`, et c'est la première migration
que ce mécanisme devra porter. Il faut l'éprouver sur ce cas-là avant tout autre :
il est réel, il est daté, et son absence est silencieuse.

---

## 8. La version attendue

### 8.1 Où elle vit

| Niveau | Emplacement | Rôle |
|---|---|---|
| Machine | `id_logiciels.agent_target_version` | dérogation : une machine fragile qu'on veut figer |
| Groupe | `groups.agent_target_version` | **le niveau ordinaire** — les anneaux de déploiement |
| Global | `server_settings.agent_target_version` | le défaut du parc |

**Résolution** : machine, sinon **la plus haute** des versions cibles de ses
groupes, sinon le défaut global, sinon **vide**.

**Vide = aucune mise à jour automatique**, et c'est le défaut. Une installation
existante ne voit donc rien changer tant que personne n'a posé de cible : c'est
la seule façon d'introduire un mécanisme pareil sans surprendre un parc en
service.

**La plus haute l'emporte** entre groupes, parce qu'une machine du groupe pilote
*et* du groupe général doit recevoir la version du pilote — qui est en avance.
La dérogation par machine existe pour le cas inverse, le poste qu'on veut laisser
derrière.

### 8.2 La vue qui manquait

C'est elle qui rend tout le reste pilotable, et elle vaut d'être écrite même si
rien d'autre ne l'était :

```
vlt agent                     constaté vs attendu, tout le parc
vlt agent -g <groupe>         par groupe
vlt agent target <version>            défaut global
vlt agent target -g <groupe> <version>
vlt agent update <machine>    force une machine, comme « gpo refresh »
vlt agent pin <machine> <version|--none>
```

Et une colonne **VERSION** dans la liste des machines du portail, qui n'en a
aucune aujourd'hui, avec l'écart mis en évidence.

Droits : `read:log` pour lire, `write:server` pour poser une cible globale ou de
groupe — mêmes clés que la signature des GPO et le second facteur Ducky, pour la
même raison : le réglage engage des machines qui ne sont pas celles d'un seul
domaine.

---

## 9. Windows — un lot à part

La DLL du Credential Provider est **chargée par Winlogon**, et Windows verrouille
le fichier : elle ne peut pas être remplacée à chaud. Il faut déposer à côté et
basculer au redémarrage, ou au minimum hors session.

Le service, lui, se remplace comme sous Linux — mais `install.ps1` est manuel et
interactif, et il n'y a aucun équivalent de `rocky.sh` côté core.

Mêler les deux produirait une conception qui ne convient bien à aucun des deux
systèmes. Windows est donc le **point 118**, après que le mécanisme Linux aura
tourné en production.

---

## 10. Ce qui reste ouvert

- **Debian.** `execute_list_of_command_on_client.go` détecte `debian` et `ubuntu`,
  mais **aucun `debian.sh` n'existe dans le dépôt** : un `--join` y échoue au SCP
  du script. La mise à jour héritera du même trou tant que le point 71 n'est pas
  traité. À nommer dans la documentation plutôt qu'à découvrir.
- **SELinux.** La politique s'installe à la main
  (`deployments/selinux/install.sh`) et n'est pas versionnée avec l'agent. Un
  binaire déplacé ou un socket au nouveau chemin demanderait une politique à jour.
- **Le SDK.** `sdk_version` est remontée et affichée, mais l'agent et le SDK sont
  compilés ensemble : il n'y a pas de mise à jour indépendante à prévoir.
- **La rotation de `pkg_signing`.** Poser une seconde clé de confiance avant de
  retirer la première demande que l'agent en accepte deux. À prévoir dès le format,
  pas après.

---

## Voir aussi

- [`TO-DO.md`](./TO-DO.md), points **111 à 118**
- [`MFA_et_Expiration.md`](./how%20it%20work/MFA_et_Expiration.md) — le point 95,
  qui rend §7 urgent
- [`ducky-network/`](./how%20it%20work/ducky-network/README.md) — les catégories
  de trames, dont `06` dont `09` reprend la forme
- [`exploitation/Releases.md`](../exploitation/Releases.md) — ce que la CI produit
- `deployments/pre-prod/docker-update.sh` — le seul mécanisme de mise à jour
  existant du dépôt, et le précédent à relire avant d'écrire le §6
