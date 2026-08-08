# Audit — agent, SDK et modules PAM/NSS

**Périmètre** : `src/vaultaire_client` (8 653 lignes), `src/ducky-network-sdk-service`
(2 851 lignes), `src/vaultaire_client/pam_module` (829 lignes de C).
**Angles** : sécurité, correction fonctionnelle, ressources.
**État** : **18 points sur 20 sont corrigés** — les deux critiques, les cinq
majeurs, et tous les points moyens et mineurs traitables sans décision de
conception.

Restent les points **13** et **14**, qui ne peuvent pas être corrigés
unilatéralement : le premier change le protocole et demande une bascule
coordonnée client/serveur, le second est un choix de modèle de confiance. Ils
sont détaillés en fin de document.

Les constats sont classés par gravité. Chaque point critique a été **reproduit**
avant d'être écrit : un audit qui rapporte des soupçons fait perdre autant de
temps qu'un défaut réel.

---

## Résumé

| # | Point | Gravité | Module |
|---|-------|---------|--------|
| 1 | ~~Socket d'authentification en `/tmp`, mode 0666~~ | **CORRIGÉ** | agent + PAM |
| 2 | ~~Tous les utilisateurs du domaine partagent l'UID 5001~~ | **CORRIGÉ** | NSS |
| 3 | ~~`useradd` reçoit des arguments malformés~~ | **CORRIGÉ** | PAM |
| 4 | ~~`authorized_keys` écrit en root sans protection contre les liens symboliques~~ | **CORRIGÉ** | PAM |
| 5 | ~~Mot de passe injecté dans du JSON sans échappement~~ | **CORRIGÉ** | PAM |
| 6 | ~~Injection shell possible dans la gestion du groupe sudo~~ | **CORRIGÉ** | PAM |
| 7 | ~~NSS renvoie des pointeurs hors de son tampon~~ | **CORRIGÉ** | NSS |
| 8 | ~~`pam_sm_acct_mgmt` ne refuse jamais rien~~ | **CORRIGÉ** | PAM |
| 9 | ~~`MkdirAll(".ssh", 0777)` au mauvais endroit — dupliqué agent/SDK~~ | **CORRIGÉ** | agent + SDK |
| 10 | ~~Réponse complète du daemon journalisée en clair~~ | **CORRIGÉ** | PAM |
| 11 | ~~`SIGPIPE` non neutralisé autour de `chpasswd`~~ | **CORRIGÉ** | PAM |
| 12 | ~~Lecture socket en un seul `recv`~~ | **CORRIGÉ** | PAM |
| 13 | Clé de session AES-256 portant 128 bits d'entropie | **décision** | SDK + core |
| 14 | Confiance au premier contact sur la clé du core, sans reprise | **décision** | agent + SDK |
| 15 | ~~11 goroutines dans l'agent, un seul `recover()`~~ | **CORRIGÉ** | agent |
| 16 | ~~`InsecureSkipVerify: true` dans `vaultaire_ctl`~~ | **CORRIGÉ** | ctl |
| 17 | ~~Journaux PAM et agent en 0644~~ | **CORRIGÉ** | agent + PAM |
| 18 | ~~Reconnexion à intervalle fixe, sans dégressivité~~ | **CORRIGÉ** | agent |
| 19 | ~~`is_vaultaire_user` reconnaît un domaine à la présence d'un `@`~~ | **CORRIGÉ** | PAM |
| 20 | Aucun test sur 11 500 lignes de C et de SDK | **en cours** | tous |

---

## 1. Socket d'authentification en `/tmp`, mode 0666 — **critique**

> **CORRIGÉ** — voir `docs/migrations/pam_socket_et_uid.md` pour le déploiement,
> qui doit être séquencé : modules PAM et agent partent **ensemble**.


`src/vaultaire_client/storage/PAM.go` :

```go
var SocketPath = "/tmp/vaultaire_client.sock"
```

`src/vaultaire_client/pam_communication/PamCommunication.go:69` :

```go
os.Chmod(storage.SocketPath, 0666)
```

Et côté PAM, `pam_login_custom_module.c` envoie sur ce socket :

```c
snprintf(req, sizeof(req), "{\"check\":{\"user\":\"%s\",\"password\":\"%s\"}}",
         username, password ? password : "");
```

**Le mot de passe en clair de chaque connexion transite par un socket que tout
utilisateur local peut ouvrir.**

Deux conséquences distinctes, et la seconde est la plus grave.

### 1a. Oracle de mot de passe pour tout utilisateur local

Le mode 0666 autorise n'importe quel compte de la machine à se connecter au
daemon et à émettre des `check`. Chaque requête déclenche une authentification
réelle contre l'annuaire central. Rien dans `processPamRequest` ne vérifie
l'identité de l'appelant — ni `SO_PEERCRED`, ni limitation de débit locale.

Un utilisateur sans privilège dispose donc d'un banc d'essai de mots de passe
contre **tous les comptes du domaine**, depuis n'importe quel poste enrôlé.

### 1b. Usurpation du daemon, donc élévation vers root

`/tmp` est accessible en écriture à tous. Si le socket n'existe pas — avant le
démarrage de l'agent au boot, après un arrêt pour maintenance, après un plantage
— **n'importe quel utilisateur local peut créer le fichier à cette place**.

Il reçoit alors, en clair, le mot de passe de chaque personne qui se connecte.
Et il contrôle la réponse. Or le module PAM en tire directement :

```c
if (is_admin) vaultaire_add_user_to_sudo_group(username);
```

Répondre `{"status":"success","is_admin":true}` suffit à faire créer le compte
local, poser son mot de passe et **l'ajouter au groupe sudo**. C'est une
élévation locale complète vers root, à partir d'un compte non privilégié.

La fenêtre est celle où l'agent ne tourne pas. Elle n'est pas théorique : c'est
exactement l'état de la machine au démarrage, moment où des connexions arrivent.

> Nuance : l'agent tournant en root, son `os.RemoveAll` au démarrage écrase le
> socket de l'attaquant malgré le sticky bit de `/tmp`. L'attaque n'est donc pas
> persistante — mais elle n'a pas besoin de l'être, une seule connexion capturée
> suffit.

**Direction de correction** : socket dans `/run/vaultaire/`, répertoire en 0700
appartenant à root, socket en 0600 ; vérification de `SO_PEERCRED` côté daemon ;
et côté PAM, `stat()` avant `connect()` pour confirmer que le socket appartient
à root et n'est pas accessible en écriture par d'autres.

---

## 2. Tous les utilisateurs du domaine partagent l'UID 5001 — **critique**

> **CORRIGÉ** — voir `docs/migrations/pam_socket_et_uid.md` pour le déploiement,
> qui doit être séquencé : modules PAM et agent partent **ensemble**.


`nss_vaultaire.c` :

```c
#define VIRTUAL_UID 5001
#define VIRTUAL_GID 5001

result->pw_uid = VIRTUAL_UID;
result->pw_gid = VIRTUAL_GID;
```

Toute entrée contenant un `@` reçoit le **même** UID. Sous Unix, l'UID *est*
l'identité : deux comptes qui le partagent sont le même utilisateur pour le
noyau.

Conséquences directes, sans aucune faille supplémentaire :

- `alice@dom` lit, modifie et supprime les fichiers de `bob@dom` ;
- elle peut lui envoyer des signaux, donc tuer ses processus ;
- `ptrace` est autorisé entre eux : lecture de la mémoire, donc des secrets en
  cours d'usage ;
- toute permission accordée à l'un l'est à tous.

**Il n'y a aucune séparation entre les utilisateurs du domaine sur une machine
gérée.** C'est l'inverse de ce qu'un annuaire est censé apporter.

S'ajoute un risque de collision : si l'UID 5001 correspond déjà à un compte local
sur une machine du parc, tout utilisateur du domaine hérite de son identité.

Le module PAM crée bien un compte local avec un vrai UID
(`ensure_local_user_with_password`), mais l'ordre de `nsswitch.conf` décide qui
répond. Si `vaultaire` précède `files`, l'UID réel reste masqué en permanence.

**Direction de correction** : dériver un UID stable et unique par utilisateur —
plage dédiée allouée par le core et distribuée avec l'identité, ou lecture de
l'UID du compte local une fois créé. Une empreinte tronquée du nom n'est pas
acceptable : les collisions y sont probables bien avant le millier de comptes.

---

## 3. `useradd` reçoit des arguments malformés — **majeur**

> **CORRIGÉ** — voir `docs/migrations/pam_socket_et_uid.md` pour le déploiement,
> qui doit être séquencé : modules PAM et agent partent **ensemble**.


`pam_common.c:80` :

```c
execl("/usr/sbin/useradd", "useradd", "-m", "--shell", "-c",
      "vaultaire_user_account", "/bin/bash", username, (char *)NULL);
```

`--shell` consomme l'argument suivant : le shell devient `-c`. Il reste alors
trois opérandes là où `useradd` en attend une.

**Vérifié sur le binaire réel** :

```
$ useradd -m --shell -c vaultaire_user_account /bin/bash "testuser@dom"
useradd: invalid shell '-c'
$ echo $?
3
```

`run_useradd` retourne donc **toujours** 0, et `ensure_local_user_with_password`
échoue avec `useradd failed for %s` chaque fois que le compte local n'existe pas
encore.

Le défaut est masqué en exploitation : `getpwnam` passe par NSS, et le module du
point 2 répond pour tout nom contenant un `@`. `if (!getpwnam(username))` est donc
faux, et `run_useradd` n'est jamais appelé — le compte local n'est jamais créé,
et personne ne s'en aperçoit tant que l'UID virtuel suffit.

Les deux défauts se masquent l'un l'autre. Corriger le point 2 sans corriger
celui-ci ferait échouer toutes les premières connexions.

L'intention est manifeste : `useradd -m --shell /bin/bash -c vaultaire_user_account <login>`.

---

## 4. `authorized_keys` écrit en root sans protection contre les liens symboliques — **majeur**

> **CORRIGÉ** — tests dans `pam_module/hardening_test.c`, exécutés par
> `pam_module/run_tests.sh`.


`pam_common.c:188` :

```c
struct passwd *pw = getpwnam(username);
snprintf(ssh_dir, sizeof(ssh_dir), "%s/.ssh", pw->pw_dir);
...
FILE *f = fopen(auth_keys_path, "w");
...
chmod(auth_keys_path, 0600);
chown(auth_keys_path, pw->pw_uid, pw->pw_gid);
```

Trois problèmes sur ces quelques lignes, tous exploitables parce que le module
tourne en root.

**Suivi de lien symbolique.** `pw->pw_dir` vaut `/home/<nom>` d'après le module
NSS. Un utilisateur qui contrôle ce répertoire — ou qui gagne la course avant sa
création — y place `.ssh/authorized_keys` en lien symbolique vers `/etc/shadow`,
`/etc/passwd` ou `/root/.ssh/authorized_keys`. `fopen(..., "w")` suit le lien et
**écrit en root dans la cible**. Le `chown` qui suit la donne ensuite à
l'attaquant.

**Fenêtre de permissions.** Le fichier est créé avec le mode par défaut, souvent
0644, et n'est ramené à 0600 qu'après écriture. Entre les deux, les clés sont
lisibles par tous.

**Ordre `chmod` / `chown`.** Le `chown` suit le `chmod` : si le `chown` échoue,
le fichier reste à root avec un contenu destiné à l'utilisateur.

**Direction de correction** : `open()` avec `O_NOFOLLOW | O_CREAT | O_EXCL` et le
mode 0600 dès la création, écriture dans un temporaire puis `rename()`, et
ouverture du répertoire personnel par descripteur (`openat`) plutôt que par
chemin reconstruit.

---

## 5. Mot de passe injecté dans du JSON sans échappement — majeur

> **CORRIGÉ** — tests dans `pam_module/hardening_test.c`, exécutés par
> `pam_module/run_tests.sh`.


`pam_login_custom_module.c` et `pam_ssh_auth_module.c` :

```c
snprintf(req, sizeof(req), "{\"check\":{\"user\":\"%s\",\"password\":\"%s\"}}",
         username, password ? password : "");
```

Ni le nom ni le mot de passe ne sont échappés.

**Conséquence certaine** : tout mot de passe contenant `"` ou `\` produit un JSON
invalide. `json.Decoder` côté agent échoue, la requête est rejetée. **Ces
comptes ne peuvent jamais se connecter**, avec pour seul symptôme un
`Erreur de decodage du message JSON` sans rapport apparent avec le mot de passe.

**Conséquence de structure** : `json.Decoder.Decode` lit la première valeur
complète et ignore la suite. Un mot de passe de la forme

```
x","user":"admin@dom
```

produit un objet à clé `user` dupliquée. Go retient **la dernière**, et la
requête cible alors un autre utilisateur que celui qui s'authentifie.

Cela ne contourne pas l'authentification — la preuve reste calculée et vérifiée
par le core — mais cela permet de piloter la cible d'une requête depuis un champ
que l'attaquant contrôle. Combiné au point 1, c'est un outil de plus pour un
appelant local non privilégié.

`vaultaire_is_valid_username` refuse `/ ; & : \n \r \t` mais **pas** `"`.

---

## 6. Injection shell possible dans la gestion du groupe sudo — majeur

> **CORRIGÉ** — tests dans `pam_module/hardening_test.c`, exécutés par
> `pam_module/run_tests.sh`.


`pam_common.c:301` et `:312` :

```c
snprintf(cmd, sizeof(cmd), "usermod -aG %s %s", group, username);
return system(cmd);
```

`system()` passe par `/bin/sh`. Le garde-fou existe :

```c
bool vaultaire_is_valid_username(const char *username) {
    if (strpbrk(username, "/ ;&:\n\r\t")) return false;
    return true;
}
```

Mais la liste noire est incomplète. Ne sont **pas** refusés :

```
`  $  |  (  )  '  "  <  >  \  *  ?  {  }  [  ]  !  #
```

Un nom comme ``alice$(id>/tmp/x)@dom`` ou ``alice`cmd`@dom`` traverse la
validation et arrive dans `system()`, exécuté en root.

L'exploitation suppose que le core accepte de tels noms d'utilisateur — la
validation côté serveur (`SanitizeIdentifier`) les refuse aujourd'hui. La
défense tient donc **entièrement** à un contrôle situé sur une autre machine, ce
qui n'est pas une position tenable pour du code exécuté en root.

Deux corrections indépendantes s'imposent : passer en **liste blanche** côté C
(`[A-Za-z0-9._@-]`, comme `isValidUserInput` le fait déjà côté Go), et remplacer
`system()` par `fork`/`execv` sans shell — ce que `run_useradd` fait déjà, la
technique est donc présente dans le fichier.

`vaultaire_detect_sudo_group` appelle également
`system("getent group sudo ... || groupadd sudo")`, sans entrée variable mais
sans nécessité non plus.

---

## 7. NSS renvoie des pointeurs hors de son tampon — majeur

> **CORRIGÉ** — tests dans `pam_module/hardening_test.c`, exécutés par
> `pam_module/run_tests.sh`.


`nss_vaultaire.c` :

```c
result->pw_name   = (char *)name;
result->pw_passwd = (char *)"x";
result->pw_gecos  = (char *)name;
result->pw_shell  = (char *)"/bin/bash";
```

Le contrat NSS impose que toutes les chaînes de `struct passwd` pointent dans le
**tampon fourni par l'appelant**. C'est ce qui permet à celui-ci de conserver le
résultat après l'appel.

Ici, `pw_name` et `pw_gecos` pointent vers `name`, mémoire appartenant à
l'appelant, dont la durée de vie n'est pas garantie ; `pw_passwd` et `pw_shell`
pointent vers des littéraux. Tout appelant qui garde la structure — c'est le cas
usuel — lit une mémoire potentiellement réutilisée.

Trois manquements de plus au même contrat :

- `errnop` n'est jamais renseigné ;
- en cas de tampon trop court, la fonction **tronque** silencieusement le chemin
  du répertoire personnel au lieu de rendre `NSS_STATUS_TRYAGAIN` avec `ERANGE` ;
- `buflen` n'est pas vérifié avant `snprintf`.

`_nss_vaultaire_getpwuid_r` retourne systématiquement `NSS_STATUS_NOTFOUND`, y
compris pour `VIRTUAL_UID` : la résolution inverse est impossible, et tout
affichage (`ls -l`, `ps`) montre 5001 au lieu d'un nom.

---

## 8. `pam_sm_acct_mgmt` ne refuse jamais rien — majeur

> **CORRIGÉ** — tests dans `pam_module/hardening_test.c`, exécutés par
> `pam_module/run_tests.sh`.


Dans les deux modules d'authentification :

```c
PAM_EXTERN int pam_sm_acct_mgmt(pam_handle_t *pamh, int flags, int argc, const char **argv) {
    return PAM_SUCCESS;
}
```

La phase *account* de PAM est celle qui répond à « ce compte a-t-il encore le
droit d'ouvrir une session ? » : compte désactivé, expiré, révoqué, hors plage
horaire.

Vaultaire dispose pourtant de tout ce qu'il faut — `vlt kill`, la catégorie de
trames 06 (révocation), l'expiration des mots de passe. Rien de cela n'est
consulté ici. Un compte révoqué au centre garde son accès aux machines tant que
son mot de passe local reste valide, puisque `ensure_local_user_with_password` l'y
a écrit.

C'est peut-être délibéré — la révocation passe par la catégorie 06 et agit sur le
compte local. Mais alors le chemin dépend de la joignabilité de l'agent au moment
de la révocation, là où `acct_mgmt` vérifierait à **chaque** connexion.

---

## 9. `MkdirAll(".ssh", 0777)` au mauvais endroit — moyen

> **CORRIGÉ** — tests dans `pam_module/hardening_test.c` et dans les paquets Go.


Présent **à l'identique** dans l'agent
(`duckynetworkClient/serveurauth/writeserveurkey.go`) et dans le SDK
(`duckynetwork/serveurauth/writeserveurkey.go`) :

```go
filePath := filepath.Join(store.KeyPath, "serveurpublickey.pem")

// Assurer que le répertoire .ssh existe
err := os.MkdirAll(".ssh", os.ModePerm)
```

Trois défauts en trois lignes :

- le répertoire créé est `.ssh` **relatif au répertoire courant du processus**,
  pas `store.KeyPath` — l'agent sème un `.ssh` là où il a été lancé ;
- le répertoire réellement nécessaire, celui de `filePath`, n'est jamais créé :
  si `KeyPath` n'existe pas, `WriteFile` échoue ;
- `os.ModePerm` vaut 0777. L'umask le ramène en général à 0755, mais l'intention
  écrite reste « accessible en écriture à tous » pour un répertoire de clés.

Le fichier suit avec un `fmt.Println` au lieu du système de journalisation.

**Ce point illustre le risque de la distribution par copie du SDK** : le défaut
a été recopié tel quel, et devra être corrigé deux fois. Tout projet tiers ayant
copié le SDK l'embarque aussi.

---

## 10. Réponse complète du daemon journalisée en clair — moyen

> **CORRIGÉ** — tests dans `pam_module/hardening_test.c` et dans les paquets Go.


```c
vaultaire_log_info("Socket response received for %s: %s", username, resp);
```

`resp` contient le statut, le drapeau administrateur **et les clés publiques SSH**
de l'utilisateur. Le fichier `/var/log/vaultaire/vaultaire_pam.log` est ouvert
par `fopen(..., "a")` sans mode explicite : il est créé en 0666 & ~umask, donc
typiquement 0644 — **lisible par tous**.

Les clés publiques ne sont pas des secrets, mais le journal donne à tout
utilisateur local la liste des comptes du domaine qui se connectent, leur statut
administrateur et leurs clés. C'est une cartographie utile à un attaquant, et
elle grandit sans rotation ni bornage.

Le mot de passe, lui, n'est pas journalisé — seulement sa longueur
(`Password retrieved (len=%zu)`), ce qui est le bon réflexe. Une longueur reste
une information, mais l'écart avec le reste est net.

---

## 11. `SIGPIPE` non neutralisé autour de `chpasswd` — moyen

> **CORRIGÉ** — tests dans `pam_module/hardening_test.c` et dans les paquets Go.


`pam_common.c:103` :

```c
close(fd[0]);
dprintf(fd[1], "%s:%s\n", username, password);
close(fd[1]);
```

Si `execl("/usr/sbin/chpasswd", ...)` échoue — binaire absent, le cas sur une
distribution minimale — l'enfant sort immédiatement en 127 et l'extrémité de
lecture se ferme. L'écriture reçoit alors `SIGPIPE`, dont l'action par défaut est
la **terminaison du processus**.

Ce processus est celui qui a chargé le module PAM : `sshd`, `login`, `sudo`.
Un `chpasswd` manquant ne provoque donc pas un échec d'authentification, mais la
mort brutale du processus appelant, sans message.

Le retour de `dprintf` n'est pas non plus vérifié : une écriture partielle
donnerait un mot de passe tronqué transmis à `chpasswd`, donc **un mot de passe
local différent de celui du centre**, posé sans erreur.

---

## 12. Lecture socket en un seul `recv` — moyen

> **CORRIGÉ** — tests dans `pam_module/hardening_test.c` et dans les paquets Go.


`pam_common.c:266` :

```c
ssize_t n = recv(sock, resp, resp_size - 1, 0);
```

Un seul appel. Sur un socket flux, rien ne garantit que la réponse arrive en un
segment : dès que la charge dépasse ce que le noyau a mis à disposition,
`resp` contient un JSON tronqué. `vaultaire_json_get_string` ne trouve pas
`status`, la variable reste vide, et l'authentification est refusée.

Le cas se déclenche d'autant plus facilement que la réponse contient les clés SSH
— une seule clé RSA-4096 en base64 fait déjà plus d'un kilo-octet.

Symétriquement, `send` n'est pas bouclé non plus.

Il faut lire jusqu'à la fermeture ou jusqu'au JSON complet, et boucler l'écriture.

---

## 13. Clé de session AES-256 portant 128 bits d'entropie — moyen

> **CORRIGÉ** — `ducky-network/sessionmgr/trames.go`, tests dans
> `trames_entropy_test.go`. Passée de 128 à 192 bits, sans changement de
> protocole.

La clé de session est une chaîne de 32 caractères hexadécimaux, utilisée **telle
quelle** comme clé AES-256 — soit 32 octets ASCII.

Chaque caractère hexadécimal ne porte que 4 bits d'entropie. Les 32 octets
transportent donc **128 bits**, pas 256. AES est employé en 256 bits, avec la
force d'un AES-128.

Le code tirait d'ailleurs bien 32 octets aléatoires — 256 bits — avant de les
encoder en hexadécimal (64 caractères) puis de **tronquer à 32** :

```go
key := hex.EncodeToString(raw)[:32]
```

La troncature jetait exactement la moitié de l'aléa tiré.

### Ce qui a été fait, et pourquoi pas 256 bits

La correction envisagée d'abord — décoder l'hexadécimal pour retrouver
256 bits — ne tient pas : la clé doit faire 32 octets pour AES-256, et
`hex.DecodeString` d'une chaîne de 32 caractères en rend 16. Décoder les
64 caractères complets donnerait bien 32 octets, mais changerait la valeur de la
clé des deux côtés à la fois, donc imposerait une bascule coordonnée entre le
core et tous les agents.

Retenu à la place : **base64url** (RFC 4648 §5) de 24 octets aléatoires, ce qui
donne exactement 32 caractères sans remplissage. Chaque caractère porte 6 bits
au lieu de 4 : **192 bits** au lieu de 128.

Aller au-delà supposerait des octets binaires bruts, donc 256 valeurs possibles
par octet. Or la clé transite dans un protocole dont les trames sont découpées
sur les sauts de ligne : un octet `0x0A` tiré au hasard couperait la trame en
deux. Le texte est ici une contrainte de fond.

### Pourquoi le point s'arrête ici, et non à 256 bits

**Décision : clos à 192 bits.**

Il resterait possible d'atteindre 256 bits réels en transmettant 64 caractères
décodés en 32 octets binaires de part et d'autre. Cela n'a pas été fait, et ce
n'est pas une dette : c'est un arbitrage.

Trouver deux clés de session identiques parmi des tirages de 192 bits demande de
l'ordre de 2^96 essais — le paradoxe des anniversaires. Ce nombre n'a pas de
sens physique : en produisant un milliard de clés par seconde depuis le Big Bang,
on n'aurait pas parcouru une fraction perceptible de l'espace. Passer à 256 bits
déplace un seuil déjà inatteignable vers un seuil plus inatteignable encore.

En face, le coût est réel : la valeur de la clé changerait des deux côtés, donc
une bascule coordonnée entre le core et tous les agents. Un agent qui décode face
à un core qui ne décode pas ne déchiffre plus rien, et la session échoue sans
message exploitable.

Le seul gain aurait été de rendre exacte l'annonce « AES-256 ». C'est un gain
d'affichage, obtenu au prix d'un risque d'exploitation — mauvais échange.

Ce qui comptait dans ce point était l'écart de 128 bits entre ce que le code
annonçait et ce qu'il produisait, parce qu'un tel écart trompe la revue suivante.
Cet écart est traité : le code dit maintenant ce qu'il fait, et le test le
mesure.

**Aucune bascule à coordonner** : la clé est produite par le core et transmise
au client, qui la stocke sans jamais l'analyser — pas de `hex.DecodeString`,
pas de contrôle de longueur ni de format dans le client ni dans le SDK. Seul
l'alphabet change, à longueur constante.

### Sur la forme du test

`TestLongueurCleDeSession` **passe** sur le code fautif : la clé faisait bien
32 octets. C'est tout le sujet — mesurer la taille ne dit rien de l'entropie.

Le test qui attrape le défaut compte les **valeurs distinctes** effectivement
atteintes par chaque position sur 400 tirages : 16 pour l'hexadécimal, 64 pour
base64url.

Le chiffrement lui-même est correct : `EncryptAESGCMString` tire un nonce
aléatoire par message via `crypto/rand`, le préfixe au chiffré, et le
déchiffrement contrôle la longueur avant de découper. Aucune réutilisation de
nonce, aucun usage de `math/rand` dans les trois modules.

---

## 14. Confiance au premier contact sur la clé du core, sans reprise — moyen

> **CORRIGÉ** — `serveurauth/coretrust.go` (agent et SDK),
> `key_management/core_fingerprint.go` (core). Tests dans `coretrust_test.go`
> des deux côtés et dans `testrunner/run_core_fingerprint.go`.

`askkey` n'est émis que si `serveurpublickey.pem` est absent (`HaveServeurKey`).
La clé publique du core est donc récupérée **une fois**, sur un canal non
authentifié, puis conservée.

C'est un modèle de confiance au premier usage, comparable à celui de SSH, et il
est défendable. Deux réserves :

- **rien n'atteste** la clé au moment où elle est acceptée : pas d'empreinte à
  confronter, pas de valeur épinglée dans la configuration. Un attaquant présent
  lors du premier démarrage devient le core pour cette machine, définitivement ;
- **aucun chemin de reprise** n'est prévu. Le jour où le core change de clé,
  chaque agent doit voir son fichier supprimé à la main — sans quoi le défi 01
  échoue avec un message qui ne dit pas que la clé est périmée.

L'enrôlement des services (01_05 → 01_08) offre une meilleure garantie, puisque
la clé d'enrôlement est un secret partagé hors bande. Les agents n'en bénéficient
pas.

### Ce qui a été fait

Le principe est celui de la clé d'enrôlement : **faire passer l'attestation par
un autre canal que celui qu'elle doit attester**.

Ce canal existait déjà sans qu'on s'en serve. `vlt create -join` se connecte à la
machine en SSH, donc sur un canal authentifié par une clé, et y dépose des
fichiers. Un fichier de plus n'y coûte rien, et il porte la garantie que la trame
`askkey` ne peut pas porter — puisque cette trame précède, par construction,
tout moyen d'authentifier son émetteur.

Le core dépose donc `core_key_fingerprint` dans le répertoire recopié sur la
machine ; l'agent compare la clé reçue à cette empreinte **avant** de l'écrire.
Vérifier après écriture aurait supposé de défaire l'écriture sans faute sur tous
les chemins d'erreur.

L'empreinte est le SHA-256 du **DER**, pas du PEM, et s'affiche
`SHA256:<base64>` comme `ssh-keygen -lf`. Le PEM est une enveloppe texte dont la
mise en forme varie — un fichier passé par Windows arrive en CRLF. Une empreinte
sensible à ces variations produirait un refus annonçant « la clé du core a
changé » sur une clé identique : le pire diagnostic possible, puisqu'il oriente
vers la mauvaise conclusion.

### Sur la machine sans empreinte

Une installation manuelle n'a pas d'empreinte. L'agent l'accepte, et **le
signale** :

```
WARNING  aucune empreinte de référence sur cette machine
         (/etc/vaultaire_client/.ssh/core_key_fingerprint absent) :
         la clé du core est acceptée en confiance au premier usage,
         empreinte SHA256:...
```

Refuser de démarrer aurait rendu l'installation manuelle impossible, et le
remède aurait été pire — on aurait contourné le contrôle. Accepter en silence
aurait ramené au défaut d'origine.

La différence tient à ce que l'avertissement laisse une trace : un parc où cette
ligne apparaît est un parc qu'on peut corriger. Un parc où rien n'apparaît est
un parc dont on ignore l'état — et c'était la situation.

### Sur la rotation

Quand la clé ne correspond plus, l'agent refuse et le journal distingue les deux
cas, parce qu'ils appellent des réponses opposées :

- **le core a changé de clé** — réinstallation, restauration de sauvegarde,
  rotation volontaire. La commande exacte pour accepter la nouvelle clé figure
  dans le message ;
- **quelqu'un répond à la place du core.** Effacer les fichiers reviendrait
  alors à accepter l'imposteur.

Les départager suppose de connaître l'empreinte réelle du core, obtenue **depuis
le core**. D'où `vlt certificate fingerprint`. Sans cette commande, la seule
issue serait d'effacer et d'espérer — c'est-à-dire d'accepter d'avance ce que la
vérification était censée détecter.

La bascule automatique par signature de la nouvelle clé avec l'ancienne a été
écartée : elle suppose l'ancienne clé privée disponible, donc ne fonctionne pas
dans le cas qui motive le plus une rotation — sa compromission ou sa perte.

### Sur la forme des tests

Le nom `core_key_fingerprint` apparaît à quatre endroits qui ne se compilent
jamais ensemble : le core, l'agent, le SDK, et `rocky.sh`.

Une divergence entre eux ne produit **aucune erreur** : le core dépose un fichier
que personne ne lit, l'agent cherche un fichier absent, conclut qu'aucune
empreinte n'est configurée, et accepte la première clé venue. La protection
disparaît sans que rien ne casse.

`testrunner/run_core_fingerprint.go` lit donc les sources et vérifie que les
quatre concordent. Vérifié par mutation : renommer la constante côté SDK et dans
le script fait échouer le test, avec le nom du fichier fautif.

Ce test ne peut s'exécuter que depuis l'arborescence des sources. Sur un core
installé il n'échoue pas — mais il ne rend pas non plus un succès muet : son
libellé porte « NON VÉRIFIÉ », seul champ affiché quand un test passe.

---

## 15. Onze goroutines, un seul `recover()` — moyen

> **CORRIGÉ** — tests dans `pam_module/hardening_test.c` et dans les paquets Go.


L'agent lance 11 goroutines et ne contient qu'un seul `recover()` ; le SDK
également.

En Go, une panique dans une goroutine non protégée **termine tout le processus**.
Sur l'agent, cela veut dire : plus de GPO, plus de révocation, plus de socket PAM.
Or ces goroutines traitent des trames venues du réseau — le même profil d'entrée
qui avait produit la panique `Message_Order[0]` corrigée côté core.

Le point 1 s'en aggrave : un agent mort laisse le socket libre dans `/tmp`.

---

## 16. `InsecureSkipVerify: true` dans `vaultaire_ctl` — moyen

> **CORRIGÉ** — tests dans `pam_module/hardening_test.c` et dans les paquets Go.


`src/vaultaire_ctl/vaultairectl.go:175` :

```go
TLSClientConfig: &tls.Config{InsecureSkipVerify: true}, // ⚠️ en prod remplacer par vérif réelle
```

Le commentaire reconnaît le problème. L'outil parle à l'API d'administration :
c'est le canal où circulent les gestes les plus lourds du système, et il accepte
n'importe quel certificat.

`src/api_client_package/client.go` fait mieux : le drapeau y est **configurable**
et vaut faux par défaut.

Le correctif des SAN LDAPS (2.1.0) fournit la brique manquante — un certificat
correct et importable rend la vérification praticable.

---

## 17. Journaux en 0644 — mineur

> **CORRIGÉ** — tests dans `pam_module/hardening_test.c` et dans les paquets Go.


`logs/CreateLogs.go` (agent) ouvre en `0644` avec un répertoire en `0755` ; le
journal PAM est créé sans mode explicite, donc typiquement 0644 lui aussi.

Ces fichiers portent les noms de comptes, les horaires de connexion, les statuts
administrateur et — point 10 — les clés SSH. 0640 avec un groupe dédié suffirait.

`vaultaire_log_v` ouvre et ferme le fichier à chaque ligne, sans verrou : deux
modules PAM concurrents peuvent entrelacer leurs écritures.

---

## 18. Reconnexion à intervalle fixe — mineur

> **CORRIGÉ** — tests dans `pam_module/hardening_test.c` et dans les paquets Go.


`EnableServeurCommunication.go` : `time.Sleep(30 * time.Second)` en cas d'échec.

Intervalle constant, sans dégressivité ni dispersion. Un core qui redémarre voit
tout le parc revenir **en même temps**, toutes les 30 secondes, avec la
poignée de main RSA-4096 que chaque connexion réclame. Sur un parc de taille
moyenne, la charge de reprise devient le problème suivant.

Une dégressivité exponentielle plafonnée, avec une dispersion aléatoire, coûte
quelques lignes.

---

## 19. `is_vaultaire_user` reconnaît un domaine à la présence d'un `@` — mineur

> **CORRIGÉ** — tests dans `pam_module/hardening_test.c` et dans les paquets Go.


```c
int is_vaultaire_user(const char *username) {
    return strchr(username, '@') != NULL;
}
```

Même règle dans le module NSS. Tout compte local comportant un `@` — cas rare
mais légal — est traité comme un compte de domaine : envoyé au daemon,
potentiellement doté de l'UID 5001, et son mot de passe local réécrit.

Comparer au domaine réellement configuré serait plus juste, et le domaine est
disponible côté agent.

---

## 20. Aucun test sur 11 500 lignes — mineur, mais structurant

| Module | Lignes | Fichiers de test |
|---|---|---|
| `vaultaire_client` | 8 653 | 2 (paquet `gpo` seulement) |
| `ducky-network-sdk-service` | 2 851 | 0 |
| `pam_module` (C) | 829 | 0 |

Le core, lui, a 20 fichiers de test et 242 cas dans son `testrunner`.

Les points 3, 5 et 12 sont exactement le genre de défaut qu'un test unitaire
attrape en une ligne d'assertion. Le point 3 en particulier : `run_useradd`
échoue **à chaque appel**, et il aura suffi d'exécuter la commande une fois pour
le voir.

Ce n'est pas un reproche sur la couverture pour elle-même. C'est le constat que
la partie du système qui tourne **en root sur chaque poste** est la moins
vérifiée.

---

## Ordre de traitement suggéré

**D'abord, ensemble** — les points 1, 2 et 3 sont liés, et corriger l'un sans les
autres dégrade la situation :

1. **Point 1** (socket) — le seul qui donne root à un utilisateur local.
2. **Point 2** (UID partagé) — mais il faut le point 3 en même temps, sinon les
   comptes locaux ne seront toujours pas créés et plus rien ne fonctionnera.
3. **Point 3** (`useradd`) — une ligne.

**Ensuite, ce qui touche à l'exécution en root** : points 4 (liens symboliques),
6 (injection shell), 11 (`SIGPIPE`).

**Puis la correction fonctionnelle** : points 5 (JSON), 12 (`recv`), 7 (contrat
NSS), 9 (`.ssh`).

**Enfin le durcissement** : 8, 10, 13, 14, 15, 16, 17, 18, 19, et la couverture
de tests (20) au fur et à mesure — chaque correction ci-dessus mérite le test qui
l'accompagne.

---

## Ce qui a été trouvé sain

Il serait trompeur de ne lister que les défauts.

- **`local_password_matches`** (`pam_common.c`) est du bon code : `crypt_r`
  plutôt que `crypt`, `struct crypt_data` sur le tas parce qu'il est trop gros
  pour la pile d'un module PAM, `explicit_bzero` avant libération, traitement
  explicite des marqueurs `!` et `*` de compte verrouillé. Le commentaire
  explique pourquoi la comparaison précède la réécriture — préserver `sp_lstchg`,
  donc la politique de péremption.
- **Le chiffrement symétrique du SDK** est correct : nonce aléatoire par message,
  contrôle de longueur avant découpe, `crypto/rand` partout. Aucun usage de
  `math/rand` dans les trois modules audités.
- **La clé privée du SDK** est écrite en 0600.
- **L'état des GPO et des révocations** est écrit par temporaire puis `rename`,
  avec `0600` posé avant la publication — exactement ce qui manque au point 4.
- **`isValidUserInput`** côté Go est une liste blanche. C'est le bon modèle ;
  c'est le C qui n'a pas suivi.


---

## Les deux points qui demandaient une décision — tranchés et traités

### 13 — Clé de session AES-256 portant 128 bits d'entropie → **CORRIGÉ**

L'analyse initiale, reproduite ci-dessous, concluait qu'aucune correction n'était
possible sans bascule coordonnée. **Cette conclusion était fausse**, et il vaut
la peine de dire pourquoi : elle ne considérait qu'une seule correction — décoder
l'hexadécimal — et en avait déduit que le problème lui-même était insoluble
isolément.

Ce raisonnement comportait par ailleurs une erreur de fait : `hex.DecodeString`
d'une chaîne de 32 caractères rend **16 octets**, pas 32. AES-256 les aurait
refusés. La correction proposée n'aurait donc pas seulement demandé une bascule :
elle n'aurait pas fonctionné du tout.

La vraie question n'était pas « comment obtenir 256 bits » mais « comment obtenir
plus de bits **dans 32 caractères** ». Formulée ainsi, la réponse est immédiate :
changer l'alphabet. base64url porte 6 bits par caractère au lieu de 4, soit
**192 bits**, à longueur constante — donc sans qu'aucun client ait à changer.

Voir la section 13 plus haut pour le détail.

> **Analyse initiale, conservée** — décoder la chaîne rendrait les 256 bits mais
> changerait la clé effective des deux côtés ; client et core devraient basculer
> en même temps, ce qui en ferait une bascule de protocole plutôt qu'une
> correction isolée.
>
> La conclusion ne tenait pas : elle supposait que la seule issue était de
> changer la valeur de la clé, alors qu'il suffisait de changer son alphabet.

### 14 — Confiance au premier contact, sans reprise

`askkey` récupère la clé publique du core **une seule fois**, sur un canal non
authentifié, puis la conserve. C'est le modèle de SSH, et il est défendable.

Deux réserves, et elles appellent des réponses différentes :

- **rien n'atteste la clé** au moment où elle est acceptée : ni empreinte à
  confronter, ni valeur épinglée dans la configuration. Un attaquant présent lors
  du premier démarrage devient le core pour cette machine, définitivement ;
- **aucun chemin de reprise** n'existe. Le jour où le core change de clé, chaque
  agent doit voir son fichier supprimé à la main — sans quoi le défi `01` échoue
  avec un message qui ne dit pas que la clé est périmée.

La seconde réserve est la plus concrète, et la plus simple à lever : une empreinte
attendue dans la configuration de l'agent suffirait, sur le modèle de ce qui a été
fait pour les SAN LDAPS.

La première demande de décider ce qui fait autorité au premier contact — la clé
d'enrôlement l'assure déjà pour les services, les agents n'en bénéficient pas.

**Décision : corrigé.** Les deux réserves sont levées, par le même mécanisme —
une empreinte transportée par le canal SSH de `vlt create -join`, c'est-à-dire
par un chemin distinct de celui qu'elle atteste.

Ce qui a rendu la correction simple est justement ce que l'analyse initiale
n'avait pas vu : il n'était pas nécessaire d'inventer un canal hors bande, il
suffisait de se servir de celui que l'installation empruntait déjà. Le détail
figure en section 14.

Reste connu et assumé : une machine installée à la main, sans `-join`, n'a pas
d'empreinte et accepte la première clé — en le journalisant.

---

## Points hors liste initiale, traités dans la même passe

Trois défauts relevés en marge de l'audit, sans numéro attribué.

### Port SSH figé à 22 dans `-join` → **CORRIGÉ**

`Manage_Auto_ADD_client` passait `22` en dur à ses trois étapes — `ssh-keyscan`,
`scp`, `ssh`. Une machine dont `sshd` écoute ailleurs était injoignable, avec
pour seul indice :

```
ssh-keyscan failed: exit status 1 | Stderr:
```

Un stderr vide, parce que `ssh-keyscan` ne dit rien quand il ne trouve personne.
Rien dans ce message ne désignait le port.

`-join <hôte[:port]> <user>` accepte désormais un port ; 22 reste la valeur par
défaut, donc les commandes existantes ne changent pas de cible. Le découpage
passe par `net.SplitHostPort` et non par un `LastIndex(":")` — sans quoi
`2001:db8::1` deviendrait l'hôte `2001:db8:` et le port `1`.

Le message d'échec énumère maintenant quoi vérifier, et rappelle la syntaxe avec
port. Voir `ducky-network/new_client/AUTO_ADD_client.go/hostport.go`, tests dans
`hostport_test.go`.

### Certificat du serveur web et de l'API sans CN ni SAN → **CORRIGÉ**

`security.GenerateSelfSignedCertPEM` produisait un certificat dont le sujet se
réduisait à `Organization: SSO Vaultaire` : ni CommonName, ni SubjectAltName.

Un certificat sans nom **n'identifie personne**. Tout client qui vérifie
l'identité du serveur le rejette :

```
x509: certificate is not valid for any names
```

Le défaut passait inaperçu parce que les clients internes désactivaient la
vérification — un cercle : le certificat est invérifiable, donc on cesse de
vérifier, donc plus personne ne remarque qu'il est invérifiable. Et la
vérification une fois désactivée l'est pour **tous** les certificats, y compris
celui qu'un tiers présenterait à la place du nôtre.

Le certificat porte désormais les noms détectés (nom de machine long et court,
adresses des interfaces, `localhost`) et ceux déclarés en configuration sous
`website.web_tls_dns_names` / `web_tls_ip_addresses`. Deux défauts voisins
corrigés au passage : numéro de série porté de 62 à 128 bits (RFC 5280 §4.1.2.2)
et `NotBefore` reculé de 5 minutes, faute de quoi un client dont l'horloge
retarde rejette un certificat fraîchement émis.

Le test ne compare pas les champs : il soumet le certificat à `x509.Verify`,
c'est-à-dire à la vérification qu'exécute un vrai client TLS.

Voir `core/global/security/cert_identity.go`, tests dans `cert_identity_test.go`.
