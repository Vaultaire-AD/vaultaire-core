# Audit — agent, SDK et modules PAM/NSS

**Périmètre** : `src/vaultaire_client` (8 653 lignes), `src/ducky-network-sdk-service`
(2 851 lignes), `src/vaultaire_client/pam_module` (829 lignes de C).
**Angles** : sécurité, correction fonctionnelle, ressources.
**État** : les trois premiers points ont été **corrigés** (voir la marque sous
chaque titre). Les 17 autres restent ouverts.

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
| 4 | `authorized_keys` écrit en root sans protection contre les liens symboliques | **majeur** | PAM |
| 5 | Mot de passe injecté dans du JSON sans échappement | majeur | PAM |
| 6 | Injection shell possible dans la gestion du groupe sudo | majeur | PAM |
| 7 | NSS renvoie des pointeurs hors de son tampon | majeur | NSS |
| 8 | `pam_sm_acct_mgmt` ne refuse jamais rien | majeur | PAM |
| 9 | `MkdirAll(".ssh", 0777)` au mauvais endroit — dupliqué agent/SDK | moyen | agent + SDK |
| 10 | Réponse complète du daemon journalisée en clair | moyen | PAM |
| 11 | `SIGPIPE` non neutralisé autour de `chpasswd` | moyen | PAM |
| 12 | Lecture socket en un seul `recv` | moyen | PAM |
| 13 | Clé de session AES-256 portant 128 bits d'entropie | moyen | SDK + core |
| 14 | Confiance au premier contact sur la clé du core, sans reprise | moyen | agent + SDK |
| 15 | 11 goroutines dans l'agent, un seul `recover()` | moyen | agent |
| 16 | `InsecureSkipVerify: true` dans `vaultaire_ctl` | moyen | ctl |
| 17 | Journaux PAM et agent en 0644 | mineur | agent + PAM |
| 18 | Reconnexion à intervalle fixe, sans dégressivité | mineur | agent |
| 19 | `is_vaultaire_user` reconnaît un domaine à la présence d'un `@` | mineur | PAM |
| 20 | Aucun test sur 11 500 lignes de C et de SDK | mineur | tous |

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

La clé de session est une chaîne de 32 caractères hexadécimaux, utilisée **telle
quelle** comme clé AES-256 — soit 32 octets ASCII.

Chaque caractère hexadécimal ne porte que 4 bits d'entropie. Les 32 octets
transportent donc **128 bits**, pas 256. AES est employé en 256 bits, avec la
force d'un AES-128.

128 bits restent hors d'atteinte, ce n'est donc pas une urgence. Mais l'écart
entre le nom et la réalité est le genre de chose qui trompe la revue suivante,
et un décodage hexadécimal (`hex.DecodeString`) rendrait les 256 bits pour un
coût nul.

Le chiffrement lui-même est correct : `EncryptAESGCMString` tire un nonce
aléatoire par message via `crypto/rand`, le préfixe au chiffré, et le
déchiffrement contrôle la longueur avant de découper. Aucune réutilisation de
nonce, aucun usage de `math/rand` dans les trois modules.

---

## 14. Confiance au premier contact sur la clé du core, sans reprise — moyen

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

---

## 15. Onze goroutines, un seul `recover()` — moyen

L'agent lance 11 goroutines et ne contient qu'un seul `recover()` ; le SDK
également.

En Go, une panique dans une goroutine non protégée **termine tout le processus**.
Sur l'agent, cela veut dire : plus de GPO, plus de révocation, plus de socket PAM.
Or ces goroutines traitent des trames venues du réseau — le même profil d'entrée
qui avait produit la panique `Message_Order[0]` corrigée côté core.

Le point 1 s'en aggrave : un agent mort laisse le socket libre dans `/tmp`.

---

## 16. `InsecureSkipVerify: true` dans `vaultaire_ctl` — moyen

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

`logs/CreateLogs.go` (agent) ouvre en `0644` avec un répertoire en `0755` ; le
journal PAM est créé sans mode explicite, donc typiquement 0644 lui aussi.

Ces fichiers portent les noms de comptes, les horaires de connexion, les statuts
administrateur et — point 10 — les clés SSH. 0640 avec un groupe dédié suffirait.

`vaultaire_log_v` ouvre et ferme le fichier à chaque ligne, sans verrou : deux
modules PAM concurrents peuvent entrelacer leurs écritures.

---

## 18. Reconnexion à intervalle fixe — mineur

`EnableServeurCommunication.go` : `time.Sleep(30 * time.Second)` en cas d'échec.

Intervalle constant, sans dégressivité ni dispersion. Un core qui redémarre voit
tout le parc revenir **en même temps**, toutes les 30 secondes, avec la
poignée de main RSA-4096 que chaque connexion réclame. Sur un parc de taille
moyenne, la charge de reprise devient le problème suivant.

Une dégressivité exponentielle plafonnée, avec une dispersion aléatoire, coûte
quelques lignes.

---

## 19. `is_vaultaire_user` reconnaît un domaine à la présence d'un `@` — mineur

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
