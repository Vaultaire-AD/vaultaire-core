# Audit de sécurité du 25/09/2026

> Ce fichier explique les constats **sérieux** relevés en relisant le code
> existant. Chacun a son entrée dans [`TO-DO.md`](./TO-DO.md) ; ici se trouve ce
> qu'une entrée de liste ne peut pas porter : ce que le code fait aujourd'hui, le
> scénario concret, et ce qui rend la correction délicate.
>
> Les constats **critiques** (points 95 à 100) ont, eux, une entrée complète
> dans `TO-DO.md` : ils n'ont pas besoin de ce fichier.
>
> Méthode : relecture du code, pas d'exécution. Chaque constat porte le fichier
> et la ligne. Ce qui n'a pas été vérifié est marqué « à confirmer ».

### État au 26/09/2026

| Point | État |
|---|---|
| 101, 102, 103, 104, 105 | ouverts |
| 98 — secrets en clair dans la base | ouvert, à cadrer |
| **106** — compte `vaultaire` | **traité** (2.2) — `03_01` et `08_01` refusent le compte d'amorçage, et un test-sentinelle interdit d'accorder un droit à partir du nom d'une session Ducky |
| **107** — unicité de `did_login` | **traité** (2.2) — contrainte en base, dédoublonnage à la migration, écritures en `ON DUPLICATE KEY UPDATE` |

Les constats **critiques** relevés le même jour sont eux aussi traités dans la
2.2, à une exception près :

| Point | État |
|---|---|
| **95** — second facteur absent du chemin Ducky | **traité** — invite après le mot de passe sur SSH, GDM et Windows, convention `0000`, migration par `vlt mfa ducky` |
| **96** — domaine du groupe superadmin | **traité** — fermé en écriture, sous-domaines compris |
| **97** — élévation locale par lien symbolique | **traité** — traversée par descripteurs, `O_NOFOLLOW` à chaque composant |
| **99** — configuration livrée et mots de passe à usage unique | **traité** — le core refuse de démarrer sur les valeurs du dépôt ; drapeau `must_change_password` |
| **100** — robustesse des mots de passe | **traité** — longueur minimale 12, plancher 8, point d'écriture unique |
| **108** — métriques `04_05` émises par personne | **traité** — le proxy les émet, `vlt cluster list` et la page Cluster les montrent |

**98** reste ouvert : chiffrer les secrets au repos demande d'abord de décider
où vit la clé de chiffrement, ce qui est une décision d'exploitation avant d'être
une décision de code.

---

## Comment lire ce fichier

Un constat n'est pas une faille tant qu'on n'a pas dit **qui** peut l'atteindre.
Chaque section donne donc, dans l'ordre : ce que le code fait, qui peut le
déclencher, ce qu'il obtient, et pourquoi ce n'est pas trivial à corriger.

Trois niveaux d'accès reviennent :

| Qui | Ce qu'il possède |
|---|---|
| **anonyme** | une route vers le port du core, rien d'autre |
| **machine du parc** | la clé privée d'un agent enrôlé, donc root sur un poste |
| **délégué** | un compte de l'annuaire avec des droits RBAC sur un domaine |

---

## 101 — Le cadrage des trames Ducky

**Ce que le code fait.** `Read_Header_Size` (`trames_manager/ReadHeaderSize.go:7`)
rend le **premier octet reçu**, sans contrainte. `Read_Message_Size`
(`ReadMessageSize.go:9`) alloue un tampon de cette taille puis fait
`binary.BigEndian.Uint16` dessus.

```go
messageSizeBuf := make([]byte, headerSize)   // headerSize vient du réseau
_, err := conn.Read(messageSizeBuf)
size := int(binary.BigEndian.Uint16(messageSizeBuf))   // panique si headerSize < 2
```

**Qui.** Anonyme. `printf '\x01\xff' | nc core 6666` suffit.

**Ce qu'il obtient.** Une panique, rattrapée par le `defer recover()` de
`handleConnection` (`duckyGoroutine.go:47`) — donc pas d'arrêt du core. Mais
chaque panique écrit une ligne **CRITICAL avec la pile complète**. Deux octets
envoyés produisent plusieurs kilo-octets de journal. En boucle sur vingt
sockets, le journal commun se remplit et noie les vraies lignes SECURITY.

**Deux défauts voisins, même fichier.**

*Les lectures courtes.* `conn.Read` n'est jamais `io.ReadFull`, ni ici ni dans
`ReadMessageContent.go:43`, ni dans les jumeaux du SDK. TCP a parfaitement le
droit de rendre moins d'octets que demandé ; l'appelant lit alors une taille
fausse puis un corps tronqué, et les octets restants passent pour l'en-tête
suivant. **Cela arrive sans attaquant**, sur une liaison lente ou chargée : c'est
un défaut de robustesse qui se manifeste en échec d'authentification
intermittent, le genre qu'on cherche pendant des semaines.

*La troncature à l'émission.* `CompileMessageSize` (`sendmessage/SendMessage.go:19`) :

```go
binary.BigEndian.PutUint16(sizeBytes, uint16(len(message)))
```

`uint16(...)` tronque **sans erreur** au-delà de 65535. Le corps entier part sur
le socket, annoncé modulo 65536 : le pair lit N octets et prend la suite pour un
nouvel en-tête. Le tunnel est désynchronisé définitivement.

Ce n'est pas théorique : la trame `02_04` embarque **toutes** les clés publiques
SSH de l'utilisateur, jointes par virgule (`CheckAuthentification.go:224`), et
rien ne borne leur nombre — n'importe qui en dépose depuis sa page de profil.
Une soixantaine de clés RSA-4096 dépassent le seuil après chiffrement et base64.
L'utilisateur casse alors l'authentification Ducky de **tous** les comptes du
poste, à chaque fois qu'il s'y connecte. *(Seuil exact à confirmer par mesure ;
le mécanisme, lui, est certain.)*

**Le garde-fou manquant du SDK.** Le core refuse une trame de moins de cinq
lignes (`ReadMessageContent.go:16`, avec un commentaire « SÉCURITÉ » et un test
dédié). Le SDK, lui, indexe `lines[1]`, `lines[2]`, `lines[3:]` sans rien
vérifier (`ducky-network-sdk-service/duckynetwork/trames_manager/ReadMessageContent.go:12`).
Ce SDK est partagé par l'agent, le proxy, Nexus et le client Windows. La
disparité est le vrai signal : le défaut a été identifié et corrigé d'un seul
côté.

**Pourquoi ce n'est pas trivial.** Rien n'est difficile ici — c'est une dizaine
de lignes. Le piège est de corriger le core et d'oublier le SDK, comme la
première fois.

---

## 102 — L'API de commande n'a ni freinage ni borne

**Ce que le code fait.** `core/api/api.go` n'importe **pas** `ratelimit`, et
`commandHandler` (ligne 130) fait `json.NewDecoder(r.Body).Decode(&req)` sans
`http.MaxBytesReader`. L'ordre des opérations est : décoder le corps → chercher
l'utilisateur → charger ses clés → vérifier la signature.

**Qui.** Anonyme : le port TLS est ouvert, l'authentification *est* la signature,
donc il n'y a aucune barrière avant le travail coûteux.

**Ce qu'il obtient.** Deux choses.

*Amplification.* Chaque requête, même absurde, coûte au core deux lectures en
base puis une vérification RSA **par clé enregistrée sur le compte visé**. Un
compte à dix clés fait dix vérifications RSA par requête reçue. Aucun plafond.

*Énumération par chronométrage.* « Utilisateur introuvable » sort **avant** la
lecture des clés : le temps de réponse distingue un compte existant d'un compte
inconnu, et l'annuaire se cartographie sans aucun droit.

*Mémoire.* Le corps JSON est décodé avant toute authentification, avec un
`ReadTimeout` de 30 s : à débit de réseau local, cela fait plusieurs gigaoctets
par requête en vol.

**Pourquoi ce n'est pas trivial.** Le freinage existant (`core/auth/ratelimit`)
est conçu pour un couple (compte, source) sur un échec d'authentification. Ici il
faut freiner **avant** de savoir à quel compte on a affaire — donc sur la source
seule, avec un barème distinct. Et il faut décider quoi faire d'un intégrateur
légitime qui pilote le parc en rafale : le freinage par source le touche aussi.

---

## 103 — Le portail n'a ni jeton CSRF ni en-tête de sécurité

**Ce que le code fait.** Recherche exhaustive dans `vaultaire_serveur` : **zéro**
occurrence de `csrf`, `Content-Security-Policy`, `X-Frame-Options`,
`Strict-Transport-Security`, `X-Content-Type-Options`, `Referrer-Policy`. La
seule mention de CSRF est un commentaire de `web_login.go:126` qui constate
l'absence.

La défense repose entièrement sur `SameSite=Strict` posé sur le cookie de
session — correctement, avec `HttpOnly` et `Secure`.

**Qui.** Quiconque amène un administrateur connecté sur une page qu'il contrôle,
depuis une origine que `SameSite` ne couvre pas.

**Ce qu'il obtient.** Les actions d'administration sont des POST simples : créer
un compte, lier une GPO, **déclencher un kill switch**. Un POST forgé les
exécute.

`SameSite=Strict` couvre la navigation inter-site ordinaire. Il ne couvre pas :
un sous-domaine du même site enregistrable contrôlé par un tiers, une extension
de navigateur, ou un navigateur qui n'applique pas l'attribut. Et sans
`Content-Security-Policy`, toute injection HTML future — contenue aujourd'hui par
`html/template` — s'exécuterait sans aucune contrainte.

**Le modèle existe déjà dans le dépôt.** Nexus a de vrais jetons CSRF
(`vaultaire_nexus/internal/web/ui.go:212`). Il s'agit de le porter, pas de
l'inventer.

**Pourquoi ce n'est pas trivial.** Un jeton par formulaire veut dire toucher
**tous** les gabarits d'administration et tous les gestionnaires POST. Et une
`Content-Security-Policy` stricte casse le JavaScript en ligne : il faut d'abord
sortir les scripts des pages.

---

## 104 — « Deny » ne refuse pas

**Ce que le code fait.** Trois fichiers, le même motif
(`permission-manager.go:82`, `permission-manager-strict.go`) :

```go
if parsedPermission.Deny {
    continue
}
```

Un refus explicite fait **sauter ce groupe**, et la boucle continue sur les
suivants. Si un autre groupe accorde, c'est accordé.

**Qui.** Personne — ce n'est pas une faille exploitable, c'est un piège
d'exploitation.

**Ce que ça produit.** Un exploitant croit retirer un droit en posant un refus
sur un groupe sensible. Il ne retire **rien** tant que la cible appartient à un
autre groupe permissif. Le mot dit l'inverse de ce qu'il fait, sur un contrôle
d'accès — c'est le genre d'écart qu'on découvre après un incident, en relisant
pourquoi quelqu'un a pu faire ce qu'il a fait.

**Pourquoi ce n'est pas trivial.** Le comportement actuel est **délibéré** : le
commentaire de `DomainsWhereAllowed` l'assume, pour que « ce qu'on voit » et « ce
qu'on peut » restent cohérents. Rendre `Deny` prioritaire — la sémantique d'AD,
celle qu'on attend — change donc un arbitrage existant, et peut retirer des
droits en service à la mise à jour. L'alternative honnête est de **renommer** :
si ce n'est pas un refus, ça ne doit pas s'appeler `Deny`.

Il faut trancher, et le choix n'est pas technique.

---

## 105 — Le nom de table DNS est construit par concaténation

**Ce que le code fait.** Cinq fichiers de `core/dns/DNS_Database/` bâtissent un
nom de table à partir du nom de zone, puis l'interpolent dans la requête
(`DNS_DELETE_Zone.go:11`) :

```go
safeTableName := "zone_" + strings.ReplaceAll(zoneName, ".", "_")
db.Exec(fmt.Sprintf(`DROP TABLE IF EXISTS %s`, safeTableName))
```

La variable s'appelle `safeTableName` ; seuls les points ont été remplacés.

**La validation en amont.** `nomDNSAcceptable` (`core/action/actions_dns.go:361`)
refuse : plus de 253 caractères, les espaces, `/`, `\`, les sauts de ligne et
les tabulations, un point mal placé. Elle **laisse passer** l'apostrophe
inverse `` ` `` et la virgule.

**Qui.** Un délégué portant `write:dns`.

**Ce qu'il obtient.** `DROP TABLE` accepte une **liste** séparée par des
virgules, et MySQL cite les identifiants avec des apostrophes inverses. Un nom de
zone de la forme `` a`,`users `` produit :

```sql
DROP TABLE IF EXISTS zone_a`,`users`
```

soit la suppression de `zone_a` **et** de `users`. Aucun espace n'est nécessaire,
donc le filtre ne gêne pas.

**Ce qui limite.** `multiStatements` n'est pas activé dans le DSN
(`core/database/init_database.go:13`) : pas de requête empilée, donc pas
d'exécution arbitraire. La portée est la destruction de tables.

**À confirmer** par un essai réel : je n'ai pas exécuté la requête.

**Pourquoi ce n'est pas trivial.** Le vrai correctif n'est pas d'allonger la
liste de caractères interdits — c'est de valider le nom de zone par une **liste
blanche** (`^[a-z0-9]([a-z0-9-]*[a-z0-9])?(\.[a-z0-9]([a-z0-9-]*[a-z0-9])?)*$`)
et de citer l'identifiant. Et il faut vérifier les cinq fichiers, pas seulement
celui-ci.

---

## 106 — Le compte « vaultaire » : tunnel machine et superadmin confondus

> **Traité dans la 2.2.** `03_01` (SSH/PAM) et `08_01` (vérification par un
> service) refusent d'ouvrir une session au nom du compte d'amorçage ; le portail
> web, compte de secours, reste ouvert. La propriété qui protégeait déjà le
> produit — aucun droit ne se déduit de `Session.Username` — est désormais
> **énoncée par un test de source** qui échouera le jour où quelqu'un écrira
> cette lecture. Voir `Permissions_RBAC.md` §6 et DO 2.2, entrée 106.

**Ce que le code fait.** `CheckAuth` (`CheckAuthentification.go:186`) :

```go
if username == "vaultaire" {
    sessionmgr.Sessions.SetIdentity(...)
    sessionmgr.Sessions.SetStatus(..., SessionAuthenticated)
    ...
    dbsessions.AddLoginEntry(db, userID, ...)
    return "02_11..."
}
```

Pour ce nom d'utilisateur, la session passe **authentifiée sans que le challenge
soit comparé** — le `bytes.Equal` est dans la branche suivante. Et
`SendAuthRequest` délivre le challenge sans avoir vérifié de mot de passe.

**Ce qui protège réellement.** La poignée de main 01_01/01_02 : la réponse est
chiffrée en RSA vers la clé publique de la machine déclarée. Il faut donc la clé
privée d'un client **déjà enrôlé**. C'est un arbitrage défendable — une machine
n'a pas de mot de passe à retenir, sa clé *est* son identité.

**Le vrai problème n'est pas là.** Il est que le nom `vaultaire` désigne **deux
choses différentes** :

- le compte sous lequel chaque machine du parc ouvre son tunnel ;
- le compte d'amorçage de l'annuaire, membre du groupe protégé, porteur de
  `vaultaire_all`, exempté d'expiration.

C'est la **même ligne** de la table `users` : `Get_User_ID_By_Username(db,
"vaultaire")`. Conséquences observables : chaque machine du parc ouvre une ligne
`did_login` au nom du superadmin, et toute lecture de droits qui partirait du nom
d'utilisateur d'une session Ducky accorderait tout.

Aujourd'hui rien ne fait cette lecture : `Split_Action` filtre par **type de
client**, pas par compte. La porte est fermée par une propriété que rien
n'énonce.

**Pourquoi ce n'est pas trivial.** Séparer les deux identités veut dire un
compte de machine distinct (`@machine`, ou un type de compte), donc toucher
l'authentification, `status -c`, la purge de sessions et l'enrôlement — et
migrer un parc existant. Le minimum immédiat est différent et bien plus petit :
**énoncer la règle** par un test (aucun chemin n'autorise à partir du nom d'une
session Ducky), et refuser explicitement le nom `vaultaire` là où un compte
d'annuaire est attendu.

---

## 107 — `did_login` n'a pas de contrainte d'unicité

> **Traité dans la 2.2.** L'unicité `(compte, machine)` est une contrainte de la
> base, posée après dédoublonnage sur les bases existantes, et les deux écritures
> passent par `INSERT … ON DUPLICATE KEY UPDATE`. Voir `Base_de_donnees.md` et
> DO 2.2, entrée 107.

**Ce que le code fait.** `user_sessions` porte
`UNIQUE KEY uq_user_session (d_id_user, d_id_logiciel)`, et le commentaire du
schéma souligne la différence :

> « L'unicité (compte, machine) est portée par la BASE cette fois, et non par le
> code comme dans did_login. »

`did_login` n'a donc aucune contrainte. `AddLoginEntry` fait `SELECT EXISTS` puis
`INSERT`, `RafraichirConnexion` fait `COUNT(*)` puis `UPDATE` : deux séquences
**lecture puis écriture non atomiques**.

**Qui.** Personne volontairement — deux authentifications simultanées de la même
paire (compte, machine) suffisent. Le `--fetch-key` de sshd en ouvre une à chaque
connexion SSH, en parallèle du tunnel : la fenêtre existe en fonctionnement
normal.

**Ce que ça produit.** Deux lignes pour une seule machine, donc la machine
affichée **deux fois** dans `status -c`. C'est exactement le défaut que le point
92 vient de fermer pour les sessions PAM, réintroduit par une autre porte — et
cette fois par une course, donc intermittent.

**Pourquoi ce n'est pas trivial.** Poser la contrainte sur une base existante
échoue s'il y a déjà des doublons : il faut une migration qui dédoublonne
d'abord. Le produit a déjà le mécanisme (`db_schema`), mais la migration doit
choisir **quelle** ligne garder — la plus récente, vraisemblablement.

---

## Les constats laissés de côté

Relevés pendant l'audit, jugés en dessous du seuil « sérieux ». Ils sont ici pour
ne pas être redécouverts comme neufs :

| Constat | Où |
|---|---|
| Aucun code de récupération MFA : perte du téléphone = verrouillage | `core/command/command_mfa/` |
| `ldap.mfa_bypass` est global, pas par compte | `configuration_file/ReadConfigFile.go` |
| L'API ignore l'expiration du mot de passe ; une clé SSH y vaut mot de passe permanent, sans portée ni échéance | `core/api/api.go`, `db_users/add_user_key.go` |
| Brute-force TOTP par recyclage du jeton : `ratelimit.Reussite` est appelé avant l'étape MFA | `web_serveur/web_login.go:103` |
| `write:mfa` sert à la fois à réinitialiser un compte et à lever le MFA d'un groupe entier | `core/action/actions_groups.go:188` |
| Empreinte MD5 de « password » dans le seed — inexploitable par accident (contrôle de longueur), pas par décision | `db_schema/create_data_base.go:387` |
| Cookie de session figé à 30 min alors que la durée est réglable | `web_serveur/web_login.go:137` |
| Upload de clé publique sans plafond mémoire ni disque | `web_serveur/web_profil.go:284` |
| Pas de numéro de séquence : rejeu intra-session possible, sans effet connu aujourd'hui | protocole Ducky |
| `TLS MinVersion` absent côté portail (présent côté API) | `web_serveur/startWEBserver.go:75` |
| `SessionIntegritykey` de la trame jamais comparé à la session réelle | `trames_manager/` |
| Correspondance de préfixes de chemins GPO sans frontière de composant, et mise en minuscules sur un système sensible à la casse | `core/gpo/guards.go:75` |
| Un champ GPO déclaré `Dynamic` court-circuite `CheckPath` — aucun champ chemin n'est concerné aujourd'hui, rien ne l'interdit demain | `core/gpo/validate.go:136` |
| `05_05` ne corrèle pas la demande de politique utilisateur à une session réellement ouverte : un agent compromis énumère les politiques de son périmètre | `gpo_manager/handlers.go:55` |
