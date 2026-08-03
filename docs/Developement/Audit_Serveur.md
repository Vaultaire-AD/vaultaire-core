# Audit global du serveur — base de données et interface web

Audit statique de `src/vaultaire_serveur`, ciblé sur les deux paquets demandés :
`core/database` (et ses cinq sous-paquets) et `core/web_serveur`.

Côté client, rien à signaler qui n'ait déjà été traité.

Aucune compilation ni exécution n'a été possible : tout ce qui suit est un
constat de lecture, avec chemin et ligne.

---

## Récapitulatif

| # | Gravité | Où | Constat | État |
|---|---------|-----|---------|------|
| 12 | **Critique** | Crypto | Hachage des mots de passe en SHA-256 à un tour | Ouvert |
| ~~13~~ | ~~Critique~~ | Ducky | ~~RSA PKCS#1 v1.5 — oracle Bleichenbacher~~ | **CORRIGÉ** — migration OAEP, voir TO-DO 11 |
| 14 | **Élevée** | Ducky | Les sessions non authentifiées ne sont jamais balayées | Ouvert |
| 15 | **Élevée** | Transverse | Aucun `recover()` : une panique dans une goroutine tue tout le serveur | Ouvert |
| 16 | **Moyenne** | LDAP | Encodeurs BER manuels : forme longue absente, `messageID` tronqué | Ouvert — **TO-DO 12** |
| 17 | **Moyenne** | DNS | Résolution strictement séquentielle, pas d'EDNS0, pas de limitation de débit | Ouvert |
| 11 | **Critique** | Ducky | Le chemin `04_01` contourne l'authentification et désarme le contrôle d'ordre des trames | **Ouvert — reporté** |
| 7 | **Faible** | database | Même requête recopiée dans 10 fonctions, alors que le helper existe | Ouvert |
| 8 | **Faible** | database | Doublons fonctionnels et nommage incohérent | Ouvert |
| 10 | **Note** | web | `web_admin_pages.go` fait 1314 lignes et mélange sept domaines | Ouvert |

> La numérotation vient des audits successifs ; les points corrigés ont été
> retirés. Le **11** est repris de l'audit des quatre points d'entrée
> (`Audit_Permissions.md`) : il y était reporté au motif que la catégorie 04 est
> expérimentale, et il le reste. Sa portée a en revanche changé depuis, et
> l'analyse ci-dessous est à jour.
>
> Les points **7, 8 et 10** sont de la dette technique sans conséquence de
> sécurité immédiate, laissés de côté à la demande.

---

## 11. Critique — `04_01` contourne l'authentification (reporté)

> **Décision : la catégorie 04 est expérimentale, à traiter avec le sujet
> cluster.** Conservé ici pour que le travail ne reparte pas de zéro, et parce
> que le report est une décision, pas un oubli.

**Chemins :** `ducky-network/networkSecurity/CheckIntegrity.go:19-21`,
`ducky-network/sessionmgr/trames.go:82`,
`ducky-network/host_handler/handler.go:66`

### Le mécanisme

Trois éléments se combinent, et aucun n'est fautif isolément.

**1. Rien n'est authentifié avant `02_01`.** C'est là, et seulement là, que
`duckysession.IsSafe` passe à `true` (`ClientAuthManager.go:16`). Avant ce
point, `MessageReader` déchiffre les trames entrantes avec la **clé privée du
serveur** :

```go
if duckysession.IsSafe {
    messageDecrypt, err = DecryptAESGCMString(duckysession.SessionKey, messageBuf)
} else {
    messageDecrypt, err = DecryptMessageWithPrivate(privateKeyStr, messageBuf)  // ← ici
}
```

Or la clé publique du serveur s'obtient sans aucune authentification, en
envoyant `askkey` sur le socket. **N'importe qui peut donc fabriquer une trame
que le serveur déchiffrera**, tant que `IsSafe` est faux.

**2. `04_01` est atteignable juste après `01_01`.**

```go
// CheckIntegrity.go
if lastTrame == "01_01" && newTrame == "04_01" { return true }
```

Et `01_01` n'authentifie personne : `Prove_Identity` se contente de renvoyer le
contenu reçu.

**3. `04_01` désarme le contrôle d'ordre pour le reste de la session.**

```go
// trames.go
if newTrame == "04_01" { s.TrameIsSafe = true }
```

Or `UpdateConnectionTrame` commence par `if s.TrameIsSafe { return nil }` :
au-delà, plus aucune trame n'est vérifiée dans son ordre.

### Ce que ça permet encore aujourd'hui

**Écriture non authentifiée dans l'annuaire.** `handleRegisterHost` crée un
groupe et un domaine à partir de chaînes fournies dans la trame :

```go
_, err := database.GetGroupIDByName(db, groupName)
if err != nil {
    _, errCreate := database.CreateGroup(db, groupName, domain)
}
```

Séquence complète, sans le moindre identifiant :

```
1. connexion TCP au port Ducky
2. « askkey »                    → clé publique du serveur
3. 01_01, chiffrée avec cette clé → session amorcée
4. 04_01, chiffrée avec cette clé → groupe et domaine créés
```

S'y ajoutent l'enregistrement de nœuds cluster (`04_01`), les métriques proxy
(`04_05`) et les battements de cœur (`04_07`), tous inscriptibles de la même
façon.

**Conséquence indirecte sur le RBAC, la moins visible et la plus gênante.** Le
projet a corrigé en Alpha 2.0.0 le fait qu'un droit accordé sur un domaine
inexistant ou mal orthographié passait quand même ; la vérification de
l'existence réelle du domaine a été ajoutée. Mais si un attaquant peut **créer**
un domaine, il peut rendre valide un droit qui ne l'était pas : une permission
portant `write:delete:user` sur `vault.fr` — faute de frappe pour
`vaultaire.fr` — devient effective le jour où quelqu'un crée `vault.fr`.

### Ce qui a été refermé entre-temps

L'audit initial décrivait une chaîne bien plus large : lecture des GPO de
n'importe quelle machine, du sel de n'importe quel utilisateur, de ses clés
publiques. **Ce volet est fermé**, par un correctif qui ne visait pas
directement celui-ci : le `ClientSoftwareID` est désormais figé à `01_01` et
vérifié à chaque trame.

Le raisonnement tient à la façon dont les réponses sont chiffrées. Tant que
`IsSafe` est faux, `SendMessage` chiffre avec la **clé publique du client
annoncé** :

| L'attaquant annonce… | Ce qui se passe |
|----------------------|-----------------|
| l'ID d'une machine qu'il ne possède pas | il ne peut pas déchiffrer les réponses — pas de fuite |
| un ID inexistant | le chiffrement échoue, aucune réponse n'est émise |
| son propre ID légitime | il lit les réponses, mais la liaison le cantonne à **ses** données |

Autrement dit, il reste **une écriture non authentifiée, sans lecture**. La
gravité passe de « divulgation de la configuration du parc » à « pollution de
l'annuaire », ce qui reste critique mais change la nature du risque.

### Correction proposée

Ne poser `TrameIsSafe` qu'après une authentification réellement établie. Le
chemin host a besoin de la sienne — un secret de nœud, ou le même challenge que
les clients — et le raccourci `01_01 → 04_01` devrait disparaître.

En attendant, une atténuation qui coûte peu : refuser `CreateGroup` depuis
`handleRegisterHost` et exiger que le groupe existe déjà. Un hôte s'enregistre
alors dans une structure qu'un administrateur a préparée, au lieu de la
fabriquer lui-même.

---

## 12. Critique — le hachage des mots de passe

**Chemin :** `core/global/security/password.go`

```go
hash := sha256.Sum256(append(salt, []byte(password)...))
```

Une itération de SHA-256. C'est une fonction conçue pour être **rapide** : un GPU
grand public en fait de l'ordre de 10¹¹ par seconde. Un mot de passe de huit
caractères alphanumériques tombe en quelques minutes, une base entière en une
nuit. Le sel empêche les tables précalculées, il ne ralentit rien.

Pour un annuaire — dont la base *est* la cible d'une exfiltration — il faut une
fonction à coût paramétrable : **argon2id**, ou bcrypt à défaut.

`golang.org/x/crypto` est **déjà dans le `go.mod`** : `argon2.IDKey` ne coûte
aucune dépendance nouvelle.

**Migration sans rupture :** préfixer les nouveaux hachages (`$argon2id$…`),
faire reconnaître les deux formats à `ComparePasswords`, et re-hacher au premier
login réussi de chaque compte. Aucune réinitialisation de masse.

---

## 14. Élevée — les sessions non authentifiées ne sont jamais balayées

**Chemins :** `ducky-network/duckyGoroutine.go:19` et `:47`,
`ducky-network/sessionmgr/manager.go:136`

`RemoveSession` **ferme bien le socket** (`manager.go:153`). Ce n'est pas là
qu'est le problème — c'est dans ce qui l'appelle, ou plutôt ne l'appelle pas.

```go
func handleConnection(duckysession *storage.DuckySession) {
    logs.Write_LogCodeMeta(...)
    for processIncomingMessage(duckysession) { }
}   // ← sortie de boucle : aucun nettoyage
```

`closeConnection` (`:47`) existe et fait exactement ce qu'il faut. **Elle n'a
aucun appelant** — vérifié sur tout l'arbre. C'est du code mort.

Le rattrapage périodique existe, mais il ne couvre pas tout le monde :
`verifyServersOnline` parcourt `ListAuthenticated()`, qui filtre sur
`Status == SessionAuthenticated` (`manager.go:141`).

| Type de session | Balayée ? |
|-----------------|-----------|
| Authentifiée | Oui, par le ticker, après `IsSessionExpired` |
| **En attente (`SessionPending`)** | **Jamais** |

Or une session est enregistrée en `SessionPending` **dès l'`accept()`**, avant
la moindre trame. Ce sont donc précisément les connexions qu'un attaquant
obtient gratuitement — sans identifiant — qui ne sont jamais nettoyées.

S'y ajoute l'absence totale de `SetReadDeadline` dans le projet (seuls les
`http.Server` ont des délais) : une connexion ouverte qui n'envoie rien bloque
une goroutine sur `conn.Read` indéfiniment. Et aucun plafond de connexions
simultanées.

Quelques milliers de connexions TCP muettes épuisent les descripteurs du
processus — donc LDAP, DNS, web et API avec lui.

**Correctif :** un `defer closeConnection(duckysession)` dans `handleConnection`,
un délai de lecture glissant, et un plafond par IP.

---

## 15. Élevée — aucun `recover()` dans le serveur

LDAP, DNS, web, API, Ducky et le socket local sont des goroutines d'**un seul
processus**. En Go, une panique non rattrapée dans n'importe laquelle termine le
processus entier : une trame malformée ferait tomber l'annuaire complet, pas
seulement le composant fautif.

**Ce n'est pas une faille identifiée aujourd'hui.** Les indexations sur données
réseau sont correctement gardées — `getSoftwareServeurInformation`,
`gpo_manager/handlers.go`, `ssh_client.go` vérifient tous la longueur avant
d'accéder. Le constat porte sur l'absence de filet pour le code qui sera écrit
ensuite.

**Correctif :** un `defer` avec `recover()` par goroutine de connexion, qui
journalise en `CRITICAL` et ferme la seule connexion concernée.

---

## 17. Moyenne — le serveur DNS est strictement séquentiel

**Chemin :** `core/dns/DNS_startServeur.go`

Une boucle, un tampon de 512 octets partagé, chaque requête traitée jusqu'au bout
avant la suivante. Une lecture lente en base bloque **toute** la résolution — et
sur un annuaire, le DNS est sur le chemin critique de la jonction de domaine.

S'y ajoutent l'absence d'EDNS0 (tampon figé à 512 octets), l'absence de toute
limitation de débit, et une écoute sur `0.0.0.0:53` sans condition.

---

## 7. Faible — la même requête recopiée dans dix fonctions

Analyse des requêtes identiques sur les 84 fichiers du paquet :

| Occurrences | Requête | Helper existant |
|-------------|---------|-----------------|
| **10** | `SELECT id_group FROM groups WHERE group_name = ?` | `GetGroupIDByName` (`Command_CREATE_Groups.go`) |
| **7** | `SELECT id_user FROM users WHERE username = ?` | `Get_User_ID_By_Username` (`GetUserIDByUsername.go`) |
| **4** | `SELECT id_logiciel FROM id_logiciels WHERE computeur_id = ?` | `Get_ClientID_By_ComputerID` |
| 3 | `SELECT id_permission FROM client_permission WHERE name_permission = ?` | — |
| 2 | `SELECT count(*) FROM logiciel_group WHERE ...` | — |
| 2 | `SELECT count(*) FROM users_group WHERE ...` | — |

Les trois premières ont **déjà un helper dédié**, simplement pas utilisé.

### Recensement complet (inventaire du 03/08/2026)

**194 fonctions** contiennent du SQL littéral, sur 17 paquets, pour **282
requêtes dont 252 distinctes**. La duplication porte donc sur **11 requêtes**,
soit 30 occurrences sur 282 — nettement moins que ce que la première rédaction
de ce point laissait entendre.

### Correction d'une affirmation fausse de cet audit

Il était écrit ici que « certaines copies distinguent `sql.ErrNoRows` d'une
vraie erreur, d'autres retournent la même chose dans les deux cas ». **C'est
faux** : les 194 fonctions gèrent `ErrNoRows`. L'inventaire l'a vérifié une par
une.

La divergence réelle portait sur la sanitisation, et **elle allait dans le sens
inverse de ce qui était affirmé** :

| Fonction | Sanitisait ? |
|----------|--------------|
| `GetGroupIDByName` — *le helper « officiel »* | **non** |
| `db_gpo/groupIDByName` | non |
| les 7 copies en ligne (`Command_ADD_*`, `Command_Remove_*`) | oui |

Rediriger les sept copies vers le helper aurait donc **affaibli** ces sept
appels. La conclusion « un durcissement posé sur le helper ne protège qu'un
tiers des appels » était juste, mais l'ordre des opérations qu'elle suggérait
était dangereux : il fallait durcir le helper **avant** toute redirection.

### Ce qui a été corrigé

| Correctif | Effet |
|-----------|-------|
| `GetGroupIDByName` : ajout de `SanitizeIdentifier` | le helper devient au moins aussi strict que les copies |
| `GetGroupIDByName` : messages de journal | disait `permission '%s' introuvable` pour un **groupe** (copier-coller) — un administrateur cherchait au mauvais endroit |
| `GetIdLogicielByComputeurID` **supprimée** | même requête que `Get_ClientID_By_ComputerID`, mais retour `string` au lieu d'`int`. Un seul appelant, repris. |
| `get_id_logiciel` **supprimée** | retournait `""` pour « introuvable » *et* pour « erreur de base ». Voir ci-dessous. |
| `db_gpo/groupIDByName` | délègue désormais au helper |
| `DeleteDidLogin` | n'ignore plus les erreurs de ses deux résolutions d'identifiant |

**Le défaut le plus sérieux trouvé pendant ce nettoyage** était dans
`AddLoginEntry` : `get_id_logiciel` retournait une chaîne vide en cas d'échec,
qui partait ensuite dans un `INSERT` sur `d_id_logiciel` — une clé étrangère
entière. L'insertion échouait, l'échec n'était que journalisé, et
`AddLoginEntry`, qui ne retourne rien, laissait l'appelant croire la session
enregistrée. Une connexion réussie **sans ligne `did_login`** est une session
que ni le nettoyage périodique ni le kill switch ne retrouvent.

### Ce qui reste

Après correctifs : **10 requêtes recopiées, 24 occurrences en trop.**

| Copies | Requête |
|--------|---------|
| 9 | `SELECT id_group FROM groups WHERE group_name = ?` |
| 7 | `SELECT id_user FROM users WHERE username = ?` |
| 3 | `SELECT id_logiciel FROM id_logiciels WHERE computeur_id = ?` |
| 3 | `SELECT id_permission FROM client_permission WHERE name_permission = ?` |

Ces copies-là vivent **à l'intérieur** de fonctions composées
(`Command_ADD_UserToGroup`, `Command_Remove_SoftwareFromGroup`…), souvent dans
une transaction, où la résolution d'identifiant n'est qu'une étape parmi
d'autres. Les rediriger est désormais **sans risque de régression de sécurité**
— le helper est durci — mais demande de reprendre la gestion d'erreur de chaque
fonction hôte. À traiter comme un chantier distinct.

---

## 8. Faible — doublons fonctionnels et nommage

**Doublons à départager :**

| Fonctions | Fichier |
|-----------|---------|
| `Command_STATUS_GetConnectedUser` / `…Users` | `Command_STATUS_GetAllUserLogin.go` — même requête, l'une filtrée par username |
| `Command_GET_UsersByGroup` / `Command_STATUS_GetUsersByGroup` | deux fichiers, types de retour différents pour la même question |
| `GetUsersByGroup` / `GetUsersByGroups` | `LDAP_GET_GetUsersData.go` |
| `GetGroupWithUsersByName` / `GetGroupsWithUsersByNames` | `LDAP_GET_GetGroupWithUser.go` |
| ~~`GetGroupIDByName` / `groupIDByName`~~ | **résolu** — `db_gpo` délègue au helper |
| ~~`GetIdLogicielByComputeurID` / `Get_ClientID_By_ComputerID`~~ | **résolu** — la première est supprimée |

**Les trois « utilisateurs d'un groupe » ne sont PAS des doublons.**
`Command_GET_UsersByGroup`, `Command_STATUS_GetUsersByGroup` et
`GetUsersByGroup` retournent `DisplayUsersByGroup`, `UserConnected` et
`ldapstorage.User` — trois consommateurs différents : affichage CLI, état de
connexion, LDAP. Le défaut n'est pas la redondance, c'est qu'on ne peut pas le
deviner depuis leur nom.

**Ordre des arguments incohérent :** `GetUsersByGroup(group string, db *sql.DB)`
prend la base en second, alors que toutes les autres fonctions du projet la
prennent en premier.

### Nommage, chiffré

Sur les **67 fonctions SQL de `core/database`**, huit conventions coexistent :

| Nombre | Convention |
|--------|------------|
| 25 | camelCase nu (`CreateGroup`) |
| 13 | `Command_GET_` |
| 11 | souligné mixte (`Get_User_ID_By_Username`) |
| 6 | `Command_STATUS_` |
| 4 | `Command_Remove_` (casse mixte, seul verbe non capitalisé) |
| 3 | `Command_ADD_` |
| 3 | `Command_DELETE_` |
| 2 | non exportées |

**26 fichiers sur 57 portent un nom qui ne correspond pas à leur contenu** —
`Command_ADD_ClientToGroup.go` contient `Command_ADD_SoftwareToGroup`,
`CheckSession.go` contient `CleanUpExpiredSessions` et `DeleteDidLogin`,
`protected.go` contient `IsUserInGroup`. Un fichier porte `Comment_` au lieu de
`Command_` (`db_permission/Comment_SET_UserPermissionActionContent.go`).

Aucune conséquence fonctionnelle, mais c'est ce qui explique le point 7 : on ne
trouve pas le helper existant, donc on le réécrit.

**Convention retenue si un renommage a lieu :** Go idiomatique, sans préfixe —
`database.GroupIDByName`, `database.UserIDByName`. Le paquet porte déjà le sens,
et c'est déjà ce que font `db_gpo`, `db_revocation` et `db_authpolicy`. Le
chantier n'est pas engagé : il touche ~200 sites d'appel et n'est pas
vérifiable sans compilateur.

---

## 10. Note — `web_admin_pages.go` fait 1314 lignes

Le fichier contient les handlers des utilisateurs, groupes, clients,
permissions, certificats, logs et cluster. Le seul `AdminUsersHandler` fait plus
de 250 lignes et mélange vue liste, vue détail et sept actions POST.

Ce n'est pas un défaut de sécurité, mais c'est ce qui a rendu invisibles les
points 1 et 2 : dans un fichier de cette taille, l'absence d'un filtre par
domaine ne saute pas aux yeux.

Découpage suggéré, un fichier par section — le paquet suit déjà ce modèle pour
`web_admin_gpo.go`, `web_admin_dns.go` et `web_admin_tree.go`.

---
