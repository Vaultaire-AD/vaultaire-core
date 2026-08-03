# Nettoyage du paquet `core/database` — plan de travail

Liste de tâches dédiée. Les chiffres viennent d'un inventaire complet du
03/08/2026 : extraction de chaque fonction contenant du SQL littéral,
normalisation des requêtes, regroupement.

**Rien ici n'est un défaut de sécurité.** Le paquet fonctionne et il est sûr.
C'est de la lisibilité et de la dette, avec deux exceptions signalées comme
telles (§1.3 et §2.2).

---

## État actuel

| Paquet | Fichiers | Lignes | Exportées |
|--------|---------:|-------:|----------:|
| `core/database` (racine) | **52** | **3 901** | **82** |
| `db_gpo` | 6 | 1 982 | 39 |
| `db_permission` | 13 | 683 | 18 |
| `db_authpolicy` | 3 | 652 | 11 |
| `db_revocation` | 3 | 449 | 10 |
| `db-certificates` | 1 | 272 | 7 |
| `db-user` | 1 | 121 | 3 |
| **Total** | **79** | **8 060** | |

**Le clivage est chronologique.** Les sous-paquets, récents, sont sains : peu de
fichiers, gros et thématiques, une convention unique par paquet. La racine est
le passif : 52 fichiers pour 3 901 lignes, soit **75 lignes par fichier** — une
fonction par fichier, et huit conventions de nommage.

Sur l'ensemble du serveur : **191 fonctions** contiennent du SQL littéral, pour
**282 requêtes dont 252 distinctes**.

---

## 1. Fait

### 1.1 Durcissement du helper de groupe

`GetGroupIDByName` a reçu `SanitizeIdentifier`, et ses messages de journal ont
été corrigés — ils annonçaient `permission '%s' introuvable` pour un **groupe**,
séquelle d'un copier-coller. Un administrateur cherchant un groupe manquant dans
les journaux cherchait au mauvais endroit.

**L'ordre comptait.** Le helper était le SEUL à ne pas assainir son entrée ; les
sept copies en ligne le faisaient. Rediriger avant de durcir aurait affaibli ces
sept appels.

### 1.2 Doublons résolus

| Supprimé | Au profit de |
|----------|--------------|
| `GetIdLogicielByComputeurID` (retour `string`) | `Get_ClientID_By_ComputerID` (retour `int`) — même requête, même colonne |
| `get_id_logiciel` | idem |
| `db_gpo/groupIDByName` | délègue à `GetGroupIDByName` |

### 1.3 Deux défauts réels trouvés en chemin

**`AddLoginEntry` pouvait enregistrer une session fantôme.** `get_id_logiciel`
retournait `""` aussi bien pour « machine inconnue » que pour « erreur de
base ». Cette chaîne partait ensuite dans un `INSERT` sur `d_id_logiciel`, une
clé étrangère entière : l'insertion échouait, l'échec n'était que journalisé, et
`AddLoginEntry` — qui ne retourne rien — laissait l'appelant croire la session
enregistrée. **Une connexion réussie sans ligne `did_login` est une session que
ni le nettoyage périodique ni le kill switch ne retrouvent.**

**`DeleteDidLogin` ignorait ses erreurs.** `idUser, _ :=` sur les deux
résolutions : un compte supprimé par kill switch donnait un `DELETE` sur
l'identifiant 0, qui ne supprimait rien, et la fonction retournait `nil`.

### 1.4 Code mort supprimé — 8 fonctions

Six fichiers entiers, deux retraits en place.

| Fonction | Sort |
|----------|------|
| `GetGroupIDsFromDomains` | fichier supprimé |
| `GetClientOS` | fichier supprimé |
| `GetUserGroupNameWhenLogin` | fichier supprimé |
| `GetGroupInfoByID` (+ type `GroupInfo` local) | fichier supprimé |
| `FindGroupsByUserInDomainTree` (+ `isSubDomain`) | fichier supprimé |
| `FindUserDomainFromGroups` | fichier supprimé |
| `DeleteGroup` | retiré de `Command_CREATE_Groups.go` |
| `GetUsersByGroups` | retiré de `LDAP_GET_GetUsersData.go` |

Deux méritent d'être signalées.

**`GetGroupIDsFromDomains`** portait l'escalade de privilèges corrigée en Alpha
2.0.0 : elle retournait *tous* les groupes des domaines d'un utilisateur, et non
ses groupes à lui. Devenue sans appelant après la réécriture de
`GetGroupIDsForUser`, elle restait exportée, compilait, et portait un nom
parfaitement plausible pour qui cherchait « comment récupérer les groupes d'un
domaine ».

**`DeleteGroup` était morte ET cassée.** Elle visait `group_permission` et
`groupe` — deux tables qui n'existent pas. Le schéma réel porte
`group_user_permission`, `group_permission_logiciel` et `groups`. Elle aurait
échoué à la première exécution sur une erreur de table inconnue.

---

## 2. À faire — par ordre de risque croissant

### 2.1 Aligner les noms de paquets sur la convention Go

**Risque : faible.** Renommage local, appelants localisables par grep.

Trois règles coexistent entre le nom du dossier et celui du paquet :

```
db_gpo/          -> package dbgpo             souligné effacé
db-user/         -> package dbuser            tiret effacé
db-certificates/ -> package dbcertificates    tiret effacé
db_permission/   -> package db_permission     souligné conservé
db_revocation/   -> package db_revocation     souligné conservé
db_authpolicy/   -> package db_authpolicy     souligné conservé
```

La convention Go est explicite : un nom de paquet est court, en minuscules,
**sans souligné**. Les trois premiers sont corrects, les trois derniers non.

À faire : `db_permission` → `dbpermission`, `db_revocation` → `dbrevocation`,
`db_authpolicy` → `dbauthpolicy`. Les alias d'import existants
(`dbrevocation "vaultaire/core/database/db_revocation"`) absorbent une partie du
changement — le nom du **dossier** peut rester tel quel, seul le `package …` en
tête de fichier change.

> `db_authpolicy` a été créé récemment en suivant le voisin `db_revocation`
> plutôt que la convention du langage. La dette a été ajoutée en connaissance de
> cause tardive : autant la corriger avec les deux autres.

### 2.2 Rediriger les 24 requêtes recopiées restantes

**Risque : moyen.** Chaque redirection demande de reprendre la gestion d'erreur
de la fonction hôte.

| Copies | Requête | Helper |
|-------:|---------|--------|
| 9 | `SELECT id_group FROM groups WHERE group_name = ?` | `GetGroupIDByName` |
| 7 | `SELECT id_user FROM users WHERE username = ?` | `Get_User_ID_By_Username` |
| 3 | `SELECT id_logiciel FROM id_logiciels WHERE computeur_id = ?` | `Get_ClientID_By_ComputerID` |
| 3 | `SELECT id_permission FROM client_permission WHERE name_permission = ?` | — à créer |
| 2 | `SELECT count(*) FROM logiciel_group WHERE …` | — à créer |
| 2 | `SELECT count(*) FROM users_group WHERE …` | — à créer |
| 2 | `SELECT id_user_permission FROM user_permission WHERE name = ? LIMIT 1` | `db_permission/Command_GET_UserPermissionID` |
| 2 | `SELECT value FROM user_permission_action WHERE …` | — |
| 2 | `SELECT name FROM ptr_records WHERE ip = ?` | — (DNS) |

Ces copies vivent **à l'intérieur** de fonctions composées
(`Command_ADD_UserToGroup`, `Command_Remove_SoftwareFromGroup`…), souvent dans
une transaction, où la résolution d'identifiant n'est qu'une étape.

**C'est désormais sans risque de régression de sécurité** — le helper est durci
depuis §1.1. Le travail restant est de la reprise de gestion d'erreur, pas de la
substitution mécanique.

> **Attention aux transactions.** Plusieurs de ces fonctions ouvrent un `tx`
> avant la résolution. Un helper prenant `*sql.DB` lit **hors** de la
> transaction : sur une lecture d'identifiant c'est sans conséquence, mais il
> faut le savoir avant de généraliser. Si le besoin apparaît, prévoir une
> variante acceptant une interface `{ QueryRow(...) *sql.Row }` que `*sql.DB` et
> `*sql.Tx` satisfont tous les deux.

### 2.3 Renommer les fichiers dont le nom ment

**Risque : faible techniquement, gros diff.**

**26 fichiers sur 57** (avant suppressions) portaient un nom sans rapport avec
leur contenu. Exemples :

| Fichier | Contient |
|---------|----------|
| `Command_ADD_ClientToGroup.go` | `Command_ADD_SoftwareToGroup` |
| `Command_ADD_PermissionClientToGroup.go` | `Command_ADD_PermissionToSoftwareGroup` |
| `CheckSession.go` | `CleanUpExpiredSessions`, `DeleteDidLogin` |
| `Command_CREATE_Users.go` | `Create_New_User` |
| `GET_USER_MainDomain.go` | `GetDomainsForUser` |
| `protected.go` | `IsUserInGroup` |
| `Get_Software_key.go` | `Get_Client_Software_PublicKey` |

Plus un fichier mal orthographié : `db_permission/Comment_SET_UserPermissionActionContent.go`
(`Comment_` au lieu de `Command_`).

Renommer un fichier ne casse rien en Go — le paquet ne dépend pas des noms de
fichiers. C'est donc **la tâche au meilleur rapport lisibilité/risque** de cette
liste.

### 2.4 Regrouper les fichiers de la racine par sujet

**Risque : faible, très gros diff.**

75 lignes par fichier en moyenne, une fonction par fichier. Les sous-paquets
récents montrent le modèle inverse et il fonctionne : `db_gpo` fait 1 982 lignes
en 6 fichiers.

Regroupement suggéré, **sans changer de paquet** — donc sans toucher un seul
appelant :

```
users.go          création, mise à jour, suppression, lecture d'utilisateurs
groups.go         groupes et appartenances
clients.go        id_logiciels, liaisons machine ↔ groupe
sessions.go       did_login, users_logiciel, expiration
domains.go        domain_group, résolution de domaines
ldap_reads.go     les lectures dédiées au module LDAP
schema.go         CreateDataBase + amorçage
protected.go      gardes d'immuabilité (déjà en place)
```

### 2.5 Unifier le nommage des fonctions

**Risque : ÉLEVÉ sans compilateur. À ne pas engager à la légère.**

Huit conventions sur les 82 fonctions exportées de la racine :

| Nombre | Convention |
|-------:|------------|
| 25 | camelCase nu (`CreateGroup`) |
| 13 | `Command_GET_` |
| 11 | souligné mixte (`Get_User_ID_By_Username`) |
| 6 | `Command_STATUS_` |
| 4 | `Command_Remove_` (seul verbe non capitalisé) |
| 3 | `Command_ADD_` |
| 3 | `Command_DELETE_` |
| 2 | non exportées |

**Convention retenue : Go idiomatique, sans préfixe.** `database.GroupIDByName`,
`database.UserIDByName`. Le paquet porte déjà le sens, et c'est déjà ce que font
`db_gpo`, `db_revocation` et `db_authpolicy` — donc la moitié récente du code.

Chantier estimé à **~200 sites d'appel**. À faire d'un bloc, avec `gopls rename`
ou l'équivalent, jamais à la main, et en compilant.

---

## 3. Points de vigilance à ne pas perdre

**Les trois « utilisateurs d'un groupe » ne sont PAS des doublons.**
`Command_GET_UsersByGroup`, `Command_STATUS_GetUsersByGroup` et `GetUsersByGroup`
retournent `DisplayUsersByGroup`, `UserConnected` et `ldapstorage.User` — trois
consommateurs : affichage CLI, état de connexion, LDAP. Le défaut est qu'on ne
peut pas le deviner depuis leur nom, pas qu'elles font double emploi. **Ne pas
les fusionner.**

**Ordre des arguments incohérent.** `GetUsersByGroup(group string, db *sql.DB)`
prend la base en second, contrairement à toutes les autres fonctions du projet.
À corriger avec §2.5.

**`sql.ErrNoRows` est géré partout.** Vérifié fonction par fonction sur les 191.
Une version antérieure de `Audit_Serveur.md` affirmait le contraire ; c'était
faux et c'est corrigé.

**Ne pas supprimer une fonction sur la seule foi d'un grep.** `DeleteGroup`,
`GetClientOS` et `GetGroupInfoByID` semblaient référencées : c'étaient leurs
propres messages de journal qui citaient leur nom.

---

## Voir aussi

- [`Audit_Serveur.md`](./Audit_Serveur.md) §7 et §8 — le constat d'origine
- [`DataBase_Struct.md`](./DataBase_Struct.md) — le schéma
