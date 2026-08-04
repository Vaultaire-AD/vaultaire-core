# Nettoyage du paquet `core/database` — plan de travail

Liste de tâches dédiée. Les chiffres viennent d'un inventaire complet du
03/08/2026 : extraction de chaque fonction contenant du SQL littéral,
normalisation des requêtes, regroupement.

**Le plan de départ annonçait « rien ici n'est un défaut de sécurité ».**
C'était vrai des symptômes listés, pas de ce qu'ils cachaient : la redirection
des requêtes recopiées (§2.2) a mis au jour une fonction qui n'avait jamais
fonctionné, et son effet est une rétention de privilèges. Voir §1.5.

---

## État actuel

*Mesuré le 04/08/2026, après les §2.1 à §2.4 puis le découpage en sous-paquets.*

| Paquet | Dossier | Fichiers | Lignes | Moyenne |
|--------|---------|---------:|-------:|--------:|
| `database` — socle | `core/database` | 36 | 613 | 17 |
| `dbusers` | `db_users` | 18 | 769 | 42 |
| `dbgroups` | `db_groups` | 13 | 580 | 44 |
| `dbclients` | `db_clients` | 13 | 589 | 45 |
| `dbsessions` | `db_sessions` | 11 | 661 | 60 |
| `dbdomains` | `db_domains` | 8 | 217 | 27 |
| `dbldap` | `db_ldap` | 7 | 263 | 37 |
| `dbschema` | `db_schema` | 5 | 484 | 96 |
| `dbpermission` | `db_permission` | 26 | 1 012 | 38 |
| `dbgpo` | `db_gpo` | 79 | 2 389 | 30 |
| `dbauthpolicy` | `db_authpolicy` | 25 | 758 | 30 |
| `dbrevocation` | `db_revocation` | 15 | 522 | 34 |
| `dbcertificates` | `db_certificates` | 10 | 333 | 33 |
| **Total** | | **266** | **9 190** | **34** |

Pour mémoire, l'état au 03/08/2026 : **79 fichiers, 8 060 lignes**, dont une
racine à 52 fichiers pour 3 901 lignes.

L'écart de lignes (8 060 → 9 190) est presque entièrement de l'en-tête : une
clause `package` et un bloc d'import par fichier, plus les `doc.go`. Le code
lui-même n'a pas grossi.

`dbschema` reste à 96 lignes par fichier : `Create_DataBase` est une liste
d'instructions DDL, pas de la logique. La découper serait un rangement pour
l'œil qui séparerait des choses qui se lisent ensemble.

Sur l'ensemble du serveur : 48 fichiers contiennent encore du SQL littéral.

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

### 1.5 Un défaut réel de plus, trouvé en redirigeant les requêtes

`Command_Remove_UserPermissionFromGroup` **n'a jamais fonctionné**, sur deux
fautes indépendantes, dans la même fonction.

1. Elle résolvait le nom de la permission dans `client_permission`, la table des
   permissions **client**, alors qu'elle retire une permission **utilisateur**.
   Les deux familles sont numérotées séparément : l'identifiant obtenu ne
   désignait pas la permission demandée, quand il existait.
2. Elle interrogeait puis supprimait dans `group_permission_user` — **table qui
   n'existe pas**. Le schéma déclare `group_user_permission`, colonne
   `d_id_user_permission`. MySQL rendait « table inconnue » dès le `COUNT`, et la
   fonction retournait « erreur lors de la vérification de la permission du
   groupe ».

**Les deux chemins offerts à l'administrateur étaient concernés** :
`vlt remove -g <groupe> -pu <permission>` et le bouton de la page groupe. En web
l'appelant ne teste que `== nil`, donc le clic ne produisait **aucun message** :
la permission restait affichée, sans explication.

**Pourquoi ce n'est pas qu'une gêne.** Un droit accordé à un groupe ne pouvait
plus lui être repris. Le seul contournement était de supprimer la permission
entière — donc de la retirer à *tous* les groupes, y compris ceux qui devaient la
garder. Une réduction de privilèges était impossible sans en casser d'autres.

Même famille que `DeleteGroup` (§1.4) : du code visant des tables inexistantes,
donc jamais exécuté sur une vraie base. Deux occurrences en un mois sur le même
paquet suggèrent que le schéma a été renommé sans que ces appels suivent.
Corrigé, avec un journal de succès qui manquait aussi.

### 1.6 §2.1 — Noms de paquets alignés sur la convention Go

`db_permission` → `dbpermission`, `db_revocation` → `dbrevocation`,
`db_authpolicy` → `dbauthpolicy`. Seule la clause `package` change ; les
dossiers gardent leur nom, comme prévu.

Deux alias divergents ont été unifiés au passage : `dbperm` et
`db_permission` coexistaient pour le même paquet (12 imports au total), tout
comme `dbcert` et `dbcertificates`. Un paquet, un nom.

L'alias d'import est désormais **toujours explicite** quand le nom du dossier
diffère du nom du paquet — c'est déjà ce que faisait `dbgpo`. Sans lui, la ligne
d'import ne dit pas sous quel nom le paquet sera appelé plus bas.

34 fichiers touchés, 99 lignes.

### 1.7 §2.3 et §2.4 — Regroupement par sujet

> **Étape intermédiaire, remplacée depuis par le §1.9.** Les gros fichiers
> thématiques décrits ici n'existent plus : ils ont été redécoupés en une
> déclaration par fichier, dans des sous-paquets. La section est conservée parce
> qu'elle explique le raisonnement qui a mené là, et parce que le regroupement par
> sujet reste la structure — ce sont les dossiers qui portent désormais les sujets
> au lieu des fichiers.

Les deux tâches se recouvraient : regrouper les fichiers de la racine dissout la
question de leurs noms, puisqu'ils disparaissent. Le §2.4 a donc été fait
d'abord, et le §2.3 ne s'est appliqué qu'aux sous-paquets.

**Racine : 52 fichiers → 12.**

```
users.go          création, mise à jour, suppression, lecture d'utilisateurs
groups.go         groupes, appartenances, IsUserInGroup
clients.go        id_logiciels, liaisons machine ↔ groupe
sessions.go       did_login, users_logiciel, expiration
domains.go        domain_group, résolution de domaines
permissions.go    permissions client, liaisons groupe ↔ permission
ldap_reads.go     les lectures dédiées au module LDAP
schema.go         Create_DataBase, amorçage, actions superadmin
resolve.go        résolution d'identifiants (§1.8)
sanitize.go       SanitizeInput / SanitizeIdentifier
db.go             ouverture, accès et fermeture de la connexion
protected.go      gardes d'immuabilité
```

`IsUserInGroup` quitte `protected.go` pour `groups.go` : c'est une lecture
d'appartenance ordinaire, pas une garde. `IsSuperadmin`, qui l'appelle, reste
dans `protected.go` parce qu'elle, porte sur le groupe protégé.

**`db_permission` : 13 fichiers → 4** (`user_permissions.go`,
`client_permissions.go`, `actions.go`, `links.go`). Le paquet souffrait de la
même pathologie que la racine — 52 lignes par fichier, une fonction par fichier.
Deux fichiers mêlaient permissions utilisateur et client et ont été scindés
avant regroupement. Le fichier mal orthographié
`Comment_SET_UserPermissionActionContent.go` disparaît avec l'opération.

`db-user/DB_Users_Key.go` → `keys.go`, `db-certificates/DB_Certificates.go` →
`certificates.go` : le préfixe `DB_` répétait le nom du dossier.

**Total du paquet : 79 fichiers → 30.**

> **Comment on sait que rien n'a bougé.** Le regroupement a été fait par splicing
> textuel : le corps de chaque fichier est repris verbatim après son bloc
> d'import, seuls les imports sont recalculés. Les commentaires de documentation
> sont donc intacts. À chaque étape, une empreinte de la surface du paquet
> (paquet, nom, signature complète de chaque fonction, type et variable de niveau
> supérieur — 331 entrées) a été comparée à l'état d'origine : **identique**.

### 1.8 §2.2 — Requêtes recopiées redirigées

Nouveau fichier `core/database/resolve.go`. Toutes les copies listées dans le
plan ont disparu, sauf `ptr_records` qui vit dans `core/dns`, hors du paquet.

```go
type RowQuerier interface { QueryRow(query string, args ...any) *sql.Row }

func LookupGroupID(q RowQuerier, groupName string)            (int, bool, error)
func LookupUserID(q RowQuerier, username string)              (int, bool, error)
func LookupClientID(q RowQuerier, computerID string)          (int, bool, error)
func LookupClientPermissionID(q RowQuerier, name string)      (int, bool, error)
func LookupUserPermissionID(q RowQuerier, name string)        (int, bool, error)
```

Plus deux helpers non exportés pour les liaisons : `userGroupLinkExists` et
`clientGroupLinkExists`, qui absorbent les `COUNT(*)` recopiés.

**Pourquoi PAS `GetGroupIDByName` et `Get_User_ID_By_Username`**, que le plan
désignait comme cibles. Ces fonctions produisent leur propre message quand
l'entité est absente. Y rediriger les appelants aurait remplacé « groupe avec le
nom X introuvable » par un message générique — et ces textes remontent jusqu'à
l'administrateur, en CLI comme en web. Les résolveurs rendent donc
`found bool` et **ne décident pas** : l'appelant formule l'absence comme il
l'entend, et tous les messages existants sont conservés au caractère près.
`GetGroupIDByName`, `Get_User_ID_By_Username` et `Get_ClientID_By_ComputerID`
délèguent désormais aux résolveurs et gardent leur signature.

**`RowQuerier` répond à l'avertissement du plan sur les transactions.**
`*sql.DB` et `*sql.Tx` satisfont tous deux cette interface : la question de lire
hors de la transaction de l'appelant ne se pose plus, y compris le jour où une
résolution suivra une écriture dans la même transaction.

**L'assainissement est fait dans le résolveur**, pas seulement chez l'appelant.
Même raisonnement qu'au §1.1 : posé au plus près de la base, il couvre les
appelants qui seront écrits plus tard. Deux fonctions y gagnent une vérification
qu'elles n'avaient pas, `Command_GET_UserPermissionID` et
`EnsureSuperadminActions`.

> Effet de bord à connaître : `callerName()` remonte deux niveaux de pile. Quand
> un identifiant malformé est refusé *dans* un résolveur, le journal nomme
> `database.lookup` et non le vrai appelant. Sans conséquence tant que tous les
> appelants assainissent déjà en entrée — ce qui est le cas aujourd'hui.

### 1.9 Découpage en sous-paquets, une déclaration par fichier

Le §2.4 avait regroupé la racine en 12 fichiers thématiques. À la relecture, des
fichiers de 500 lignes se sont révélés aussi peu praticables que 52 fichiers
d'une fonction : on remplace « où est cette fonction ? » par « où est-elle dans
ce fichier ? ».

**Règle retenue : une déclaration par fichier, le nom du fichier dérivé du nom de
la déclaration.** La dérivation est mécanique — CamelCase vers minuscules
soulignées, préfixe `Command_` retiré — donc un nom de fichier ne PEUT plus
mentir sur son contenu. C'était le défaut principal de l'organisation d'origine,
où 26 fichiers sur 57 portaient un nom sans rapport avec ce qu'ils déclaraient.

**En Go, un dossier est un paquet.** Créer des dossiers signifiait donc créer de
vrais sous-paquets, et changer tous les appels : `database.Command_ADD_UserToGroup`
devient `dbgroups.Command_ADD_UserToGroup`. 637 références qualifiées dans 155
fichiers. C'est le choix qui a été fait, et il est cohérent avec ce que le projet
faisait déjà — `db_gpo`, `db_permission`, `db_revocation` étaient déjà des
sous-paquets.

#### Ce qui reste dans le socle, et pourquoi

`core/database` ne contient plus une seule requête métier. Il porte la connexion,
le filtrage des entrées, les résolveurs d'identifiants et les gardes
d'immuabilité — c'est-à-dire ce dont tous les sous-paquets ont besoin.

**Le socle n'importe aucun sous-paquet.** C'est l'invariant qui garantit
l'absence de cycle, et il a coûté une exception : `IsUserInGroup` vit dans le
socle alors que c'est une lecture d'appartenance, parce que `IsSuperadmin` en a
besoin et que `dbgroups` importe déjà les gardes. La déplacer aurait obligé à
dupliquer la requête dans le socle — exactement ce que le §2.2 venait de
supprimer.

Ordre entre sous-paquets :

```
socle <- dbgroups <- dbdomains <- dbusers <- { dbsessions, dbschema }
socle <- dbclients <- dbsessions
socle <- { dbldap, dbpermission, dbgpo, dbauthpolicy, dbrevocation, dbcertificates }
```

#### Regroupements au passage

- `permissions.go` (permissions client, liaisons groupe ↔ permission) rejoint
  `dbpermission`, qui portait déjà les permissions utilisateur. Deux paquets pour
  le même sujet n'avaient pas de sens.
- `db-user` disparaît dans `dbusers` : une clé publique SSH est un attribut de
  compte, et la séparer obligeait à connaître deux paquets pour répondre à « que
  sait-on de cet utilisateur ».
- `db-certificates` devient `db_certificates` : deux conventions de nom de
  dossier coexistaient.

#### Ce que le découpage a failli coûter

Un découpage par déclaration **perd les commentaires d'en-tête de fichier**, ceux
qui précèdent la première déclaration sans lui être attachés. Ce sont justement
ceux qui portent le raisonnement d'ensemble : pourquoi `dbauthpolicy` mêle TOTP
et expiration, pourquoi les restrictions GPO vérifient l'appartenance dans la
couche base, pourquoi un ordre de révocation est durable.

Vérification faite par comptage : 1 173 lignes de commentaire avant, et le
même contenu retrouvé après. Les en-têtes ont été restaurés en `doc.go` par
paquet, ce qui est leur place correcte en Go — ils deviennent la documentation
du paquet. Les mentions de fonctions retirées (`DeleteGroup`, `GetUsersByGroups`,
`get_id_logiciel`) y ont été rapatriées aussi : c'est là qu'on les cherchera.

#### Ce que la vérification a rattrapé

Le contrôle de cohérence usage/import a trouvé une erreur que la réécriture avait
introduite : dans `scope/legacy.go`, dont **tout le contenu est commenté**, un
import avait été ajouté sur la foi d'une occurrence située dans un commentaire.
Le paquet `scope` n'aurait pas compilé. Aucun autre cas.

Vérifié aussi : aucun symbole de la racine ne porte le même nom qu'un symbole
d'un sous-paquet, donc aucune réécriture n'a pu être routée vers le mauvais
paquet. Le seul homonyme entre sous-paquets est `CreateTables`, qui n'a jamais
existé à la racine.

> **Portée de la preuve.** `core/database/...` est compilé et passé au `vet` :
> les 12 sous-paquets sont prouvés. Les 155 fichiers appelants ne le sont pas —
> ils dépendent de bibliothèques externes indisponibles hors ligne. Ils sont
> vérifiés au parseur (547 fichiers, 0 échec) et par un contrôle statique
> qui confirme que les 637 références qualifiées désignent un symbole
> réellement exporté par le paquet importé. **Recompiler avant de pousser.**

---

## 2. À faire

### 2.1 Unifier le nommage des fonctions

**Risque : ÉLEVÉ sans compilateur. À ne pas engager à la légère.**

Huit conventions sur les fonctions exportées de la racine (comptage d'origine,
sur 82 ; les 5 `Lookup*` ajoutées depuis suivent déjà la convention retenue) :

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
À corriger avec §2.1.

**Déréférencement nul latent dans `DidUserCanLogin`.** La branche
`} else if err != sql.ErrNoRows {` appelle `err.Error()`. Quand la lecture
réussit sans ligne correspondante, `err` vaut `nil`, `nil != sql.ErrNoRows` est
vrai, et l'appel panique. Le cas est aujourd'hui **inatteignable** — la requête
sélectionne le littéral `1`, donc `err == nil` implique `canLogin == true` et la
branche précédente sort. La sûreté ne tient qu'à la forme de la requête : la
première réécriture qui sélectionnerait une colonne réelle ouvrirait le trou.
Repéré pendant le §2.2, laissé en l'état parce que le corriger change une
logique de connexion et sort du périmètre d'un nettoyage.

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
