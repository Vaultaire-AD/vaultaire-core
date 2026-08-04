// Package database est le SOCLE de la couche base de données.
//
// Il ne contient aucune requête métier. Ce qui vit ici est ce dont tous les
// sous-paquets ont besoin et qui ne peut donc dépendre d'aucun d'eux :
//
//	db.go, init_database.go...   ouverture, accès et fermeture de la connexion
//	sanitize_*.go                filtrage des entrées
//	lookup_*.go, row_querier.go  résolution d'identifiants
//	guard_protected_*.go         gardes d'immuabilité
//
// Le métier est réparti par sujet dans les sous-paquets : dbusers, dbgroups,
// dbclients, dbsessions, dbdomains, dbldap, dbschema, dbpermission, dbgpo,
// dbauthpolicy, dbrevocation, dbcertificates.
//
// # La règle de dépendance
//
// Le socle n'importe AUCUN sous-paquet. C'est ce qui garantit l'absence de
// cycle, et c'est la raison pour laquelle IsUserInGroup vit ici alors que c'est
// une lecture d'appartenance : IsSuperadmin en a besoin, et dbgroups importe
// déjà les gardes.
//
// Entre sous-paquets, l'ordre est : dbgroups <- dbdomains <- dbusers <-
// {dbsessions, dbschema}, et dbclients <- dbsessions. Tout le reste ne dépend
// que du socle.
//
// # Immuabilité de l'identité d'amorçage
//
// Le compte `vaultaire`, le groupe `vaultaire` et la permission `vaultaire_all`
// sont créés par Create_DataBase et forment le seul chemin d'accès garanti à
// l'annuaire. Les supprimer, les renommer ou les délier revient à se verrouiller
// définitivement dehors : plus personne ne peut administrer le domaine, et
// aucune commande ne permet de reconstruire l'ensemble depuis l'extérieur.
//
// Les refus sont posés dans la couche base et non dans les commandes, pour que
// tous les appelants (CLI, interface web, LDAP, API) soient couverts par
// construction — y compris ceux qui seront écrits plus tard.
//
// # Deux niveaux de filtrage
//
// Les confondre serait une erreur dans les deux sens.
//
// SanitizeInput est une liste NOIRE, appliquée à du texte libre : mots de passe,
// modèle de processeur (« Intel(R) Core(TM) i7 »), motifs d'expression
// régulière des restrictions GPO (« ^[a-z0-9._-]+\.service$ »), préfixes de
// chemin. Y interdire les espaces, parenthèses ou crochets casserait ces
// usages légitimes.
//
// SanitizeIdentifier est une liste BLANCHE, appliquée à ce qui nomme une entité :
// utilisateur, groupe, permission, identifiant de machine. Ces valeurs finissent
// dans des clauses WHERE, des DN LDAP, des chemins de fichiers et des noms de
// groupes POSIX. Rien qui ressemble à un espace, une parenthèse, un crochet ou
// un chevron n'y a sa place, et une liste blanche est la seule forme de
// filtrage qui n'oublie rien : ce qui n'est pas explicitement autorisé est
// refusé, y compris les caractères auxquels personne n'a encore pensé.
//
// # Résolution d'identifiants : nom d'entité -> clé primaire
//
// Ces requêtes étaient recopiées dans une vingtaine de fonctions composées
// (Command_ADD_UserToGroup, Command_Remove_SoftwareFromGroup...), où la
// résolution n'est qu'une étape parmi d'autres. Les copies ne se comportaient
// pas toutes pareil : certaines assainissaient leur entrée, d'autres non.
//
// POURQUOI PAS LES FONCTIONS EXPORTÉES EXISTANTES. GetGroupIDByName et
// Get_User_ID_By_Username produisent leur propre message d'erreur quand
// l'entité est absente. Y rediriger les appelants aurait remplacé « groupe avec
// le nom X introuvable » par un message générique, alors que ces textes
// remontent jusqu'à l'administrateur en CLI et en web. Les résolveurs Lookup*
// ne décident donc PAS : ils rendent found == false et laissent l'appelant
// formuler l'absence comme il l'entend.
//
// # Une déclaration par fichier
//
// Le nom du fichier est dérivé du nom de la déclaration qu'il contient, en
// minuscules séparées par des soulignés. La règle est mécanique, donc un nom de
// fichier ne peut plus mentir sur son contenu — c'était le défaut principal de
// l'ancienne organisation, où 26 fichiers sur 57 portaient un nom sans rapport
// avec ce qu'ils déclaraient.
package database
