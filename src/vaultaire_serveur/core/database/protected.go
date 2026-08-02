package database

import (
	"database/sql"
	"fmt"
	"strings"

	"vaultaire/core/logs"
)

// Immuabilité de l'identité d'amorçage.
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

const (
	// ProtectedUsername est le compte d'amorçage, non supprimable et non renommable.
	ProtectedUsername = "vaultaire"
	// ProtectedGroupName est le groupe superadmin, non supprimable et non renommable.
	ProtectedGroupName = "vaultaire"
	// ProtectedUserPermission est la permission complète attachée au groupe superadmin.
	ProtectedUserPermission = "vaultaire_all"
	// ProtectedClientPermission est la permission client d'administration.
	ProtectedClientPermission = "vaultaire_admin"
)

// IsProtectedUser indique si un nom d'utilisateur est celui du compte d'amorçage.
// La comparaison est insensible à la casse : « Vaultaire » ne doit pas passer.
func IsProtectedUser(username string) bool {
	return strings.EqualFold(strings.TrimSpace(username), ProtectedUsername)
}

// IsProtectedGroup indique si un nom de groupe est celui du groupe superadmin.
func IsProtectedGroup(groupName string) bool {
	return strings.EqualFold(strings.TrimSpace(groupName), ProtectedGroupName)
}

// IsProtectedUserPermission indique si une permission utilisateur est protégée.
func IsProtectedUserPermission(name string) bool {
	return strings.EqualFold(strings.TrimSpace(name), ProtectedUserPermission)
}

// IsProtectedClientPermission indique si une permission client est protégée.
func IsProtectedClientPermission(name string) bool {
	return strings.EqualFold(strings.TrimSpace(name), ProtectedClientPermission)
}

// refuseProtected journalise la tentative et retourne l'erreur à remonter.
//
// Le niveau SECURITY est volontaire : une tentative de suppression du compte
// d'amorçage est soit une erreur de manipulation qu'il faut pouvoir retracer,
// soit une tentative de verrouiller l'administrateur légitime dehors.
func refuseProtected(kind, name, operation string) error {
	logs.Write_Log("SECURITY", fmt.Sprintf(
		"protection: tentative de %s sur le %s protégé %q — refusée", operation, kind, name))
	return fmt.Errorf("le %s %q est protégé : %s est impossible", kind, name, operation)
}

// GuardProtectedUserDeletion refuse la suppression du compte d'amorçage.
func GuardProtectedUserDeletion(username string) error {
	if IsProtectedUser(username) {
		return refuseProtected("compte", username, "la suppression")
	}
	return nil
}

// GuardProtectedUserRename refuse le renommage du compte d'amorçage.
//
// Le changement de mot de passe reste autorisé, et c'est délibéré : le compte
// est créé avec un mot de passe par défaut connu, interdire sa rotation ferait
// plus de mal que de bien. Seule l'identité (username) est figée, parce que
// c'est elle qui est câblée dans l'authentification serveur et le bind LDAP.
func GuardProtectedUserRename(currentUsername, newUsername string) error {
	if !IsProtectedUser(currentUsername) {
		return nil
	}
	if strings.TrimSpace(newUsername) == "" || IsProtectedUser(newUsername) {
		return nil
	}
	return refuseProtected("compte", currentUsername, "le renommage")
}

// GuardProtectedPermissionContent refuse toute écriture sur le contenu de la
// permission d'amorçage.
//
// Les autres gardes couvraient la suppression, le renommage et le déliage. Il
// restait un chemin plus discret pour arriver au même résultat : vider la
// permission de l'intérieur. `update -pu vaultaire_all web_admin nil` ne
// supprime rien, ne renomme rien, ne délie rien — et verrouille pourtant tout
// le monde hors de l'interface d'administration. La même opération sur les clés
// RBAC neutralise le compte d'amorçage action par action.
//
// C'est exactement ce que l'en-tête de ce fichier dit vouloir empêcher : se
// retrouver sans aucun chemin d'accès garanti à l'annuaire. La garde est donc
// posée ici, dans la couche base, pour couvrir le CLI, l'interface web et tout
// appelant futur d'un seul coup.
//
// Conséquence assumée : `vaultaire_all` n'est plus modifiable du tout. C'est
// voulu — cette permission n'a qu'un état correct, « tout autorisé ». Une
// délégation se construit en créant d'autres permissions, pas en rognant
// celle-ci.
func GuardProtectedPermissionContent(permissionName, action string) error {
	if IsProtectedUserPermission(permissionName) {
		return refuseProtected("permission", permissionName,
			"la modification de l'action "+action)
	}
	return nil
}

// GuardProtectedGroupDeletion refuse la suppression du groupe superadmin.
func GuardProtectedGroupDeletion(groupName string) error {
	if IsProtectedGroup(groupName) {
		return refuseProtected("groupe", groupName, "la suppression")
	}
	return nil
}

// GuardProtectedGroupRename refuse le renommage du groupe superadmin.
func GuardProtectedGroupRename(currentName, newName string) error {
	if !IsProtectedGroup(currentName) {
		return nil
	}
	if strings.TrimSpace(newName) == "" || IsProtectedGroup(newName) {
		return nil
	}
	return refuseProtected("groupe", currentName, "le renommage")
}

// GuardProtectedMembership refuse de retirer le compte d'amorçage du groupe
// superadmin. Le retirer ne supprime rien mais lui ôte toutes ses permissions :
// l'effet pratique est identique à une suppression du compte.
func GuardProtectedMembership(username, groupName string) error {
	if IsProtectedUser(username) && IsProtectedGroup(groupName) {
		return refuseProtected("couple compte/groupe", username+"/"+groupName, "le retrait d'appartenance")
	}
	return nil
}

// GuardProtectedUserPermissionUnlink refuse de détacher la permission complète
// du groupe superadmin — dernier maillon de la chaîne d'accès administrateur.
func GuardProtectedUserPermissionUnlink(groupName, permissionName string) error {
	if IsProtectedGroup(groupName) && IsProtectedUserPermission(permissionName) {
		return refuseProtected("permission du groupe superadmin",
			groupName+"/"+permissionName, "le détachement")
	}
	return nil
}

// GuardProtectedUserPermissionDeletion refuse la suppression de la permission
// complète du groupe superadmin.
func GuardProtectedUserPermissionDeletion(permissionName string) error {
	if IsProtectedUserPermission(permissionName) {
		return refuseProtected("permission", permissionName, "la suppression")
	}
	return nil
}

// GuardProtectedClientPermissionDeletion refuse la suppression de la permission
// client d'administration.
func GuardProtectedClientPermissionDeletion(permissionName string) error {
	if IsProtectedClientPermission(permissionName) {
		return refuseProtected("permission client", permissionName, "la suppression")
	}
	return nil
}

// IsUserInGroup indique si un utilisateur appartient à un groupe donné.
//
// Utilisé notamment pour la porte d'entrée superadmin des restrictions GPO :
// l'appartenance est relue en base à chaque vérification, jamais mise en cache,
// pour qu'un retrait du groupe prenne effet immédiatement.
func IsUserInGroup(db *sql.DB, username, groupName string) (bool, error) {
	if err := SanitizeIdentifier(username, groupName); err != nil {
		return false, err
	}
	if db == nil {
		return false, fmt.Errorf("connexion base indisponible")
	}
	var count int
	err := db.QueryRow(
		`SELECT COUNT(*) FROM users u
		 INNER JOIN users_group ug ON ug.d_id_user = u.id_user
		 INNER JOIN groups g ON g.id_group = ug.d_id_group
		 WHERE u.username = ? AND g.group_name = ?`,
		username, groupName,
	).Scan(&count)
	if err != nil {
		logs.Write_Log("ERROR", fmt.Sprintf(
			"protection: vérification d'appartenance %s/%s échouée : %v", username, groupName, err))
		return false, err
	}
	return count > 0, nil
}

// IsSuperadmin indique si l'utilisateur est membre du groupe superadmin.
func IsSuperadmin(db *sql.DB, username string) bool {
	member, err := IsUserInGroup(db, username, ProtectedGroupName)
	if err != nil {
		// En cas d'erreur de lecture on refuse : une panne de base ne doit pas
		// ouvrir l'accès aux réglages les plus sensibles du produit.
		return false
	}
	return member
}
