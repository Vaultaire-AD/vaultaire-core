package database

// LookupUserPermissionID résout un nom de permission UTILISATEUR en
// id_user_permission.
//
// Les deux familles de permissions vivent dans des tables distinctes et n'ont
// rien à voir : confondre leurs identifiants a déjà produit un défaut réel, voir
// Command_Remove_UserPermissionFromGroup.
func LookupUserPermissionID(q RowQuerier, permissionName string) (int, bool, error) {
	return lookup(q, `SELECT id_user_permission FROM user_permission WHERE name = ? LIMIT 1`, permissionName)
}
