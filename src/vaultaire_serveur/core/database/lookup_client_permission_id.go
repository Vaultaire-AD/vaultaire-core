package database

// LookupClientPermissionID résout un nom de permission CLIENT en id_permission.
func LookupClientPermissionID(q RowQuerier, permissionName string) (int, bool, error) {
	return lookup(q, `SELECT id_permission FROM client_permission WHERE name_permission = ?`, permissionName)
}
