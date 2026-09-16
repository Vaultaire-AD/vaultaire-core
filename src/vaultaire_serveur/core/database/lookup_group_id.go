package database

// LookupGroupID résout un nom de groupe en id_group.
func LookupGroupID(q RowQuerier, groupName string) (int, bool, error) {
	return lookup(q, `SELECT id_group FROM groups WHERE group_name = ?`, groupName)
}
