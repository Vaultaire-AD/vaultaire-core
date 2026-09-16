package database

// LookupUserID résout un nom d'utilisateur en id_user.
func LookupUserID(q RowQuerier, username string) (int, bool, error) {
	return lookup(q, `SELECT id_user FROM users WHERE username = ?`, username)
}
