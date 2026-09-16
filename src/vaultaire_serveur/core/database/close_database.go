package database

func CloseDatabase() bool {
	if DB != nil {
		_ = DB.Close()
	}
	return true
}
