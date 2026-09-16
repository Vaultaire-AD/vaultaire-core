package database

import (
	"database/sql"
	"time"
	"vaultaire/core/logs"
	"vaultaire/core/storage"
)

func InitDatabase() bool {
	var err error
	for {
		DB, err = sql.Open("mysql", storage.Database_username+":"+storage.Database_password+
			"@tcp("+storage.Database_iPDatabase+":"+storage.Database_portDatabase+")/"+
			storage.Database_databaseName+"?parseTime=true")
		if err != nil {
			logs.Write_LogCode("ERROR", logs.CodeDBConnection, "database: connection open failed: "+err.Error())
		} else {
			err = DB.Ping()
			if err == nil {
				logs.Write_Log("INFO", "database: connected successfully")
				break
			}
			logs.Write_LogCode("ERROR", logs.CodeDBConnection, "database: ping failed: "+err.Error())
		}

		logs.Write_Log("INFO", "database: retrying connection in 5 seconds")
		time.Sleep(5 * time.Second)
	}

	return true
}
