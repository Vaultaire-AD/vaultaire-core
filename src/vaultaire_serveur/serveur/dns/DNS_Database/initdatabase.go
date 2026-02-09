package dnsdatabase

import (
	"vaultaire/serveur/logs"
	"vaultaire/serveur/storage"
	"database/sql"
	"fmt"
	"log"
	"time"

	_ "github.com/go-sql-driver/mysql"
)

var db *sql.DB

func InitDatabase() bool {
	var err error
	dsnNoDB := fmt.Sprintf("%s:%s@tcp(%s:%s)/",
		storage.Database_username,
		storage.Database_password,
		storage.Database_iPDatabase,
		storage.Database_portDatabase,
	)

	// Connexion sans base pour pouvoir la créer
	var tempDB *sql.DB
	for {
		tempDB, err = sql.Open("mysql", dsnNoDB)
		if err != nil {
			logs.Write_LogCode("ERROR", logs.CodeDBConnection, "dnsdb: MySQL connection open failed (no DB): "+err.Error())
		} else {
			err = tempDB.Ping()
			if err == nil {
				break
			}
			logs.Write_LogCode("ERROR", logs.CodeDBConnection, "dnsdb: MySQL ping failed (no DB): "+err.Error())
		}
		logs.Write_Log("INFO", "dnsdb: retrying connection in 30 seconds")
		time.Sleep(30 * time.Second)
	}

	// Création de la base si elle n'existe pas
	createQuery := fmt.Sprintf("CREATE DATABASE IF NOT EXISTS `%s`", storage.Database_databaseName+"_dns")

	_, err = tempDB.Exec(createQuery)
	if err != nil {
		log.Fatalf("❌ Erreur création base de données : %v", err)
	}
	defer func() {
		if err := tempDB.Close(); err != nil {
			// Handle or log the error
			logs.Write_Log("ERROR", "Error closing connection: "+err.Error())
		}
	}()

	// Connexion finale avec la base sélectionnée
	dsnWithDB := fmt.Sprintf("%s:%s@tcp(%s:%s)/%s?parseTime=true",
		storage.Database_username,
		storage.Database_password,
		storage.Database_iPDatabase,
		storage.Database_portDatabase,
		storage.Database_databaseName+"_dns",
	)

	for {
		db, err = sql.Open("mysql", dsnWithDB)
		if err != nil {
			logs.Write_LogCode("ERROR", logs.CodeDBConnection, "dnsdb: final database connection open failed: "+err.Error())
		} else {
			err = db.Ping()
			if err == nil {
				logs.Write_Log("INFO", "dnsdb: connected to database successfully")
				break
			}
			logs.Write_LogCode("ERROR", logs.CodeDBConnection, "dnsdb: final database ping failed: "+err.Error())
		}
		logs.Write_Log("INFO", "dnsdb: retrying connection in 30 seconds")
		time.Sleep(30 * time.Second)
	}
	err = InitPTRTable(db)
	if err != nil {
		logs.Write_LogCode("ERROR", logs.CodeDBQuery, "dnsdb: PTR table initialization failed: "+err.Error())
		return false
	}
	err = InitZonesTable(db)
	if err != nil {
		logs.Write_LogCode("ERROR", logs.CodeDBQuery, "dnsdb: zones table initialization failed: "+err.Error())
		return false
	}
	logs.Write_Log("INFO", "dnsdb: database initialized successfully")
	return true
}

func GetDatabase() *sql.DB {
	return db
}

func CloseDatabase() bool {
	if db != nil {
		_ = db.Close()
	}
	return true
}
