package database

import (
	"DUCKY/serveur/logs"
	"DUCKY/serveur/storage"
	"database/sql"
	"fmt"
	"log"
	"time"

	_ "github.com/go-sql-driver/mysql"
)

var DB *sql.DB

func InitDatabase() bool {
	var err error
	for {
		DB, err = sql.Open("mysql", storage.Database_username+":"+storage.Database_password+
			"@tcp("+storage.Database_iPDatabase+":"+storage.Database_portDatabase+")/"+
			storage.Database_databaseName)
		if err != nil {
			log.Printf("Erreur lors de l'ouverture de la connexion à la base de données : %v", err)
		} else {
			err = DB.Ping()
			if err == nil {
				logs.Write_Log("INFO", "✅ Connecté à la base de données.")
				break
			}
			logs.Write_Log("ERROR", "❌ Erreur de ping : "+err.Error())
		}

		fmt.Println("🔁 Nouvelle tentative de connexion dans 5 secondes...")
		time.Sleep(5 * time.Second)
	}

	return true
}

func GetDatabase() *sql.DB {
	return DB
}

func CloseDatabase() bool {
	if DB != nil {
		_ = DB.Close()
	}
	return true
}
