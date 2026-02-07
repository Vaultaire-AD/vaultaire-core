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
			log.Printf("❌ Erreur d'ouverture MySQL (sans DB) : %v", err)
		} else {
			err = tempDB.Ping()
			if err == nil {
				break
			}
			log.Printf("❌ Erreur de ping (sans DB) : %v", err)
		}
		fmt.Println("🔁 Tentative de reconnexion dans 30 secondes...")
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
			log.Printf("❌ Erreur ouverture DB finale : %v", err)
		} else {
			err = db.Ping()
			if err == nil {
				logs.Write_Log("INFO", "✅ Connecté à la base de données.")
				break
			}
			logs.Write_Log("ERROR", "❌ Erreur de ping finale : "+err.Error())
		}
		fmt.Println("🔁 Nouvelle tentative dans 30 secondes...")
		time.Sleep(30 * time.Second)
	}
	err = InitPTRTable(db)
	if err != nil {
		logs.Write_Log("ERROR", "❌ Erreur lors de l'initialisation de la table PTR : "+err.Error())
		return false
	}
	err = InitZonesTable(db)
	if err != nil {
		logs.Write_Log("ERROR", "❌ Erreur lors de l'initialisation de la table Zones : "+err.Error())
		return false
	}
	logs.Write_Log("INFO", "✅ Base de données initialisée avec succès.")
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
