package database

import (
	"vaultaire/serveur/logs"
	"vaultaire/serveur/storage"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"fmt"
	"log"
	"time"
)

// CreateDefaultAdminUser crée l'utilisateur administrateur par défaut s'il n'existe pas, et l'ajoute au groupe vaultaire.
// Si l'admin existe déjà (ex: redémarrage du conteneur), la création est ignorée et le processus continue.
func CreateDefaultAdminUser(db *sql.DB) {
	log.Println("[BOOTSTRAP] Vérification de l'administrateur par défaut...")

	// 1. Validation minimale
	if storage.Administrateur_Username == "" {
		log.Fatal("[BOOTSTRAP] Le username de l'administrateur est vide")
	}
	if storage.Administrateur_Password == "" {
		log.Fatal("[BOOTSTRAP] Le password de l'administrateur est vide")
	}

	// 2. Si l'admin existe déjà (ex: redémarrage), ne pas recréer — éviter log.Fatal sur contrainte unique
	userID, err := Get_User_ID_By_Username(db, storage.Administrateur_Username)
	if err == nil {
		log.Printf("[BOOTSTRAP] Admin '%s' déjà existant, pas de création (id=%d)", storage.Administrateur_Username, userID)
		// S'assurer qu'il est bien dans le groupe vaultaire (INSERT IGNORE si déjà présent)
		_, _ = db.Exec(`
			INSERT IGNORE INTO users_group (d_id_user, d_id_group)
			SELECT ?, g.id_group FROM groups g WHERE g.group_name = 'vaultaire'
		`, userID)
		log.Println("[BOOTSTRAP] ✓ Démarrage avec admin existant")
		return
	}

	// 3. Créer le nouvel admin
	log.Println("[BOOTSTRAP] Création de l'administrateur...")
	salt, err := generateSalt(16)
	if err != nil {
		logs.WriteLog("db", "génération salt admin: "+err.Error())
		log.Fatalf("[BOOTSTRAP] Erreur génération salt: %v", err)
	}
	saltHex := hex.EncodeToString(salt)
	saltedPassword := append(salt, []byte(storage.Administrateur_Password)...)
	hash := sha256.Sum256(saltedPassword)
	hashHex := hex.EncodeToString(hash[:])

	firstname := "Admin"
	lastname := "System"
	email := storage.Administrateur_Username + "@vaultaire.local"
	birthdate := "01/01/3300"

	err = Create_New_User(
		GetDatabase(),
		storage.Administrateur_Username,
		firstname,
		lastname,
		email,
		hashHex,
		saltHex,
		birthdate,
		time.Now().Format("2006-01-02 15:04:05"),
	)
	if err != nil {
		logs.WriteLog("db", fmt.Sprintf("Erreur création admin: %v", err))
		log.Fatalf("[BOOTSTRAP] Erreur création admin: %v", err)
	}
	log.Println("[BOOTSTRAP] ✓ Utilisateur administrateur créé")

	userID, err = Get_User_ID_By_Username(db, storage.Administrateur_Username)
	if err != nil {
		logs.WriteLog("db", fmt.Sprintf("Erreur récupération ID admin: %v", err))
		log.Fatalf("[BOOTSTRAP] Erreur récupération ID admin: %v", err)
	}

	// 6. Ajouter la clé publique si fournie
	if storage.Administrateur_PublicKey != "" {
		_, err = db.Exec(`
			INSERT IGNORE INTO user_public_keys (id_user, public_key, label)
			VALUES (?, ?, 'Admin Key')
		`,
			userID,
			storage.Administrateur_PublicKey,
		)
		if err != nil {
			logs.WriteLog("db", fmt.Sprintf("Erreur ajout clé publique: %v", err))
			log.Printf("[BOOTSTRAP] WARN: Impossible d'ajouter la clé publique: %v", err)
		} else {
			log.Println("[BOOTSTRAP] Clé publique ajoutée")
		}
	}

	// 7. Ajouter l'utilisateur au groupe vaultaire
	_, err = db.Exec(`
		INSERT IGNORE INTO users_group (d_id_user, d_id_group)
		SELECT ?, g.id_group
		FROM groups g
		WHERE g.group_name = 'vaultaire'
	`,
		userID,
	)
	if err != nil {
		logs.WriteLog("db", fmt.Sprintf("Erreur association au groupe vaultaire: %v", err))
		log.Fatalf("[BOOTSTRAP] Erreur association au groupe vaultaire: %v", err)
	}

	log.Printf("[BOOTSTRAP] ✓ Admin '%s' créé et ajouté au groupe vaultaire", storage.Administrateur_Username)
}
