package database

import (
	"DUCKY/serveur/logs"
	"DUCKY/serveur/storage"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"fmt"
	"log"
	"time"
)

// CreateAdminUser crée un utilisateur administrateur et l'ajoute au groupe vaultaire
func CreateDefaultAdminUser(db *sql.DB) {
	log.Println("[BOOTSTRAP] Création de l'administrateur...")

	// 1. Validation minimale
	if storage.Administrateur_Username == "" {
		log.Fatal("[BOOTSTRAP] Le username de l'administrateur est vide")
	}
	if storage.Administrateur_Password == "" {
		log.Fatal("[BOOTSTRAP] Le password de l'administrateur est vide")
	}

	// Générer un salt
	salt, err := generateSalt(16)
	if err != nil {
		return
	}
	saltHex := hex.EncodeToString(salt)

	// Appliquer le hash SHA256 sur le mot de passe + salt
	saltedPassword := append(salt, []byte(storage.Administrateur_Password)...)
	hash := sha256.Sum256(saltedPassword)
	hashHex := hex.EncodeToString(hash[:])

	// 3. Valeurs par défaut pour les champs requis
	firstname := "Admin"
	lastname := "System"
	email := storage.Administrateur_Username + "@vaultaire.local"
	birthdate := "01/01/3300"

	// 4. Créer l'utilisateur admin
	err = Create_New_User(
		GetDatabase(),
		storage.Administrateur_Username,
		firstname,
		lastname,
		email,
		hashHex, // mot de passe hashé
		saltHex, // salt (en hex)
		birthdate,
		time.Now().Format("2006-01-02 15:04:05"),
	)
	if err != nil {
		logs.WriteLog("db", fmt.Sprintf("Erreur création admin: %v", err))
		log.Fatalf("[BOOTSTRAP] Erreur création admin: %v", err)
	} else {
		log.Println("[BOOTSTRAP] ✓ Utilisateur administrateur créé")
	}

	// 5. Récupérer l'ID de l'utilisateur
	var userID int
	err = db.QueryRow(`
		SELECT id_user FROM users WHERE username = ?
	`, storage.Administrateur_Username).Scan(&userID)
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
