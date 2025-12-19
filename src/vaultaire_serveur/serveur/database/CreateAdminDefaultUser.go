package database

import (
	"DUCKY/serveur/storage"
	"database/sql"
	"log"
)

func CreateAdminDefaultUser(db *sql.DB) {
	// Fonction pour créer un utilisateur administrateur par défaut
	log.Println("[BOOTSTRAP] Administrateur activé")

	// 1. Validation minimale
	if storage.Administrateur_Username == "" {
		log.Fatal("Administrateur username vide")
	}

	if storage.Administrateur_PublicKey == "" {
		log.Fatal("Administrateur public_key manquante")
	}

	// 2. Créer l'utilisateur admin s'il n'existe pas
	_, err := db.Exec(`
		INSERT IGNORE INTO users (username, password)
		VALUES (?, ?)
	`,
		storage.Administrateur_Username,
		storage.Administrateur_Password, // idéalement hashé, mais on reste cohérent avec ton modèle actuel
	)
	if err != nil {
		log.Fatalf("Erreur création utilisateur admin: %v", err)
	}

	// 3. Associer la clé publique à l'utilisateur
	_, err = db.Exec(`
		INSERT IGNORE INTO user_public_key (d_id_user, public_key)
		SELECT u.id_user, ?
		FROM users u
		WHERE u.username = ?
	`,
		storage.Administrateur_PublicKey,
		storage.Administrateur_Username,
	)
	if err != nil {
		log.Fatalf("Erreur ajout clé publique admin: %v", err)
	}

	// 4. Ajouter l'utilisateur au groupe "vaultaire"
	_, err = db.Exec(`
		INSERT IGNORE INTO users_group (d_id_user, d_id_group)
		SELECT u.id_user, g.id_group
		FROM users u, groups g
		WHERE u.username = ? AND g.group_name = 'vaultaire'
	`,
		storage.Administrateur_Username,
	)
	if err != nil {
		log.Fatalf("Erreur association admin au groupe vaultaire: %v", err)
	}

	log.Println("[BOOTSTRAP] Administrateur créé et configuré")
}
