package dbcertificates

import (
	"database/sql"
	"fmt"
	"vaultaire/core/database"
	"vaultaire/core/storage"
)

// CreateCertificate crée un nouveau certificat
func CreateCertificate(name, certType string, certData, privKeyData, pubKeyData, description *string) (*storage.Certificate, error) {
	db := database.GetDatabase()

	// Vérifier si le certificat existe déjà
	var existingID int
	err := db.QueryRow("SELECT id_certificate FROM certificates WHERE name = ?", name).Scan(&existingID)
	if err == nil {
		return nil, fmt.Errorf("un certificat avec le nom '%s' existe déjà", name)
	}
	if err != sql.ErrNoRows {
		return nil, fmt.Errorf("erreur vérification certificat existant: %v", err)
	}

	// Insérer le nouveau certificat
	result, err := db.Exec(
		"INSERT INTO certificates (name, certificate_type, certificate_data, private_key_data, public_key_data, description) VALUES (?, ?, ?, ?, ?, ?)",
		name, certType, certData, privKeyData, pubKeyData, description,
	)
	if err != nil {
		return nil, fmt.Errorf("erreur création certificat: %v", err)
	}

	id, err := result.LastInsertId()
	if err != nil {
		return nil, fmt.Errorf("erreur récupération ID: %v", err)
	}

	return GetCertificateByID(int(id))
}
