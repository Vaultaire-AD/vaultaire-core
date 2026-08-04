package dbcertificates

import (
	"fmt"
	"vaultaire/core/database"
)

// UpdateCertificate met à jour un certificat existant
func UpdateCertificate(id int, certData, privKeyData, pubKeyData, description *string) error {
	db := database.GetDatabase()

	_, err := db.Exec(
		"UPDATE certificates SET certificate_data = ?, private_key_data = ?, public_key_data = ?, description = ? WHERE id_certificate = ?",
		certData, privKeyData, pubKeyData, description, id,
	)
	if err != nil {
		return fmt.Errorf("erreur mise à jour certificat: %v", err)
	}

	return nil
}
