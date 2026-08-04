package dbcertificates

import (
	"fmt"
	"vaultaire/core/database"
)

// DeleteCertificate supprime un certificat
func DeleteCertificate(id int) error {
	db := database.GetDatabase()

	result, err := db.Exec("DELETE FROM certificates WHERE id_certificate = ?", id)
	if err != nil {
		return fmt.Errorf("erreur suppression certificat: %v", err)
	}

	rowsAffected, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("erreur vérification suppression: %v", err)
	}
	if rowsAffected == 0 {
		return fmt.Errorf("certificat non trouvé: ID %d", id)
	}

	return nil
}
