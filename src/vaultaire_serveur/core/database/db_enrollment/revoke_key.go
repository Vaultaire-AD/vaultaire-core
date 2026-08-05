package dbenrollment

import (
	"database/sql"
	"fmt"
	"time"

	"vaultaire/core/logs"
)

// RevokeKey neutralise une clé sans la supprimer.
//
// La ligne est conservée : c'est elle qui porte les consommations déjà faites,
// et supprimer la clé effacerait par cascade la trace des services entrés avec
// elle — exactement ce qu'on veut lire le jour où l'on révoque.
func RevokeKey(db *sql.DB, id int, revokedBy string) error {
	if db == nil {
		return fmt.Errorf("connexion base indisponible")
	}
	res, err := db.Exec(
		`UPDATE service_enrollment_key
		    SET revoked_by = ?, revoked_at = ?
		  WHERE id_key = ? AND revoked_at IS NULL`,
		revokedBy, time.Now().UTC(), id)
	if err != nil {
		logs.Write_LogCode("ERROR", logs.CodeDBQuery, "dbenrollment: révocation échouée : "+err.Error())
		return fmt.Errorf("révocation de la clé : %w", err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return fmt.Errorf("révocation de la clé : %w", err)
	}
	if n == 0 {
		return fmt.Errorf("clé %d introuvable ou déjà révoquée", id)
	}

	logs.Write_Log("SECURITY", fmt.Sprintf("enrôlement: %s a révoqué la clé %d", revokedBy, id))
	return nil
}
