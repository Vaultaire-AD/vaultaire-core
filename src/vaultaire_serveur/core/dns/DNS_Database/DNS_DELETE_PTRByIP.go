package dnsdatabase

import (
	"database/sql"
	"fmt"
)

func DeletePTRRecordByIP(db *sql.DB, ip string) error {
	query := `DELETE FROM ptr_records WHERE ip = ?`
	res, err := db.Exec(query, ip)
	if err != nil {
		return fmt.Errorf("❌ erreur suppression PTR pour IP %s : %v", ip, err)
	}

	rowsAffected, _ := res.RowsAffected()
	if rowsAffected == 0 {
		return fmt.Errorf("ℹ️ aucun enregistrement PTR trouvé pour IP %s", ip)
	}
	return nil
}
