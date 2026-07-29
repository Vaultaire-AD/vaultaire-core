package database

import (
	"database/sql"
	"fmt"
)

// DomainExists vérifie qu'un domaine est réellement enregistré (associé à au
// moins un groupe via domain_group), et pas juste une chaîne fournie par le
// client. C'est distinct de la vérification de permission : un droit "*"
// (super admin, autorisé partout) répond à "où a-t-il le droit d'aller",
// pas à "est-ce que cet endroit existe" — sans ce check, un domaine mal tapé
// ou inventé (ex "vault.fr" au lieu de "vaultaire.fr") serait accepté tel
// quel par n'importe quel super admin.
func DomainExists(db *sql.DB, domainName string) (bool, error) {
	if domainName == "" {
		return false, nil
	}
	var groupID int
	err := db.QueryRow(`SELECT d_id_group FROM domain_group WHERE domain_name = ? LIMIT 1`, domainName).Scan(&groupID)
	if err == sql.ErrNoRows {
		return false, nil
	}
	if err != nil {
		return false, fmt.Errorf("erreur vérification existence domaine : %w", err)
	}
	return true, nil
}
