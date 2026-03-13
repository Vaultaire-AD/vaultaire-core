package dnsdatabase

import (
	"database/sql"
	"fmt"
)

// domainIsTrue vérifie si le domaine (zone) existe dans la table dns_zones
func DomainIsTrue(domain string, db *sql.DB) bool {
	var id int64
	err := db.QueryRow(`SELECT id FROM dns_zones WHERE zone_name = ?`, domain).Scan(&id)
	if err == sql.ErrNoRows {
		return false
	} else if err != nil {
		fmt.Printf("❌ Erreur lors de la vérification du domaine : %v\n", err)
		return false
	}
	return true
}
