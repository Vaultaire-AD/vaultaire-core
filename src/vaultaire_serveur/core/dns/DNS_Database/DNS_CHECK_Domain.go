package dnsdatabase

import (
	"database/sql"
	"vaultaire/core/logs"
)

// domainIsTrue vérifie si le domaine (zone) existe dans la table dns_zones
func DomainIsTrue(domain string, db *sql.DB) bool {
	var id int64
	err := db.QueryRow(`SELECT id FROM dns_zones WHERE zone_name = ?`, domain).Scan(&id)
	if err == sql.ErrNoRows {
		return false
	} else if err != nil {
		logs.Write_LogCode("ERROR", logs.CodeDBQuery, "dns : zone "+domain+" non vérifiable : "+err.Error())
		return false
	}
	return true
}
