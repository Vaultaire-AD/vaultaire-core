package commanddns

import (
	"database/sql"
	"fmt"
	"strings"
)

// command_dns_showReverse affiche les enregistrements PTR de la table ptr_records
func command_dns_showReverse(commandList []string, db *sql.DB) string {
	query := `SELECT ip, name FROM ptr_records ORDER BY ip ASC`

	rows, err := db.Query(query)
	if err != nil {
		return fmt.Sprintf("❌ Erreur lors de la récupération des enregistrements PTR : %v", err)
	}
	defer rows.Close()

	var sb strings.Builder
	sb.WriteString("🔁 Enregistrements PTR (Reverse DNS)\n")
	sb.WriteString("--------------------------------------------------\n")
	sb.WriteString("Adresse IP              ↔️ Nom\n")
	sb.WriteString("--------------------------------------------------\n")

	count := 0
	for rows.Next() {
		var ip, name string
		if err := rows.Scan(&ip, &name); err != nil {
			return fmt.Sprintf("❌ Erreur de lecture ligne PTR : %v", err)
		}
		sb.WriteString(fmt.Sprintf("%-23s ↔️ %s\n", ip, name))
		count++
	}

	if count == 0 {
		sb.WriteString("Aucun enregistrement PTR trouvé.\n")
	}

	sb.WriteString("--------------------------------------------------")

	return sb.String()
}
