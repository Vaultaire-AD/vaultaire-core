package dnsdatabase

import (
	"database/sql"
	"fmt"
	"strings"
)

func ResolvePTRQuery(db *sql.DB, ptrFQDN string) (string, error) {
	//fmt.Println("🔍 Résolution PTR pour :", ptrFQDN)
	ptrFQDN = strings.ToLower(strings.TrimSuffix(ptrFQDN, "."))

	// Extraire les octets inversés
	trimmed := strings.TrimSuffix(ptrFQDN, ".in-addr.arpa")
	octets := strings.Split(trimmed, ".")
	if len(octets) != 4 {
		return "", fmt.Errorf("❌ Format PTR inattendu pour '%s'", ptrFQDN)
	}

	ip := fmt.Sprintf("%s.%s.%s.%s", octets[0], octets[1], octets[2], octets[3])

	// Rechercher dans la base
	var hostname string
	err := db.QueryRow(`SELECT name FROM ptr_records WHERE ip = ?`, ip).Scan(&hostname)
	if err == sql.ErrNoRows {
		return "", fmt.Errorf("❌ Aucun enregistrement PTR pour IP %s", ip)
	}
	if err != nil {
		return "", fmt.Errorf("❌ Erreur DB : %v", err)
	}

	return hostname, nil
}
