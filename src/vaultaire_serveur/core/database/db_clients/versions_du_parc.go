package dbclients

import (
	"database/sql"
	"fmt"

	"vaultaire/core/parcversion"
)

// VersionsDuParc rend chaque machine inscrite avec la version qu'elle a
// déclarée dans sa dernière 02_12 (TO-DO 161, lecture partagée avec le 111).
//
// TOUTES les lignes d'id_logiciels : agents Linux et Windows, proxies, Nexus.
// Tous emploient le même socle réseau, donc le même tunnel, et un proxy
// antérieur à la 2.2 ferme le sien après dix minutes sans trafic comme un
// poste. Une machine créée mais jamais raccordée y figure avec une version
// vide : c'est voulu, elle se raccordera un jour avec la version qu'on lui
// aura installée — rien ne dit que ce sera la bonne.
func VersionsDuParc(db *sql.DB) ([]parcversion.Machine, error) {
	if db == nil {
		return nil, fmt.Errorf("base indisponible")
	}
	rows, err := db.Query(`SELECT computeur_id, hostname, agent_version FROM id_logiciels`)
	if err != nil {
		return nil, fmt.Errorf("lecture des versions du parc : %w", err)
	}
	defer func() { _ = rows.Close() }()

	var parc []parcversion.Machine
	for rows.Next() {
		var m parcversion.Machine
		if err := rows.Scan(&m.ComputeurID, &m.Hostname, &m.Declaree); err != nil {
			return nil, fmt.Errorf("lecture des versions du parc : %w", err)
		}
		parc = append(parc, m)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("lecture des versions du parc : %w", err)
	}
	return parc, nil
}
