package database

import (
	"database/sql"
	"errors"
	"fmt"
	"strings"
	"vaultaire/core/logs"
	"vaultaire/core/storage"
)

// Récupère les domaines associés aux groupes utilisateur
func GetDomainsForUser(db *sql.DB, userID int) ([]string, error) {
	query := `
		SELECT DISTINCT dg.domain_name
		FROM domain_group dg
		JOIN groups g ON dg.d_id_group = g.id_group
		JOIN users_group ug ON ug.d_id_group = g.id_group
		WHERE ug.d_id_user = ?
	`

	rows, err := db.Query(query, userID)
	if err != nil {
		return nil, err
	}
	defer func() {
		if err := rows.Close(); err != nil {
			// Handle or log the error
			logs.Write_Log("ERROR", "Error closing connection: "+err.Error())
		}
	}()

	var domains []string
	for rows.Next() {
		var domain string
		if err := rows.Scan(&domain); err != nil {
			return nil, err
		}
		domains = append(domains, domain)
	}
	// rows.Err() distingue « la lecture est terminée » de « la lecture s'est
	// interrompue ». Sans ce contrôle, une coupure en cours d'itération rend un
	// résultat PARTIEL présenté comme complet.
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return domains, nil
}

// Récupérer le domaine principal, ex: company.com à partir de finance.company.com
func ExtractMainDomain(domain string) (string, error) {
	parts := strings.Split(domain, ".")
	if len(parts) < 2 {
		return "", errors.New("domaine invalide")
	}
	n := len(parts)
	return parts[n-2] + "." + parts[n-1], nil
}

// Fonction principale qui récupère le domaine principal d’un utilisateur (le premier trouvé)
func GetUserMainDomain(db *sql.DB, userID int) (string, error) {
	domains, err := GetDomainsForUser(db, userID)
	if err != nil {
		return "", err
	}
	if len(domains) == 0 {
		return "", errors.New("aucun domaine trouvé pour l'utilisateur")
	}

	// Ici on prend le premier domaine associé
	return ExtractMainDomain(domains[0])
}

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

// Command_GET_DomainsFromGroupIDs récupère les domaines associés à une liste d'ID de groupes.
// Comme un groupe ne peut avoir qu'un seul domaine, on retourne une slice de string correspondante.
func Command_GET_DomainsFromGroupIDs(db *sql.DB, groupIDs []int) ([]string, error) {
	if len(groupIDs) == 0 {
		return []string{}, nil
	}

	domains := []string{}
	for _, id := range groupIDs {
		var domain string
		err := db.QueryRow(`SELECT domain_name FROM domain_group WHERE d_id_group = ? LIMIT 1`, id).Scan(&domain)
		if err != nil {
			if err == sql.ErrNoRows {
				// Pas de domaine pour ce groupe, on peut ignorer
				continue
			}
			return nil, fmt.Errorf("erreur lors de la récupération du domaine pour le groupe %d : %v", id, err)
		}
		domains = append(domains, domain)
	}

	return domains, nil
}

func GetDomainsFromGroupName(groupName string) ([]string, error) {
	db := GetDatabase()

	// On récupère l'ID du groupe via son nom
	groupID, err := GetGroupIDByName(db, groupName)
	if err != nil {
		logs.Write_Log("WARNING", "Erreur récupération ID du groupe "+groupName+" : "+err.Error())
		return nil, err
	}

	// On récupère les domaines associés à ce groupe
	domains, err := Command_GET_DomainsFromGroupIDs(db, []int{groupID})
	if err != nil {
		logs.Write_Log("WARNING", "Erreur récupération domaines du groupe "+groupName+" : "+err.Error())
		return nil, err
	}

	return domains, nil
}

func GetAllGroupsWithDomains(db *sql.DB) ([]storage.GroupDomain, error) {
	query := `
		SELECT 
			g.group_name, 
			dg.domain_name
		FROM 
			groups g
		JOIN 
			domain_group dg ON g.id_group = dg.d_id_group
	`

	rows, err := db.Query(query)
	if err != nil {
		return nil, fmt.Errorf("erreur lors de l'exécution de la requête : %v", err)
	}
	defer func() {
		if err := rows.Close(); err != nil {
			// Handle or log the error
			logs.Write_Log("ERROR", "Error closing connection: "+err.Error())
		}
	}()

	var results []storage.GroupDomain
	for rows.Next() {
		var gd storage.GroupDomain
		if err := rows.Scan(&gd.GroupName, &gd.DomainName); err != nil {
			return nil, fmt.Errorf("erreur lors du scan : %v", err)
		}
		results = append(results, gd)
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("erreur d'itération : %v", err)
	}

	return results, nil
}
