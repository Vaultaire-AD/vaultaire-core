package database

import (
	"vaultaire/serveur/logs"
	"vaultaire/serveur/storage"
	"database/sql"
	"fmt"
	"strings"
)

// Structure pour stocker les informations du groupe

// Récupérer toutes les infos d'un groupe via son nom
func Command_GET_GroupInfo(db *sql.DB, groupName string) (*storage.GroupInfo, error) {
	injection := SanitizeInput(groupName)
	if injection != nil {
		return nil, injection
	}

	query := `
	SELECT 
		g.id_group,
		g.group_name,
		COALESCE(dg.domain_name, '') AS domain_name,
		COALESCE(GROUP_CONCAT(DISTINCT u.username ORDER BY u.username SEPARATOR ', '), '') AS users,
		-- Permissions utilisateurs (LDAP)
		COALESCE(GROUP_CONCAT(DISTINCT p.name ORDER BY p.name SEPARATOR ', '), '') AS user_permissions,
		COALESCE(GROUP_CONCAT(DISTINCT l.computeur_id ORDER BY l.computeur_id SEPARATOR ', '), '') AS clients,
		-- Permissions clients/logiciels (table client_permission)
		COALESCE(GROUP_CONCAT(DISTINCT cp.name_permission ORDER BY cp.name_permission SEPARATOR ', '), '') AS client_permissions,
		COALESCE(GROUP_CONCAT(DISTINCT gpo.gpo_name ORDER BY gpo.gpo_name SEPARATOR ', '), '') AS gpos
	FROM groups g
	LEFT JOIN domain_group dg ON g.id_group = dg.d_id_group
	LEFT JOIN users_group ug ON g.id_group = ug.d_id_group
	LEFT JOIN users u ON ug.d_id_user = u.id_user
	LEFT JOIN group_user_permission gp ON g.id_group = gp.d_id_group
	LEFT JOIN user_permission p ON gp.d_id_user_permission = p.id_user_permission
	LEFT JOIN logiciel_group lg ON g.id_group = lg.d_id_group
	LEFT JOIN id_logiciels l ON lg.d_id_logiciel = l.id_logiciel
	LEFT JOIN group_permission_logiciel gpl ON g.id_group = gpl.d_id_group
	LEFT JOIN client_permission cp ON gpl.d_id_permission = cp.id_permission
	LEFT JOIN group_linux_gpo gg ON g.id_group = gg.d_id_group
	LEFT JOIN linux_gpo_distributions gpo ON gg.d_id_gpo = gpo.id
	WHERE g.group_name = ?
	GROUP BY g.id_group, g.group_name, dg.domain_name;
	`

	var group storage.GroupInfo
	var domainName sql.NullString
	var users, userPerms, clients, clientPerms, gpos sql.NullString

	err := db.QueryRow(query, groupName).Scan(
		&group.ID,
		&group.Name,
		&domainName,
		&users,
		&userPerms,
		&clients,
		&clientPerms,
		&gpos,
	)
	if err != nil {
		if err == sql.ErrNoRows {
			logs.WriteLog("db", "❌ Aucun groupe trouvé avec le nom : "+groupName)
			return nil, fmt.Errorf("❌ Aucun groupe trouvé avec le nom : %v", groupName)
		}
		logs.WriteLog("db", "❌ Erreur SQL : "+err.Error())
		return nil, fmt.Errorf("erreur lors de l'exécution de la requête : %v", err)
	}

	group.DomainName = domainName.String
	group.Users = splitIfNotEmpty(users.String)
	group.Permissions = splitIfNotEmpty(userPerms.String) // Permissions utilisateurs
	group.Clients = splitIfNotEmpty(clients.String)
	group.ClientPerms = splitIfNotEmpty(clientPerms.String) // Permissions clients/logiciels
	group.GPOs = splitIfNotEmpty(gpos.String)

	return &group, nil
}

// Fonction utilitaire pour transformer une string en slice
func splitIfNotEmpty(s string) []string {
	if s == "" {
		return []string{}
	}
	return splitTrim(s, ", ")
}

// Fonction utilitaire pour split + trim chaque élément
func splitTrim(s, sep string) []string {
	parts := []string{}
	for _, part := range strings.Split(s, sep) {
		parts = append(parts, strings.TrimSpace(part))
	}
	return parts
}
