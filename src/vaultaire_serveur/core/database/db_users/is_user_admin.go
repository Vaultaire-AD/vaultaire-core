package dbusers

import (
	"database/sql"
	"fmt"
	database "vaultaire/core/database"
	"vaultaire/core/logs"
)

// Vérifie si un utilisateur est admin par rapport à un client spécifique
func IsUserAdmin(db *sql.DB, username, computeur_id string) (bool, error) {
	injection := database.SanitizeIdentifier(username, computeur_id)
	if injection != nil {
		return false, injection
	}
	// Récupérer l'ID utilisateur
	userID, found, err := database.LookupUserID(db, username)
	if err != nil {
		logs.Write_LogCode("ERROR", logs.CodeDBQuery, "database: "+"Erreur lors de la récupération de l'ID utilisateur: "+err.Error())
		return false, err
	}
	if !found {
		logs.Write_LogCode("WARNING", logs.CodeDBUserNotFound, "database: Utilisateur non trouvé: "+username)
		return false, fmt.Errorf("utilisateur non trouvé")
	}

	// Récupérer l'ID du logiciel associé au client
	logicielID, found, err := database.LookupClientID(db, computeur_id)
	if err != nil {
		logs.Write_LogCode("ERROR", logs.CodeDBQuery, "database: "+"Erreur lors de la récupération de l'ID logiciel: "+err.Error())
		return false, err
	}
	if !found {
		logs.Write_LogCode("WARNING", logs.CodeDBGeneric, "database: Client non trouvé: "+computeur_id)
		return false, fmt.Errorf("client non trouvé")
	}

	// --- Suppression de la vérification directe de permission utilisateur avec le logiciel ---

	// Vérifier si l'utilisateur et le logiciel sont dans un même groupe ayant une permission admin
	query := `
		SELECT 1
FROM users_group AS ug
JOIN logiciel_group AS lg ON ug.d_id_group = lg.d_id_group
JOIN group_permission_logiciel AS gpl ON lg.d_id_group = gpl.d_id_group
JOIN client_permission AS p ON gpl.d_id_permission = p.id_permission
WHERE ug.d_id_user = ? AND lg.d_id_logiciel = ? AND p.is_admin = TRUE
LIMIT 1
`
	err = db.QueryRow(query, userID, logicielID).Scan(new(int))
	if err == nil {
		logs.Write_LogCode("DEBUG", logs.CodeNone, "database: Utilisateur "+username+" est admin via un groupe commun avec le client.")
		return true, nil
	} else if err != sql.ErrNoRows {
		logs.Write_LogCode("ERROR", logs.CodeDBQuery, "database: "+"Erreur lors de la vérification des permissions de groupe: "+err.Error())
		return false, err
	}

	// Si aucune condition d'admin n'est remplie
	logs.Write_LogCode("DEBUG", logs.CodeNone, "database: Utilisateur "+username+" n'a pas de permission admin.")
	return false, nil
}
