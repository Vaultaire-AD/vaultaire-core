package database

import (
	"DUCKY/serveur/logs"
	"database/sql"
	"fmt"
)

// Vérifie si un utilisateur est admin par rapport à un client spécifique
func IsUserAdmin(db *sql.DB, username, computeur_id string) (bool, error) {
	injection := SanitizeInput(username, computeur_id)
	if injection != nil {
		return false, injection
	}
	var userID, logicielID int

	// Récupérer l'ID utilisateur
	query := `SELECT id_user FROM users WHERE username = ?`
	err := db.QueryRow(query, username).Scan(&userID)
	if err != nil {
		if err == sql.ErrNoRows {
			logs.WriteLog("db", "Utilisateur non trouvé: "+username)
			return false, fmt.Errorf("utilisateur non trouvé")
		}
		logs.WriteLog("db", "Erreur lors de la récupération de l'ID utilisateur: "+err.Error())
		return false, err
	}

	// Récupérer l'ID du logiciel associé au client
	query = `SELECT id_logiciel FROM id_logiciels WHERE computeur_id = ?`
	err = db.QueryRow(query, computeur_id).Scan(&logicielID)
	if err != nil {
		if err == sql.ErrNoRows {
			logs.WriteLog("db", "Client non trouvé: "+computeur_id)
			return false, fmt.Errorf("client non trouvé")
		}
		logs.WriteLog("db", "Erreur lors de la récupération de l'ID logiciel: "+err.Error())
		return false, err
	}

	// --- Suppression de la vérification directe de permission utilisateur avec le logiciel ---

	// Vérifier si l'utilisateur et le logiciel sont dans un même groupe ayant une permission admin
	query = `
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
		logs.WriteLog("db", "Utilisateur "+username+" est admin via un groupe commun avec le client.")
		return true, nil
	} else if err != sql.ErrNoRows {
		logs.WriteLog("db", "Erreur lors de la vérification des permissions de groupe: "+err.Error())
		return false, err
	}

	// Si aucune condition d'admin n'est remplie
	logs.WriteLog("db", "Utilisateur "+username+" n'a pas de permission admin.")
	return false, nil
}
