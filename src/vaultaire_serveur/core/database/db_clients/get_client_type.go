package dbclients

import (
	"database/sql"
	"fmt"

	"vaultaire/core/database"
	"vaultaire/core/logs"
)

// Get_Client_Type retourne le type déclaré d'une machine.
//
// Lu UNE FOIS à la poignée de main pour être figé sur la session, jamais à
// chaque trame : relire le type en cours de session permettrait à une
// modification concurrente de changer les droits d'une connexion déjà ouverte.
//
// L'identifiant passé ici est déjà prouvé au moment où cette fonction est
// appelée — la réponse 01_02 est chiffrée avec la clé publique de cet
// identifiant, donc qui ment sur son identifiant ne déchiffre rien. Le type qui
// en dérive hérite de cette preuve.
func Get_Client_Type(db *sql.DB, computerID string) (string, error) {
	if err := database.SanitizeIdentifier(computerID); err != nil {
		return "", err
	}
	if db == nil {
		return "", fmt.Errorf("connexion base indisponible")
	}

	var clientType string
	err := db.QueryRow(
		`SELECT logiciel_type FROM id_logiciels WHERE computeur_id = ? LIMIT 1`,
		computerID).Scan(&clientType)
	switch {
	case err == sql.ErrNoRows:
		return "", fmt.Errorf("aucun client trouvé pour l'ordinateur %s", computerID)
	case err != nil:
		logs.Write_LogCode("ERROR", logs.CodeDBQuery,
			"dbclients: lecture du type de "+computerID+" échouée : "+err.Error())
		return "", err
	}
	return clientType, nil
}
