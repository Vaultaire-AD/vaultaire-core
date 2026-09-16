package dbauthpolicy

import (
	"database/sql"
	"fmt"
	"vaultaire/core/logs"
)

// ConsumeMFACounter enregistre un pas de temps comme consommé.
//
// Retourne false si le pas a déjà servi, ou si un pas ultérieur a été consommé
// depuis.
//
// TOUT TIENT DANS LA CONDITION DE LA REQUÊTE. La vérification et l'écriture
// doivent être une seule opération atomique : lire le compteur puis l'écrire
// laisserait deux requêtes concurrentes lire la même valeur et accepter le même
// code deux fois — ce qui est précisément le scénario d'un code intercepté et
// rejoué en parallèle de la connexion légitime. MySQL sérialise l'UPDATE
// conditionnel, donc une seule des deux voit RowsAffected à 1.
func ConsumeMFACounter(db *sql.DB, username string, counter int64) (bool, error) {
	res, err := db.Exec(`UPDATE users SET mfa_last_counter = ?
		WHERE username = ? AND (mfa_last_counter IS NULL OR mfa_last_counter < ?)`,
		counter, username, counter)
	if err != nil {
		logs.Write_LogCode("ERROR", logs.CodeDBQuery,
			"authpolicy: consommation du code MFA de "+username+" échouée : "+err.Error())
		return false, fmt.Errorf("consommation du code : %w", err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return false, fmt.Errorf("consommation du code : %w", err)
	}
	return n > 0, nil
}
