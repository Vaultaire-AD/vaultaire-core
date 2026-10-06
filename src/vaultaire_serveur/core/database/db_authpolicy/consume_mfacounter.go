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
	// `updated_at = updated_at` : la date de modification de l'annuaire ne bouge PAS.
	//
	// La colonne est tenue par la base — `ON UPDATE CURRENT_TIMESTAMP` —, ce qui est
	// voulu : un chemin d'écriture nouveau bumpe la date sans que personne y pense,
	// et sur-synchroniser vaut mieux que manquer un changement.
	//
	// Mais ce qui s'écrit ici n'est visible d'aucun client LDAP. Laisser la date
	// bouger ferait réimporter le compte à CHAQUE connexion par tout client qui
	// synchronise en incrémental, pour un annuaire qui n'a pas changé d'un
	// caractère. Réaffecter la colonne à elle-même est la façon MySQL de le dire.
	res, err := db.Exec(`UPDATE users SET mfa_last_counter = ?, updated_at = updated_at
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
