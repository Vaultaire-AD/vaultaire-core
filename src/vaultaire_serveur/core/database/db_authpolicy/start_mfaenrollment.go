package dbauthpolicy

import (
	"database/sql"
	"fmt"
	"vaultaire/core/logs"
)

// StartMFAEnrollment enregistre un secret sans activer le second facteur.
//
// Deux temps, et c'est le point important de l'enrôlement : tant que
// l'utilisateur n'a pas prouvé qu'il peut produire un code, `mfa_enabled` reste
// faux. Écrire secret et activation d'un seul geste enfermerait dehors quiconque
// ferme l'onglet entre l'affichage du QR code et sa lecture par le téléphone.
//
// Écrase un enrôlement en cours, volontairement : recharger la page doit donner
// un secret utilisable, pas se heurter à un secret précédent abandonné.
func StartMFAEnrollment(db *sql.DB, username, secret string) error {
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
	res, err := db.Exec(`UPDATE users SET mfa_secret = ?, mfa_enabled = FALSE, mfa_last_counter = NULL, updated_at = updated_at
		WHERE username = ? AND mfa_enabled = FALSE`, secret, username)
	if err != nil {
		logs.Write_LogCode("ERROR", logs.CodeDBQuery,
			"authpolicy: enregistrement du secret MFA de "+username+" échoué : "+err.Error())
		return fmt.Errorf("enregistrement du secret : %w", err)
	}
	if n, _ := res.RowsAffected(); n == 0 {
		// La condition mfa_enabled = FALSE protège un second facteur déjà actif :
		// sans elle, un POST forgé sur la page d'enrôlement remplacerait le secret
		// d'un compte protégé par un secret choisi par l'attaquant. Le
		// remplacement d'un MFA actif passe obligatoirement par ResetMFA, qui est
		// gardé par write:mfa.
		return fmt.Errorf("un second facteur est déjà actif sur ce compte : il faut d'abord le réinitialiser")
	}
	return nil
}
