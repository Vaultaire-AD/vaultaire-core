package dbauthpolicy

import (
	"database/sql"
	"fmt"
	"vaultaire/core/logs"
)

// IsMFARequired dit si un compte est soumis au second facteur par l'un de ses
// groupes.
//
// « Au moins un groupe l'exige » et non « tous » : le second facteur est une
// contrainte, pas un droit. Un administrateur qui appartient aussi à un groupe
// ordinaire ne doit pas voir son exigence levée par ce second groupe — ce serait
// une baisse de sécurité obtenue en ajoutant une appartenance, exactement le
// contraire de ce qu'on attend.
//
// Fail-closed, contrairement à la lecture de la politique de mot de passe : une
// erreur ici conduit à EXIGER le second facteur. L'asymétrie est inverse du cas
// de l'expiration — refuser à tort demande à l'utilisateur un code qu'il a déjà
// dans son téléphone, tandis qu'accorder à tort lève la protection de tous les
// comptes administrateurs pendant l'incident.
func IsMFARequired(db *sql.DB, username string) (bool, error) {
	if db == nil {
		return true, fmt.Errorf("base indisponible")
	}

	var count int
	err := db.QueryRow(`SELECT COUNT(*)
		FROM users u
		JOIN users_group ug ON ug.d_id_user = u.id_user
		JOIN groups g ON g.id_group = ug.d_id_group
		WHERE u.username = ? AND g.mfa_required = TRUE`, username).Scan(&count)
	if err != nil {
		logs.Write_LogCode("ERROR", logs.CodeDBQuery,
			"authpolicy: lecture de l'exigence MFA de "+username+" échouée : "+err.Error())
		return true, fmt.Errorf("lecture de l'exigence MFA : %w", err)
	}
	return count > 0, nil
}
