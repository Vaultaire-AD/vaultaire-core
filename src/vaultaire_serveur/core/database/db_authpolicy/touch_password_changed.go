package dbauthpolicy

import (
	"database/sql"
	"fmt"
	"vaultaire/core/logs"
)

// TouchPasswordChanged remet à zéro le compteur d'expiration d'un compte.
//
// À appeler depuis TOUT chemin qui modifie un mot de passe — page profil,
// commande CLI, réinitialisation par un administrateur. Un chemin qui l'oublie
// produit un compte dont le mot de passe vient de changer mais reste marqué
// expiré : l'utilisateur change son mot de passe et se retrouve renvoyé sur la
// même page, sans comprendre.
func TouchPasswordChanged(db *sql.DB, username string) error {
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
	if _, err := db.Exec(`UPDATE users SET password_changed_at = NOW(), updated_at = updated_at WHERE username = ?`, username); err != nil {
		logs.Write_LogCode("ERROR", logs.CodeDBQuery,
			"authpolicy: mise à jour de password_changed_at pour "+username+" échouée : "+err.Error())
		return fmt.Errorf("mise à jour de la date de mot de passe : %w", err)
	}
	return nil
}
