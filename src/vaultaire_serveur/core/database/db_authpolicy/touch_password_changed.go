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
	if _, err := db.Exec(`UPDATE users SET password_changed_at = NOW() WHERE username = ?`, username); err != nil {
		logs.Write_LogCode("ERROR", logs.CodeDBQuery,
			"authpolicy: mise à jour de password_changed_at pour "+username+" échouée : "+err.Error())
		return fmt.Errorf("mise à jour de la date de mot de passe : %w", err)
	}
	return nil
}
