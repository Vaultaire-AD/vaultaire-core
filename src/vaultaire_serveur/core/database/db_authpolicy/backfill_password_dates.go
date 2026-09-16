package dbauthpolicy

import (
	"database/sql"
	"fmt"
	"vaultaire/core/logs"
)

// backfillPasswordDates donne une date de référence aux comptes qui n'en ont
// pas.
//
// Sans cela, tous les comptes existants auraient `password_changed_at` à NULL au
// premier démarrage suivant la mise à jour. Deux lectures possibles de ce NULL,
// toutes deux mauvaises : « jamais changé, donc infiniment expiré » verrouille
// l'annuaire entier d'un coup, et « inconnu, donc valide » crée une population
// de comptes qui n'expirera jamais.
//
// La date de création est la seule approximation défendable : c'est le moment où
// le mot de passe initial a été posé. Un compte créé il y a deux ans avec une
// politique à 90 jours se retrouve donc expiré dès l'activation de la politique
// — ce qui est le comportement correct, et la raison pour laquelle la politique
// est désactivée par défaut (durée 0).
func backfillPasswordDates(db *sql.DB) error {
	res, err := db.Exec(`UPDATE users SET password_changed_at = created_at
		WHERE password_changed_at IS NULL`)
	if err != nil {
		logs.Write_LogCode("ERROR", logs.CodeDBQuery,
			"authpolicy: initialisation de password_changed_at échouée : "+err.Error())
		return fmt.Errorf("initialisation de password_changed_at : %w", err)
	}
	if n, err := res.RowsAffected(); err == nil && n > 0 {
		logs.Write_Log("INFO", fmt.Sprintf(
			"authpolicy: %d compte(s) initialisé(s) sur leur date de création", n))
	}
	return nil
}
