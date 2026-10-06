package dbauthpolicy

import (
	"database/sql"
	"fmt"
)

// CompterComptesAvecMFA compte les comptes qui ont réellement un second
// facteur actif — TO-DO 95.
//
// # À quoi sert ce chiffre
//
// Il est affiché AVANT d'activer l'exigence de second facteur sur le chemin
// Ducky, et il refuse le geste quand il vaut zéro. C'est le seul indicateur que
// le core possède sur l'état de préparation du parc : il ne sait pas quelle
// version d'agent tourne sur chaque poste, mais il sait si quelqu'un a enrôlé
// quoi que ce soit.
//
// # Les deux conditions ensemble
//
// `mfa_enabled` ET un secret non vide. Entre la génération du secret et la
// validation du premier code, un compte a un secret sans second facteur actif :
// le compter ferait croire à un enrôlement qui n'a jamais abouti.
func CompterComptesAvecMFA(db *sql.DB) (int, error) {
	if db == nil {
		return 0, fmt.Errorf("base indisponible")
	}
	var n int
	err := db.QueryRow(`SELECT COUNT(*) FROM users
		WHERE mfa_enabled = TRUE AND mfa_secret IS NOT NULL AND mfa_secret <> ''`).Scan(&n)
	if err != nil {
		return 0, fmt.Errorf("comptage des comptes à second facteur : %w", err)
	}
	return n, nil
}
