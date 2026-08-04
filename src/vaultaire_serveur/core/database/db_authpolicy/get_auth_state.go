package dbauthpolicy

import (
	"database/sql"
	"fmt"
	"vaultaire/core/logs"
)

// GetAuthState lit l'état d'authentification d'un compte.
//
// Retourne une erreur si le compte n'existe pas : l'appelant a déjà vérifié son
// existence à ce stade, donc un compte absent ici signale une disparition en
// cours de traitement — un kill switch en mode hard, typiquement — et doit
// interrompre l'authentification plutôt que la poursuivre sur un état vide.
func GetAuthState(db *sql.DB, username string) (AuthState, error) {
	st := AuthState{Username: username}
	if db == nil {
		return st, fmt.Errorf("base indisponible")
	}

	var (
		secret  sql.NullString
		counter sql.NullInt64
		changed sql.NullTime
	)
	err := db.QueryRow(`SELECT mfa_enabled, mfa_secret, mfa_last_counter, password_changed_at
		FROM users WHERE username = ?`, username).
		Scan(&st.MFAEnabled, &secret, &counter, &changed)
	if err == sql.ErrNoRows {
		return st, fmt.Errorf("compte %s introuvable", username)
	}
	if err != nil {
		logs.Write_LogCode("ERROR", logs.CodeDBQuery,
			"authpolicy: lecture de l'état d'authentification de "+username+" échouée : "+err.Error())
		return st, fmt.Errorf("lecture de l'état d'authentification : %w", err)
	}

	st.MFASecret = secret.String
	st.MFALastCounter, st.HasMFALastCounter = counter.Int64, counter.Valid
	st.PasswordChangedAt, st.HasPasswordDate = changed.Time, changed.Valid
	return st, nil
}
