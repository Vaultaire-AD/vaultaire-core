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
		secret     sql.NullString
		counter    sql.NullInt64
		changed    sql.NullTime
		provisoire sql.NullTime
	)
	// Le drapeau de changement obligatoire est lu ICI et non par une requête à
	// part : tous les chemins d'authentification lisent déjà cet état pour le
	// second facteur, et leur faire relire le compte doublerait les requêtes sur
	// le trajet le plus fréquent du serveur — en ouvrant une fenêtre où les deux
	// lectures ne verraient pas le même compte.
	err := db.QueryRow(`SELECT mfa_enabled, mfa_secret, mfa_last_counter, password_changed_at,
		       must_change_password, provisional_password_until
		FROM users WHERE username = ?`, username).
		Scan(&st.MFAEnabled, &secret, &counter, &changed,
			&st.MustChangePassword, &provisoire)
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
	st.ProvisionalUntil, st.HasProvisionalUntil = provisoire.Time, provisoire.Valid
	return st, nil
}
