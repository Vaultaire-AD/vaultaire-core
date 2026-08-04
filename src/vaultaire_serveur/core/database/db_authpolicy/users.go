package dbauthpolicy

import (
	"database/sql"
	"fmt"
	"time"

	"vaultaire/core/logs"
)

// AuthState rassemble tout ce qu'un chemin d'authentification doit savoir d'un
// compte, en une seule lecture.
//
// Une seule requête et non trois : ces champs sont lus à chaque tentative de
// connexion, sur les trois chemins. Les séparer multiplierait les allers-retours
// sur le trajet le plus chaud du serveur, et surtout ouvrirait une fenêtre où le
// second facteur serait lu avant une désactivation et l'expiration après.
type AuthState struct {
	Username          string
	MFAEnabled        bool
	MFASecret         string
	MFALastCounter    int64
	HasMFALastCounter bool
	PasswordChangedAt time.Time
	HasPasswordDate   bool
}

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

// SetGroupMFARequired pose ou retire l'exigence de second facteur sur un groupe.
func SetGroupMFARequired(db *sql.DB, groupName string, required bool, updatedBy string) error {
	res, err := db.Exec(`UPDATE groups SET mfa_required = ? WHERE group_name = ?`, required, groupName)
	if err != nil {
		logs.Write_LogCode("ERROR", logs.CodeDBQuery,
			"authpolicy: mise à jour de mfa_required sur "+groupName+" échouée : "+err.Error())
		return fmt.Errorf("mise à jour du groupe %s : %w", groupName, err)
	}
	if n, _ := res.RowsAffected(); n == 0 {
		// Zéro ligne peut signifier « groupe inconnu » ou « valeur déjà posée ».
		// On vérifie plutôt que d'annoncer un succès sur un nom mal orthographié.
		var exists int
		if err := db.QueryRow(`SELECT COUNT(*) FROM groups WHERE group_name = ?`, groupName).Scan(&exists); err == nil && exists == 0 {
			return fmt.Errorf("groupe %s inconnu", groupName)
		}
	}

	state := "retirée de"
	if required {
		state = "posée sur"
	}
	logs.Write_Log("SECURITY", fmt.Sprintf(
		"authpolicy: exigence MFA %s le groupe %s par %s", state, groupName, updatedBy))
	return nil
}

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
	res, err := db.Exec(`UPDATE users SET mfa_secret = ?, mfa_enabled = FALSE, mfa_last_counter = NULL
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

// ActivateMFA active le second facteur après vérification d'un premier code.
//
// `counter` est le pas de temps du code qui vient d'être validé : il est
// consommé du même geste, sinon le code affiché à l'écran resterait rejouable
// pendant sa fenêtre de validité.
func ActivateMFA(db *sql.DB, username string, counter int64) error {
	res, err := db.Exec(`UPDATE users
		SET mfa_enabled = TRUE, mfa_enrolled_at = NOW(), mfa_last_counter = ?
		WHERE username = ? AND mfa_secret IS NOT NULL AND mfa_enabled = FALSE`,
		counter, username)
	if err != nil {
		logs.Write_LogCode("ERROR", logs.CodeDBQuery,
			"authpolicy: activation MFA de "+username+" échouée : "+err.Error())
		return fmt.Errorf("activation du second facteur : %w", err)
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return fmt.Errorf("aucun enrôlement en cours pour ce compte")
	}

	logs.Write_Log("SECURITY", "authpolicy: second facteur activé sur le compte "+username)
	return nil
}

// ResetMFA retire le second facteur d'un compte.
//
// Sert au déblocage — téléphone perdu ou remplacé — et est gardé côté appelant
// par write:mfa. Le secret est effacé et non conservé : un secret désactivé mais
// stocké resterait une clé valide si le drapeau venait à être remis par ailleurs.
func ResetMFA(db *sql.DB, username, resetBy string) error {
	_, err := db.Exec(`UPDATE users
		SET mfa_secret = NULL, mfa_enabled = FALSE, mfa_enrolled_at = NULL, mfa_last_counter = NULL
		WHERE username = ?`, username)
	if err != nil {
		logs.Write_LogCode("ERROR", logs.CodeDBQuery,
			"authpolicy: réinitialisation MFA de "+username+" échouée : "+err.Error())
		return fmt.Errorf("réinitialisation du second facteur : %w", err)
	}

	logs.Write_Log("SECURITY", fmt.Sprintf(
		"authpolicy: second facteur réinitialisé sur %s par %s", username, resetBy))
	return nil
}

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
