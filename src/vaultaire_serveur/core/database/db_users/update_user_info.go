package dbusers

import (
	"database/sql"
	"errors"
	"fmt"
	"vaultaire/core/auth/passwordpolicy"
	database "vaultaire/core/database"
	dbdomains "vaultaire/core/database/db_domains"
	guardprotected "vaultaire/core/database/guard_protected"
	"vaultaire/core/logs"
)

func Update_User_Info(db *sql.DB, userID int, username, firstname, lastname, password, birthdate string) error {
	// Même séparation qu'à la création : identifiant en liste blanche, mot de
	// passe en texte libre.
	if err := database.SanitizeIdentifier(username); err != nil {
		return err
	}
	injection := database.SanitizeInput(password, birthdate)
	if injection != nil {
		return injection
	}

	// Le compte d'amorçage ne peut pas être renommé (son nom est câblé dans
	// l'authentification serveur et le bind LDAP). Le changement de mot de passe
	// reste autorisé : le compte naît avec un mot de passe par défaut connu,
	// bloquer sa rotation serait contre-productif. Voir protected.go.
	var currentUsername string
	if err := db.QueryRow(`SELECT username FROM users WHERE id_user = ?`, userID).Scan(&currentUsername); err != nil {
		if err == sql.ErrNoRows {
			return fmt.Errorf("utilisateur %d introuvable", userID)
		}
		logs.Write_LogCode("ERROR", logs.CodeDBQuery, "database: "+"Erreur lecture username courant: "+err.Error())
		return fmt.Errorf("erreur lecture de l'utilisateur %d: %v", userID, err)
	}
	if err := guardprotected.GuardProtectedUserRename(currentUsername, username); err != nil {
		return err
	}

	tx, err := db.Begin()
	if err != nil {
		logs.Write_LogCode("ERROR", logs.CodeDBQuery, "database: "+"Erreur début transaction update: "+err.Error())
		return fmt.Errorf("erreur début transaction: %v", err)
	}
	defer func() {
		if rerr := tx.Rollback(); rerr != nil && rerr != sql.ErrTxDone {
			// Log rollback failure (don't usually return it, because the main err is more important)
			logs.Write_LogCode("ERROR", logs.CodeDBQuery, "database: "+"Erreur rollback transaction update: "+rerr.Error())
		}
	}()

	// Récupérer domaine principal depuis les groupes de l'utilisateur
	mainDomain, err := dbdomains.GetUserMainDomain(db, userID)
	if err != nil {
		logs.Write_LogCode("ERROR", logs.CodeDBQuery, "database: "+"Erreur récupération domaine principal: "+err.Error())
		return fmt.Errorf("erreur récupération domaine principal: %v", err)
	}

	email := fmt.Sprintf("%s@%s", username, mainDomain)

	var (
		hashHex string
		saltHex string
	)

	if password != "" {
		// Un changement de mot de passe produit toujours une empreinte argon2id,
		// quel que soit le format de celle qu'il remplace. C'est le second chemin
		// de migration, en plus du réencodage à la connexion : qui change son mot
		// de passe quitte le SHA-256 par ce seul geste.
		//
		// PreparerNouveauMotDePasse et non security.Hacher : le contrôle de
		// robustesse (TO-DO 100) est adossé au hachage, pas recopié dans chaque
		// façade. Ce chemin-ci est emprunté par la page profil, la page
		// d'administration et le CLI ; les brancher un à un aurait laissé le
		// quatrième dehors.
		var err error
		hashHex, saltHex, err = passwordpolicy.PreparerNouveauMotDePasse(db, username, password)
		if err != nil {
			// Un refus de robustesse n'est PAS une erreur de base : il est rendu
			// tel quel pour que son message atteigne celui qui tape, et il n'est
			// pas journalisé en ERROR — PreparerNouveauMotDePasse l'a déjà noté.
			var faible *passwordpolicy.ErreurRobustesse
			if errors.As(err, &faible) {
				return faible
			}
			logs.Write_LogCode("ERROR", logs.CodeDBQuery, "database: "+"Erreur hachage du mot de passe: "+err.Error())
			return fmt.Errorf("erreur hachage du mot de passe: %v", err)
		}
	}

	if password != "" {
		// password_changed_at est remis à jour DANS LA MÊME REQUÊTE que le mot de
		// passe.
		//
		// Un appel séparé après coup — TouchPasswordChanged — aurait marché, et
		// aurait fini par être oublié : ce chemin est appelé depuis la page profil,
		// la page d'administration et le CLI, et rien n'aurait signalé l'oubli. Un
		// compte se serait retrouvé avec un mot de passe changé mais toujours
		// marqué expiré, donc renvoyé sur la page de changement en boucle.
		// Ici, changer le mot de passe sans changer la date est impossible.
		_, err = tx.Exec(`
		UPDATE users
		SET username = ?, firstname = ?, lastname = ?, email = ?, password = ?, salt = ?, password_changed_at = NOW()
		WHERE id_user = ?`,
			username, firstname, lastname, email, hashHex, saltHex, userID)
	} else {
		_, err = tx.Exec(`
		UPDATE users
		SET username = ?, firstname = ?, lastname = ?, email = ?
		WHERE id_user = ?`,
			username, firstname, lastname, email, userID)
	}

	if err != nil {
		logs.Write_LogCode("ERROR", logs.CodeDBQuery, "database: "+"Erreur update user: "+err.Error())
		return fmt.Errorf("erreur update: %v", err)
	}

	if err = tx.Commit(); err != nil {
		logs.Write_LogCode("ERROR", logs.CodeDBQuery, "database: "+"Erreur commit update: "+err.Error())
		return fmt.Errorf("erreur commit: %v", err)
	}

	return nil
}
