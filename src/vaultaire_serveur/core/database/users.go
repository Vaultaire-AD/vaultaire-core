package database

import (
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"fmt"
	"vaultaire/core/logs"
	"vaultaire/core/storage"
	"vaultaire/core/tools"

	_ "github.com/go-sql-driver/mysql"
)

func Create_New_User(db *sql.DB, username, firstname, lastname, email, password, salt, birthdate, createdAt string) error {
	// Le nom d'utilisateur nomme une entité : liste blanche. Le mot de passe est
	// du texte libre et doit le rester — y interdire espaces et parenthèses
	// affaiblirait les mots de passe au lieu de protéger la base.
	if err := SanitizeIdentifier(username); err != nil {
		return err
	}
	injection := SanitizeInput(password, birthdate)
	if injection != nil {
		return injection
	}

	tx, err := db.Begin()
	if err != nil {
		logs.WriteLog("db", "erreur lors du début de la transaction: "+err.Error())
		return fmt.Errorf("erreur lors du début de la transaction: %v", err)
	}

	defer func() {
		if rerr := tx.Rollback(); rerr != nil && rerr != sql.ErrTxDone {
			// Log rollback failure (don't usually return it, because the main err is more important)
			logs.WriteLog("db", "erreur lors du rollback de la transaction: "+rerr.Error())
		}
	}()

	birthdate, err = tools.StringToDate(birthdate)
	if err != nil {
		logs.WriteLog("date", "Date de naissance invalide: "+err.Error())
		return fmt.Errorf("format de date invalide: %v", err)
	}
	// 1. Insérer un nouvel utilisateur dans la table users
	//
	// password_changed_at est posé dès la création, et non laissé à NULL.
	// Le rattrapage du schéma (db_authpolicy) ne s'exécute qu'au démarrage : un
	// compte créé ensuite garderait une date nulle jusqu'au prochain
	// redémarrage, donc un mot de passe qui n'expire jamais. Le trou serait
	// invisible — le compte fonctionne — et ne se refermerait qu'au hasard des
	// redémarrages.
	_, err = tx.Exec(`
		INSERT INTO users (username, firstname, lastname, email, password, salt, date_naissance, created_at, password_changed_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`, username, firstname, lastname, email, password, salt, birthdate, createdAt, createdAt)
	if err != nil {
		logs.WriteLog("db", "erreur lors de l'insertion de l'utilisateur: "+err.Error())
		return fmt.Errorf("erreur lors de l'insertion de l'utilisateur: %v", err)
	}

	err = tx.Commit()
	if err != nil {
		logs.WriteLog("db", "erreur lors de la validation de la transaction: "+err.Error())
		return fmt.Errorf("erreur lors de la validation de la transaction: %v", err)
	}

	return nil
}

// Command_Remove_User supprime un utilisateur et toutes ses relations
func Command_DELETE_UserWithUsername(db *sql.DB, username string) error {
	injection := SanitizeIdentifier(username)
	if injection != nil {
		return injection
	}
	// Le compte d'amorçage n'est pas supprimable : voir protected.go.
	if err := GuardProtectedUserDeletion(username); err != nil {
		return err
	}
	// Vérifier si l'utilisateur existe
	userID, found, err := LookupUserID(db, username)
	if err != nil {
		logs.WriteLog("db", "Erreur lors de la récupération de l'utilisateur : "+err.Error())
		return fmt.Errorf("erreur lors de la récupération de l'utilisateur : %v", err)
	}
	if !found {
		logs.Write_LogCode("WARNING", logs.CodeDBUserNotFound, fmt.Sprintf("database: Utilisateur %s introuvable", username))
		return fmt.Errorf("utilisateur %s introuvable", username)
	}

	// Supprimer l'utilisateur (les contraintes ON DELETE CASCADE s'occupent du reste)
	queryDelete := `DELETE FROM users WHERE id_user = ?`
	_, err = db.Exec(queryDelete, userID)
	if err != nil {
		logs.WriteLog("db", "Erreur lors de la suppression de l'utilisateur : "+err.Error())
		return fmt.Errorf("erreur lors de la suppression de l'utilisateur : %v", err)
	}

	logs.Write_LogCode("DEBUG", logs.CodeNone, fmt.Sprintf("database: Utilisateur %s supprimé avec succès", username))
	return nil
}

func Command_GET_AllUsers(db *sql.DB) ([]storage.GetUsers, error) {
	// Requête SQL pour récupérer tous les utilisateurs
	query := `
		SELECT 
			u.id_user, 
			u.username, 
			u.date_naissance, 
			u.created_at
		FROM 
			users u
	`

	// Exécution de la requête SQL
	rows, err := db.Query(query)
	if err != nil {
		logs.WriteLog("db", "Erreur lors de l'exécution de la requête : "+err.Error())
		return nil, fmt.Errorf("erreur lors de l'exécution de la requête : %v", err)
	}
	defer func() {
		if err := rows.Close(); err != nil {
			// Handle or log the error
			logs.Write_Log("ERROR", "Error closing connection: "+err.Error())
		}
	}()

	// Déclaration d'une slice pour stocker les résultats
	var users []storage.GetUsers
	for rows.Next() {
		// Structure pour stocker un utilisateur
		var user storage.GetUsers
		// Scan des résultats de la requête dans la structure
		if err := rows.Scan(&user.ID, &user.Username, &user.DateNaissance, &user.CreatedAt); err != nil {
			logs.WriteLog("db", "Erreur lors du scan des résultats : "+err.Error())
			return nil, fmt.Errorf("erreur lors du scan des résultats : %v", err)
		}
		// Ajout de l'utilisateur à la slice
		users = append(users, user)
	}

	// Vérifier s'il y a une erreur d'itération des résultats
	if err = rows.Err(); err != nil {
		logs.WriteLog("db", "Erreur lors de l'itération des résultats : "+err.Error())
		return nil, fmt.Errorf("erreur lors de l'itération des résultats : %v", err)
	}

	// Retourner les utilisateurs récupérés
	return users, nil
}

func Command_GET_UserInfo(db *sql.DB, username string) (*storage.GetUserInfoSingle, error) {
	injection := SanitizeIdentifier(username)
	if injection != nil {
		return nil, injection
	}

	query := `
		SELECT 
			u.username,
			u.firstname,
			u.lastname,
			u.email,
			COALESCE(DATE_FORMAT(u.date_naissance, '%Y-%m-%d'), '') AS date_naissance, 
			COALESCE(g.group_name, '') AS group_name, 
			CASE WHEN dl.d_id_user IS NOT NULL THEN TRUE ELSE FALSE END AS is_connected
		FROM users u
		LEFT JOIN users_group ug ON u.id_user = ug.d_id_user
		LEFT JOIN groups g ON ug.d_id_group = g.id_group
		LEFT JOIN did_login dl ON u.id_user = dl.d_id_user
		WHERE u.username = ?;
	`

	rows, err := db.Query(query, username)
	if err != nil {
		logs.WriteLog("db", "Erreur lors de l'exécution de la requête : "+err.Error())
		return nil, fmt.Errorf("erreur lors de l'exécution de la requête : %v", err)
	}
	defer func() {
		if err := rows.Close(); err != nil {
			// Handle or log the error
			logs.Write_Log("ERROR", "Error closing connection: "+err.Error())
		}
	}()

	var userInfo storage.GetUserInfoSingle
	userInfo.Username = username
	groupsSet := make(map[string]bool)
	isConnected := false

	for rows.Next() {
		var groupName, dateNaissance string
		var connected bool

		// Récupérer tous les champs
		err := rows.Scan(
			&userInfo.Username,
			&userInfo.Firstname,
			&userInfo.Lastname,
			&userInfo.Email,
			&dateNaissance,
			&groupName,
			&connected,
		)
		if err != nil {
			logs.WriteLog("db", "Erreur lors du scan des résultats : "+err.Error())
			return nil, fmt.Errorf("erreur lors du scan des résultats : %v", err)
		}

		userInfo.DateOfBirth = dateNaissance
		if groupName != "" {
			groupsSet[groupName] = true
		}
		if connected {
			isConnected = true
		}
	}

	for g := range groupsSet {
		userInfo.Groups = append(userInfo.Groups, g)
	}
	userInfo.Connected = isConnected

	if err = rows.Err(); err != nil {
		logs.WriteLog("db", "Erreur lors de l'itération des résultats : "+err.Error())
		return nil, fmt.Errorf("erreur lors de l'itération des résultats : %v", err)
	}

	if userInfo.Username == "" {
		logs.Write_LogCode("DEBUG", logs.CodeNone, "database: Aucun utilisateur trouvé avec le username : "+username)
		return nil, fmt.Errorf("aucun utilisateur trouvé avec le username '%s'", username)
	}

	return &userInfo, nil
}

// Fonction pour générer un salt aléatoire
func generateSalt(length int) ([]byte, error) {
	salt := make([]byte, length)
	_, err := rand.Read(salt)
	return salt, err
}

func Update_User_Info(db *sql.DB, userID int, username, firstname, lastname, password, birthdate string) error {
	// Même séparation qu'à la création : identifiant en liste blanche, mot de
	// passe en texte libre.
	if err := SanitizeIdentifier(username); err != nil {
		return err
	}
	injection := SanitizeInput(password, birthdate)
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
		logs.WriteLog("db", "Erreur lecture username courant: "+err.Error())
		return fmt.Errorf("erreur lecture de l'utilisateur %d: %v", userID, err)
	}
	if err := GuardProtectedUserRename(currentUsername, username); err != nil {
		return err
	}

	tx, err := db.Begin()
	if err != nil {
		logs.WriteLog("db", "Erreur début transaction update: "+err.Error())
		return fmt.Errorf("erreur début transaction: %v", err)
	}
	defer func() {
		if rerr := tx.Rollback(); rerr != nil && rerr != sql.ErrTxDone {
			// Log rollback failure (don't usually return it, because the main err is more important)
			logs.WriteLog("db", "Erreur rollback transaction update: "+rerr.Error())
		}
	}()

	// Récupérer domaine principal depuis les groupes de l'utilisateur
	mainDomain, err := GetUserMainDomain(db, userID)
	if err != nil {
		logs.WriteLog("db", "Erreur récupération domaine principal: "+err.Error())
		return fmt.Errorf("erreur récupération domaine principal: %v", err)
	}

	email := fmt.Sprintf("%s@%s", username, mainDomain)

	var (
		hashHex string
		saltHex string
	)

	if password != "" {
		salt, err := generateSalt(16)
		if err != nil {
			logs.WriteLog("auth", "Erreur génération salt: "+err.Error())
			return fmt.Errorf("erreur génération salt: %v", err)
		}
		saltHex = hex.EncodeToString(salt)

		saltedPassword := append(salt, []byte(password)...)
		hash := sha256.Sum256(saltedPassword)
		hashHex = hex.EncodeToString(hash[:])
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
		logs.WriteLog("db", "Erreur update user: "+err.Error())
		return fmt.Errorf("erreur update: %v", err)
	}

	if err = tx.Commit(); err != nil {
		logs.WriteLog("db", "Erreur commit update: "+err.Error())
		return fmt.Errorf("erreur commit: %v", err)
	}

	return nil
}

func Get_User_ID_By_Username(db *sql.DB, username string) (int, error) {
	injection := SanitizeIdentifier(username)
	if injection != nil {
		return 0, injection
	}
	userID, found, err := LookupUserID(db, username)
	if err != nil {
		logs.Write_LogCode("ERROR", logs.CodeDBQuery, "récupération ID utilisateur: "+err.Error())
		return 0, fmt.Errorf("erreur lors de la récupération de l'ID utilisateur: %v", err)
	}
	if !found {
		logs.Write_LogCode("WARNING", logs.CodeDBUserNotFound, "utilisateur non trouvé "+username)
		return 0, fmt.Errorf("utilisateur non trouvé")
	}

	return userID, nil
}

func Get_User_Password_By_ID(db *sql.DB, id int) (string, string, error) {
	var password string
	var salt string
	query := `SELECT password, salt FROM users WHERE id_user = ?`

	err := db.QueryRow(query, id).Scan(&password, &salt)
	if err != nil {
		if err == sql.ErrNoRows {
			logs.WriteLog("db", "utilisateur non trouvé "+err.Error())
			return "", "", fmt.Errorf("utilisateur non trouvé")
		}
		logs.WriteLog("db", "erreur lors de la récupération de l'ID utilisateur: "+err.Error())
		return "", "", fmt.Errorf("erreur lors de la récupération de l'ID utilisateur: %v", err)
	}

	return password, salt, nil
}

// Get_User_Salt_By_ID récupère le salt d'un utilisateur en fonction de son ID
func Get_User_Salt_By_UserID(db *sql.DB, userID int) (string, error) {
	var salt string
	query := `SELECT salt FROM users WHERE id_user = ?`

	err := db.QueryRow(query, userID).Scan(&salt)
	if err != nil {
		if err == sql.ErrNoRows {
			logs.Write_LogCode("WARNING", logs.CodeDBUserNotFound, fmt.Sprintf("utilisateur non trouvé pour l'ID: %d", userID))
			return "", fmt.Errorf("utilisateur non trouvé")
		}
		logs.Write_LogCode("ERROR", logs.CodeDBQuery, fmt.Sprintf("récupération salt utilisateur ID %d: %s", userID, err.Error()))
		return "", fmt.Errorf("erreur lors de la récupération du salt utilisateur: %v", err)
	}

	return salt, nil
}

func Get_User_PasswordHash_By_UserID(db *sql.DB, userID int) (string, error) {
	var passwordHash string
	query := `SELECT password FROM users WHERE id_user = ?`

	err := db.QueryRow(query, userID).Scan(&passwordHash)
	if err != nil {
		if err == sql.ErrNoRows {
			logs.Write_LogCode("WARNING", logs.CodeDBUserNotFound, fmt.Sprintf("utilisateur non trouvé pour l'ID: %d", userID))
			return "", fmt.Errorf("utilisateur non trouvé")
		}
		logs.Write_LogCode("ERROR", logs.CodeDBQuery, fmt.Sprintf("récupération password hash utilisateur ID %d: %s", userID, err.Error()))
		return "", fmt.Errorf("erreur lors de la récupération du password hash: %v", err)
	}

	return passwordHash, nil
}

func Get_PublicKeys_ByUserID(db *sql.DB, userID int) ([]string, error) {
	query := `SELECT public_key FROM user_public_keys WHERE id_user = ?`

	rows, err := db.Query(query, userID)
	if err != nil {
		return nil, fmt.Errorf("erreur requête DB: %w", err)
	}
	defer rows.Close()

	var keys []string

	for rows.Next() {
		var key string
		if err := rows.Scan(&key); err != nil {
			return nil, fmt.Errorf("erreur scan clé publique: %w", err)
		}
		keys = append(keys, key)
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("erreur itération rows: %w", err)
	}

	if len(keys) == 0 {
		return nil, fmt.Errorf("aucune clé publique pour l'utilisateur %d", userID)
	}

	return keys, nil
}

// Vérifie si un utilisateur peut se connecter avec un client (partage un groupe ou une permission)
func DidUserCanLogin(db *sql.DB, username, computeur_id string) (bool, error) {
	injection := SanitizeIdentifier(username, computeur_id)
	if injection != nil {
		return false, injection
	}
	// Récupère l'ID de l'utilisateur basé sur le username
	userID, found, err := LookupUserID(db, username)
	if err != nil {
		logs.WriteLog("db", "Erreur lors de la récupération de l'ID utilisateur: "+err.Error())
		return false, err
	}
	if !found {
		logs.Write_LogCode("WARNING", logs.CodeDBUserNotFound, "database: Utilisateur non trouvé: "+username)
		return false, fmt.Errorf("utilisateur non trouvé")
	}

	// Vérification si l'utilisateur et l'ordinateur partagent un groupe via `users_group` et `logiciel_group`
	var canLogin bool
	query := `SELECT 1 FROM users_group
			 JOIN logiciel_group ON users_group.d_id_group = logiciel_group.d_id_group
			 JOIN id_logiciels ON logiciel_group.d_id_logiciel = id_logiciels.id_logiciel
			 WHERE users_group.d_id_user = ? AND id_logiciels.computeur_id = ? LIMIT 1`
	err = db.QueryRow(query, userID, computeur_id).Scan(&canLogin)
	if err == nil && canLogin {
		return true, nil
	} else if err != sql.ErrNoRows {
		logs.WriteLog("db", "Erreur lors de la vérification du groupe partagé: "+err.Error())
		return false, err
	}

	// Si aucune correspondance n'est trouvée
	logs.WriteLog("WARNING", "L'utilisateur "+username+" ne peut pas se connecter avec ce client "+computeur_id)
	return false, nil
}

// Vérifie si un utilisateur est admin par rapport à un client spécifique
func IsUserAdmin(db *sql.DB, username, computeur_id string) (bool, error) {
	injection := SanitizeIdentifier(username, computeur_id)
	if injection != nil {
		return false, injection
	}
	// Récupérer l'ID utilisateur
	userID, found, err := LookupUserID(db, username)
	if err != nil {
		logs.WriteLog("db", "Erreur lors de la récupération de l'ID utilisateur: "+err.Error())
		return false, err
	}
	if !found {
		logs.Write_LogCode("WARNING", logs.CodeDBUserNotFound, "database: Utilisateur non trouvé: "+username)
		return false, fmt.Errorf("utilisateur non trouvé")
	}

	// Récupérer l'ID du logiciel associé au client
	logicielID, found, err := LookupClientID(db, computeur_id)
	if err != nil {
		logs.WriteLog("db", "Erreur lors de la récupération de l'ID logiciel: "+err.Error())
		return false, err
	}
	if !found {
		logs.Write_LogCode("WARNING", logs.CodeDBGeneric, "database: Client non trouvé: "+computeur_id)
		return false, fmt.Errorf("client non trouvé")
	}

	// --- Suppression de la vérification directe de permission utilisateur avec le logiciel ---

	// Vérifier si l'utilisateur et le logiciel sont dans un même groupe ayant une permission admin
	query := `
		SELECT 1
FROM users_group AS ug
JOIN logiciel_group AS lg ON ug.d_id_group = lg.d_id_group
JOIN group_permission_logiciel AS gpl ON lg.d_id_group = gpl.d_id_group
JOIN client_permission AS p ON gpl.d_id_permission = p.id_permission
WHERE ug.d_id_user = ? AND lg.d_id_logiciel = ? AND p.is_admin = TRUE
LIMIT 1
`
	err = db.QueryRow(query, userID, logicielID).Scan(new(int))
	if err == nil {
		logs.Write_LogCode("DEBUG", logs.CodeNone, "database: Utilisateur "+username+" est admin via un groupe commun avec le client.")
		return true, nil
	} else if err != sql.ErrNoRows {
		logs.WriteLog("db", "Erreur lors de la vérification des permissions de groupe: "+err.Error())
		return false, err
	}

	// Si aucune condition d'admin n'est remplie
	logs.Write_LogCode("DEBUG", logs.CodeNone, "database: Utilisateur "+username+" n'a pas de permission admin.")
	return false, nil
}
