package client

import (
	"bytes"
	"strconv"
	"strings"
	"vaultaire/core/database"
	dbuser "vaultaire/core/database/db-user"
	gc "vaultaire/core/global/security"
	logs "vaultaire/core/logs"
	"vaultaire/core/permission"
	"vaultaire/core/storage"
	"vaultaire/ducky-network/ducky_tools"
	"vaultaire/ducky-network/sessionmgr"
)

// SendAuthRequest processes the authentication request from the client.
// It checks if the username is "vaultaire" and generates a challenge token for it.
// If the username is not "vaultaire", it retrieves the user ID, password hash, and salt from the database.
// It then compares the provided password with the stored hash using the salt.
// If the password matches, it generates a challenge token and stores the authentication data in storage.
// It returns a response string that includes the session integrity key, authID, and challenge token.
// If the username does not exist or the password is incorrect, it returns an error message.
func SendAuthRequest(trames_content storage.Trames_struct_client) string {
	// À ce stade, trames_content.SessionIntegritykey == duckysession.SessionID
	// (Rekey a déjà eu lieu pendant la poignée de main 01_01) : on peut
	// l'utiliser directement comme clé de corrélation dans les logs.
	meta := logs.WithMeta(trames_content.SessionIntegritykey, trames_content.Username)

	if trames_content.Username == "vaultaire" {
		token, alphaCheck := Generate_Challenge(trames_content.ClientSoftwareID)
		nouvelleAuth := storage.Authentification{
			RandomAuth:       token,
			AuthID:           alphaCheck,
			Username:         trames_content.Username,
			Password:         trames_content.Content,
			ClientSoftwareID: trames_content.ClientSoftwareID,
		}
		storeAuth(nouvelleAuth)
		logs.Write_LogCodeMeta("INFO", logs.CodeNone,
			trames_content.ClientSoftwareID+" try to login by auth server Has User = vaultaire", meta)
		return ("02_02\nserveur_central\n" + trames_content.SessionIntegritykey + "\n" + alphaCheck + "\n" + string(token))
	}
	// KILL SWITCH — refus avant toute évaluation du mot de passe.
	//
	// Le message renvoyé est le même que pour un mot de passe faux : un compte
	// révoqué ne doit pas se distinguer d'un compte inexistant vu du réseau,
	// sinon le kill switch devient un oracle qui confirme qu'un compte existe
	// et qu'il vient d'être coupé.
	if permission.IsRevoked(trames_content.Username) {
		logs.Write_LogCodeMeta("SECURITY", logs.CodeNone,
			trames_content.Username+" : tentative d'authentification sur un compte révoqué", meta)
		return ("02_07\nserveur_central\n" + trames_content.SessionIntegritykey + "\nWrong login Data")
	}

	user_ID, err := database.Get_User_ID_By_Username(database.GetDatabase(), trames_content.Username)
	if err != nil {
		logs.Write_LogCodeMeta("WARNING", logs.CodeNone, trames_content.Username+" try to login but user does not exist", meta)
		return ("02_07\nserveur_central\n" + trames_content.SessionIntegritykey + "\nWrong login Data")
	}
	Hpassword, salt, err := database.Get_User_Password_By_ID(database.GetDatabase(), user_ID)
	if err != nil {
		logs.Write_LogCodeMeta("WARNING", logs.CodeNone, trames_content.Username+" try to login but error for get password", meta)
		return ("02_07\nserveur_central\n" + trames_content.SessionIntegritykey + "\nWrong login Data")
	}
	if !gc.ComparePasswords(trames_content.Content, salt, Hpassword) {
		logs.Write_LogCodeMeta("WARNING", logs.CodeNone, trames_content.Username+" try to login but password is not correct", meta)
		return ("02_07\nserveur_central\n" + trames_content.SessionIntegritykey + "\nWrong login Data")
	}
	token, alphaCheck := Generate_Challenge(trames_content.ClientSoftwareID)
	if alphaCheck == "no" {
		logs.Write_LogCodeMeta("ERROR", logs.CodeNone, trames_content.Username+" try to login but error for generate challenge", meta)
		return ("02_07\nserveur_central\n" + trames_content.SessionIntegritykey + "\nAuth Failed please retry")
	}
	nouvelleAuth := storage.Authentification{
		RandomAuth:       token,
		AuthID:           alphaCheck,
		Username:         trames_content.Username,
		Password:         trames_content.Content,
		ClientSoftwareID: trames_content.ClientSoftwareID,
	}
	storeAuth(nouvelleAuth)
	logs.Write_LogCodeMeta("INFO", logs.CodeNone, nouvelleAuth.Username+" try to login", meta)
	return ("02_02\nserveur_central\n" + trames_content.SessionIntegritykey + "\n" + alphaCheck + "\n" + string(token))
}

// CheckAuth verifies the authentication challenge sent by the client.
// It reconstructs the message content from the received data, retrieves the random authentication data and username using the authID,
// and deletes the authentication entry from storage.
// If the username is "vaultaire", it adds the server to the online list and returns a success message.
// If the username is not "vaultaire", it compares the provided challenge with the stored random authentication data.
// If they match, it generates a session key, checks if the user can log in, and adds a login entry to the database.
// If the user can log in, it sends the GPO to the client and returns a success message with the session key.
// If the challenge does not match, it logs a warning and returns an error message indicating that the authentication failed.
func CheckAuth(trames_content storage.Trames_struct_client, duckysession *storage.DuckySession) string {
	meta := logs.WithMeta(duckysession.SessionID, trames_content.Username)

	message_reconstruction := strings.Split(trames_content.Content, "\n")
	message_content := storage.Authentification_Challenge_server{
		AuthID:    message_reconstruction[0],
		Challenge: strings.Join(message_reconstruction[1:], "\n"),
	}
	randomAuth, username := GetRandomAuthByAuthID(message_content.AuthID)

	// Garde-fou sur le cas vide.
	//
	// Un AuthID inconnu fait renvoyer (nil, "") par le store. Plus bas, la
	// comparaison est bytes.Equal(randomAuth, returnchack) : en Go,
	// bytes.Equal(nil, []byte("")) vaut true. Une trame 02_03 dont le contenu
	// est vide franchissait donc la comparaison du challenge avec un username
	// vide. Elle était arrêtée juste après par DidUserCanLogin — aucun
	// utilisateur ne porte le nom vide — mais elle l'était par accident, pas
	// par décision. On refuse explicitement.
	if message_content.AuthID == "" || len(randomAuth) == 0 || username == "" {
		logs.Write_LogCodeMeta("WARNING", logs.CodeNone,
			"Challenge d'authentification inconnu ou vide, trame 02_03 rejetée", meta)
		return ("02_07\nserveur_central\n" + trames_content.SessionIntegritykey + "\nYou are not authentificate")
	}

	if username == "vaultaire" {
		sessionmgr.Sessions.SetIdentity(duckysession.SessionID, username, trames_content.ClientSoftwareID)
		sessionmgr.Sessions.SetStatus(duckysession.SessionID, sessionmgr.SessionAuthenticated)
		addOnlineServerToTable(duckysession.SessionID, username, trames_content.ClientSoftwareID)
		db := database.GetDatabase()
		userID, _ := database.Get_User_ID_By_Username(db, username)
		database.AddLoginEntry(db, userID, []byte(trames_content.SessionIntegritykey), trames_content.ClientSoftwareID)
		logs.Write_LogCodeMeta("INFO", logs.CodeNone, trames_content.ClientSoftwareID+" is online and enter in the system", meta)
		return ("02_11\nserveur_central\n" + trames_content.SessionIntegritykey + "\n" + username + "\nclient_giveinformation")

	}

	returnchack := []byte(message_content.Challenge)
	if bytes.Equal(randomAuth, returnchack) {
		db := database.GetDatabase()
		userID, _ := database.Get_User_ID_By_Username(db, username)

		can, err := database.DidUserCanLogin(database.GetDatabase(), username, trames_content.ClientSoftwareID)
		if err != nil {
			logs.Write_LogCodeMeta("ERROR", logs.CodeNone, username+" try to login but error for get user can login", meta)
			return ("02_07\n" + trames_content.SessionIntegritykey + "\n" + username + "\nSomething go wrong contact you administrator")
		}
		if can {
			database.AddLoginEntry(db, userID, []byte(trames_content.SessionIntegritykey), trames_content.ClientSoftwareID)
			sessionmgr.Sessions.SetIdentity(duckysession.SessionID, username, trames_content.ClientSoftwareID)
			sessionmgr.Sessions.SetStatus(duckysession.SessionID, sessionmgr.SessionAuthenticated)
			logs.Write_LogCodeMeta("INFO", logs.CodeNone, username+" login with succes with clientsoftware "+trames_content.ClientSoftwareID, meta)
			admin, _ := database.IsUserAdmin(database.GetDatabase(), username, trames_content.ClientSoftwareID)
			if admin {
				logs.Write_LogCodeMeta("INFO", logs.CodeNone, username+" is admin for the client : "+trames_content.ClientSoftwareID, meta)
			}
			userpukey, err := dbuser.GetUserKeys(userID)
			if err != nil {
				logs.Write_LogCodeMeta("ERROR", logs.CodeNone,
					"Erreur lors de la récupération de la clé publique de l'utilisateur "+username+" : "+err.Error(), meta)
				return ("02_04\nserveur_central\n" + trames_content.SessionIntegritykey + "\n" + username + "\n" + strconv.FormatBool(admin) + "\n" + "empty" + "\nYou are authentificate Has : \n" + username)
			} else {
				publicKeys := ducky_tools.ExtractPublicKeys(userpukey)
				return ("02_04\nserveur_central\n" + trames_content.SessionIntegritykey + "\n" + username + "\n" + strconv.FormatBool(admin) + "\n" + publicKeys + "\nYou are authentificate Has : \n" + username)
			}

		} else {
			return ("02_07\nserveur_central\n" + trames_content.SessionIntegritykey + "\n" + username + "\nyou have not the authorisation for acces to this computeur")
		}

	} else {
		logs.Write_LogCodeMeta("WARNING", logs.CodeNone, username+" Does not have the permission for login to "+trames_content.ClientSoftwareID, meta)
		return ("02_07\nserveur_central\n" + trames_content.SessionIntegritykey + "\nYou are not authentificate")

	}
}
