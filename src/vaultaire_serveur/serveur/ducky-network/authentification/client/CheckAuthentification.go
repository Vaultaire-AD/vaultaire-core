package client

import (
	"vaultaire/serveur/database"
	dbuser "vaultaire/serveur/database/db-user"
	"vaultaire/serveur/ducky-network/ducky_tools"
	gc "vaultaire/serveur/global/security"
	logs "vaultaire/serveur/logs"
	"vaultaire/serveur/storage"
	"strconv"

	//"vaultaire/serveur/logs"
	"bytes"
	"crypto/rand"
	"strings"
)

// GetRandomAuthByAuthID retrieves the random authentication data and username for a given authID.
// It removes the authentication entry from storage after retrieval.
// If the authID is not found, it returns nil and an empty string.
// This function is used to manage the authentication process by matching the authID with the stored authentication data.
func GetRandomAuthByAuthID(authIDToFind string) ([]byte, string) {
	for i, auth := range storage.StorageAuth {
		if auth.AuthID == authIDToFind {
			randomAuth := auth.RandomAuth
			username := auth.Username
			storage.StorageAuth = append(storage.StorageAuth[:i], storage.StorageAuth[i+1:]...)
			return randomAuth, username
		}
	}
	return nil, ""
}

// DeleteAuthByID removes the authentication entry with the specified authID from storage.
// This function is used to clean up the authentication storage after a successful authentication or when an auth entry is no longer needed.
// It iterates through the storage and removes the entry that matches the given authID.
// If the authID is not found, it does nothing.
// This helps in managing the authentication lifecycle and ensuring that only valid authentication entries are kept in storage.
// It is important to ensure that the authID is unique to avoid accidental deletions.
func DeleteAuthByID(authID string) {
	for i, auth := range storage.StorageAuth {
		if auth.AuthID == authID {
			// Supprime l'élément à l'index i
			storage.StorageAuth = append(storage.StorageAuth[:i], storage.StorageAuth[i+1:]...)
			break
		}
	}
}

// SendAuthRequest processes the authentication request from the client.
// It checks if the username is "vaultaire" and generates a challenge token for it.
// If the username is not "vaultaire", it retrieves the user ID, password hash, and salt from the database.
// It then compares the provided password with the stored hash using the salt.
// If the password matches, it generates a challenge token and stores the authentication data in storage.
// It returns a response string that includes the session integrity key, authID, and challenge token.
// If the username does not exist or the password is incorrect, it returns an error message.
func SendAuthRequest(trames_content storage.Trames_struct_client) string {
	if trames_content.Username == "vaultaire" {
		token, alphaCheck := Generate_Challenge(trames_content.ClientSoftwareID)
		nouvelleAuth := storage.Authentification{
			RandomAuth:       token,
			AuthID:           alphaCheck,
			Username:         trames_content.Username,
			Password:         trames_content.Content,
			ClientSoftwareID: trames_content.ClientSoftwareID,
		}
		storage.StorageAuth = append(storage.StorageAuth, nouvelleAuth)
		logs.Write_Log("INFO", trames_content.ClientSoftwareID+" try to login by auth server Has User = vaultaire")
		//fmt.Println("User : " + nouvelleAuth.Username + " try to login")
		return ("02_02\nserveur_central\n" + trames_content.SessionIntegritykey + "\n" + alphaCheck + "\n" + string(token))
	}
	user_ID, err := database.Get_User_ID_By_Username(database.GetDatabase(), trames_content.Username)
	if err != nil {
		logs.Write_Log("WARNING", trames_content.Username+" try to login but user does not exist")
		return ("02_07\nserveur_central\n" + trames_content.SessionIntegritykey + "\nWrong login Data")
	}
	Hpassword, salt, err := database.Get_User_Password_By_ID(database.GetDatabase(), user_ID)
	if err != nil {
		logs.Write_Log("WARNING", trames_content.Username+" try to login but error for get password")
		return ("02_07\nserveur_central\n" + trames_content.SessionIntegritykey + "\nWrong login Data")
	}
	if !gc.ComparePasswords(trames_content.Content, salt, Hpassword) {
		logs.Write_Log("WARNING", trames_content.Username+" try to login but password is not correct")
		return ("02_07\nserveur_central\n" + trames_content.SessionIntegritykey + "\nWrong login Data")
	}
	token, alphaCheck := Generate_Challenge(trames_content.ClientSoftwareID)
	if alphaCheck == "no" {
		logs.Write_Log("ERROR", trames_content.Username+" try to login but error for generate challenge")
		return ("02_07\nserveur_central\n" + trames_content.SessionIntegritykey + "\nAuth Failed please retry")
	}
	nouvelleAuth := storage.Authentification{
		RandomAuth:       token,
		AuthID:           alphaCheck,
		Username:         trames_content.Username,
		Password:         trames_content.Content,
		ClientSoftwareID: trames_content.ClientSoftwareID,
	}
	storage.StorageAuth = append(storage.StorageAuth, nouvelleAuth)
	logs.Write_Log("INFO", nouvelleAuth.Username+" try to login")
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
	message_reconstruction := strings.Split(trames_content.Content, "\n")
	message_content := storage.Authentification_Challenge_server{
		AuthID:    message_reconstruction[0],
		Challenge: strings.Join(message_reconstruction[1:], "\n"),
	}
	randomAuth, username := GetRandomAuthByAuthID(message_content.AuthID)
	DeleteAuthByID(message_content.AuthID)
	if username == "vaultaire" {
		addOnlineServerToTable(username, trames_content.ClientSoftwareID, trames_content.SessionIntegritykey, duckysession)
		db := database.GetDatabase()
		userID, _ := database.Get_User_ID_By_Username(db, username)
		key := make([]byte, 8)
		database.AddLoginEntry(db, userID, key, trames_content.ClientSoftwareID)
		logs.Write_Log("INFO", trames_content.ClientSoftwareID+" is online and enter in the system")
		return ("02_11\nserveur_central\n" + trames_content.SessionIntegritykey + "\n" + username + "\nclient_giveinformation")

	}

	returnchack := []byte(message_content.Challenge)
	if bytes.Equal(randomAuth, returnchack) {
		db := database.GetDatabase()
		userID, _ := database.Get_User_ID_By_Username(db, username)
		key := make([]byte, 32)
		_, err := rand.Read(key)
		if err != nil {
			logs.Write_Log("ERROR", " Erreur lors de la clé de session : "+err.Error())
			return ("erreur lors de la génération de données aléatoires : ")
		}

		can, err := database.DidUserCanLogin(database.GetDatabase(), username, trames_content.ClientSoftwareID)
		if err != nil {
			logs.Write_Log("ERROR", username+" try to login but error for get user can login")
			return ("02_07\nSomething go wrong contact you administrator")
		}
		if can {
			database.AddLoginEntry(db, userID, key, trames_content.ClientSoftwareID)
			logs.Write_Log("INFO", username+" login with succes with clientsoftware "+trames_content.ClientSoftwareID)
			admin, _ := database.IsUserAdmin(database.GetDatabase(), username, trames_content.ClientSoftwareID)
			if admin {
				logs.Write_Log("INFO", username+" is admin for the client : "+trames_content.ClientSoftwareID)
			}
			userpukey, err := dbuser.GetUserKeys(userID)
			if err != nil {
				logs.Write_Log("ERROR", "Erreur lors de la récupération de la clé publique de l'utilisateur "+username+" : "+err.Error())
				return ("02_04\nserveur_central\n" + trames_content.SessionIntegritykey + "\n" + username + "\n" + strconv.FormatBool(admin) + "\n" + "empty" + "\nYou are authentificate Has : \n" + username + "\n" + string(key))
			} else {
				publicKeys := ducky_tools.ExtractPublicKeys(userpukey)
				return ("02_04\nserveur_central\n" + trames_content.SessionIntegritykey + "\n" + username + "\n" + strconv.FormatBool(admin) + "\n" + publicKeys + "\nYou are authentificate Has : \n" + username + "\n" + string(key))
			}

		} else {
			return ("02_07\nserveur_central\n" + trames_content.SessionIntegritykey + "\n" + username + "you have not the authorisation for acces to this computeur")
		}

	} else {
		logs.Write_Log("WARNING", username+" Does not have the permission for login to "+trames_content.ClientSoftwareID)
		return ("02_07\nserveur_central\n" + trames_content.SessionIntegritykey + "\nYou are not authentificate")

	}
}
