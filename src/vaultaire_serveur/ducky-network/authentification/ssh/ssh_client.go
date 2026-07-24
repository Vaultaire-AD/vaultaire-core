package sshclient

import (
	"strings"
	"vaultaire/core/database"
	gc "vaultaire/core/global/security"
	"vaultaire/core/logs"
	"vaultaire/core/storage"
)

func SSH_Client_Manager(trames_content storage.Trames_struct_client, duckysession *storage.DuckySession) string {
	message := ""
	switch trames_content.Message_Order[1] {
	case "01":
		message = SSH_SEND_Pubkey_AUTH(trames_content)
	case "04":
		message = SSH_SEND_SALT(trames_content)
	default:

	}
	return message
}

func SSH_SEND_Pubkey_AUTH(trames_content storage.Trames_struct_client) string {
	content := strings.Split(trames_content.Content, "\n")
	if len(content) < 3 {
		logs.Write_Log("ERROR", "Malformed SSH pubkey request")
		return "02_07\nserveur_central\n" +
			trames_content.SessionIntegritykey + "\n" + trames_content.Username + "\ninvalid request"
	}

	order := content[0]
	sshUser := content[1]
	password := content[2]

	db := database.GetDatabase()

	// 1. Récupérer l'ID de l'utilisateur
	userID, err := database.Get_User_ID_By_Username(db, sshUser)
	if err != nil {
		logs.Write_Log("ERROR", "User not found: "+sshUser)
		return "03_03\nserveur_central\n" + trames_content.SessionIntegritykey + "\n" + sshUser + "\nuser not found"
	}
	// 2. 🔐 VÉRIFICATION DU MOT DE PASSE (MFA)
	hPassword, salt, err := database.Get_User_Password_By_ID(db, userID)
	if err != nil {
		logs.Write_Log("ERROR", "Password lookup failed for "+sshUser)
		return "03_03\nserveur_central\n" + trames_content.SessionIntegritykey + "\n" + sshUser + "\ninternal error"
	}
	// On utilise ta fonction de comparaison (GC = ton package de crypto/auth)
	if !gc.ComparePasswords(password, salt, hPassword) {
		logs.Write_Log("WARNING", "MFA Failed: Invalid password for "+sshUser)
		return "03_03\nserveur_central\n" + trames_content.SessionIntegritykey + "\n" + sshUser + "\ninvalid credentials"
	}

	// 3. VÉRIFICATION DES DROITS (Peut-il se connecter sur cette machine ?)
	can, err := database.DidUserCanLogin(db, sshUser, trames_content.ClientSoftwareID)
	if err != nil || !can {
		logs.Write_Log("WARNING", sshUser+" permission denied for machine "+trames_content.ClientSoftwareID)
		return "03_03\nserveur_central\n" + trames_content.SessionIntegritykey + "\n" + sshUser + "\npermission denied"
	}

	// 4. RÉCUPÉRATION DES CLÉS ET DU STATUT ADMIN
	if order == "ask_sshpubkey" {
		// Check Admin
		isAdmin, _ := database.IsUserAdmin(db, sshUser, trames_content.ClientSoftwareID)

		// Check Pubkeys
		pubkeys, err := database.Get_PublicKeys_ByUserID(db, userID)
		if err != nil {
			return "03_03\nserveur_central\n" + trames_content.SessionIntegritykey + "\nkey error"
		}

		pubkeyStr := strings.Join(pubkeys, "\n")

		// On forge la réponse 03_02 (Succès)
		// Format : Status | User | IsAdmin | Keys...
		adminFlag := "false"
		if isAdmin {
			adminFlag = "true"
		}

		logs.Write_Log("INFO", "MFA Success: "+sshUser+" authorized on "+trames_content.ClientSoftwareID+" (Admin: "+adminFlag+")")

		return "03_02\nserveur_central\n" + trames_content.SessionIntegritykey + "\n" + sshUser + "\n" + adminFlag + "\n" + pubkeyStr
	}
	return "03_03\nserveur_central\n" + trames_content.SessionIntegritykey + "\n" + trames_content.Username + "\nunknown order"
}

func SSH_SEND_SALT(trames_content storage.Trames_struct_client) string {

	content := strings.Split(trames_content.Content, "\n")
	if len(content) < 1 {
		logs.Write_Log("ERROR", "Trame SSH 03_04 invalide : contenu incomplet")
		return "03_03\nserveur_central\n" + trames_content.SessionIntegritykey + "\n" + "vaultaire" + "\nmalformed_trame"
	}
	// Logique : Le client demande les clés publiques pour l'utilisateur X
	username := content[0]
	db := database.GetDatabase()

	// 3. VÉRIFICATION DES DROITS (Peut-il se connecter sur cette machine ?)
	can, err := database.DidUserCanLogin(db, username, trames_content.ClientSoftwareID)
	if err != nil || !can {
		logs.Write_Log("WARNING", username+" permission denied for machine "+trames_content.ClientSoftwareID)
		return "03_03\nserveur_central\n" + trames_content.SessionIntegritykey + "\n" + username + "\npermission denied"
	}

	id, err := database.Get_User_ID_By_Username(db, username)
	if err != nil {
		logs.Write_Log("ERROR", "User not found: "+username)
		return "03_03\nserveur_central\n" + trames_content.SessionIntegritykey + "\n" + "vaultaire" + "\nuser not found"
	}
	salt, err := database.Get_User_Salt_By_UserID(db, id)
	if err != nil {
		logs.Write_Log("ERROR", "Error retrieving salt for user "+username)
		return "03_03\nserveur_central\n" + trames_content.SessionIntegritykey + "\n" + "vaultaire" + "\n" + "salt error"
	}
	nonce, err := IssueChallenge(trames_content.SessionIntegritykey)
	if err != nil {
		logs.Write_Log("ERROR", "Error issuing challenge nonce")
		return "03_03\nserveur_central\n" + trames_content.SessionIntegritykey + "\n" + "vaultaire" + "\nnonce error"
	}
	return "03_05\nserveur_central\n" + trames_content.SessionIntegritykey + "\n" + username + "\n" + salt + "\n" + nonce
}
