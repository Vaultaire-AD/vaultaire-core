package sshclient

import (
	"fmt"
	"strconv"
	"strings"
	"vaultaire/core/database"
	"vaultaire/core/domain"
	"vaultaire/core/logs"
	"vaultaire/core/permission"
	"vaultaire/core/storage"
)

func SSH_Client_Manager(trames_content storage.Trames_struct_client, duckysession *storage.DuckySession) string {
	message := ""
	switch trames_content.Message_Order[1] {
	case "01":
		message = SSH_SEND_Pubkey_AUTH(trames_content)
	case "04":
		message = SSH_SEND_SALT(trames_content)
	case "06":
		message = SSH_SEND_Fetch_Pubkey(trames_content)
	default:

	}
	return message
}

func SSH_SEND_Pubkey_AUTH(trames_content storage.Trames_struct_client) string {
	content := strings.Split(trames_content.Content, "\n")
	if len(content) < 2 {
		logs.Write_Log(
			"ERROR",
			fmt.Sprintf(
				"Malformed CHECK TRAME THAT IS SEND %s %s %s %s %s %s",
				trames_content.Destination_Server,
				trames_content.SessionIntegritykey,
				trames_content.Username,
				trames_content.Domain,
				trames_content.ClientSoftwareID,
				trames_content.Content,
			),
		)
		return "02_07\nserveur_central\n" +
			trames_content.SessionIntegritykey + "\n" + trames_content.Username + "\ninvalid request"
	}
	db := database.GetDatabase()
	fullUsername := content[0] // "admin@vaultaire.fr" — NE PAS le strip pour le HMAC
	sshUser, domaine := domain.ExctractDomainFromUsername(content[0])
	proof := content[1]
	isauth, err := VerifyChallengeProof(db, sshUser, fullUsername, trames_content.SessionIntegritykey, proof)
	if err != nil {
		logs.Write_Log("ERROR", "Error verifying challenge proof for user "+fullUsername+": "+err.Error())
		return "02_07\nserveur_central\n" +
			trames_content.SessionIntegritykey + "\n" + fullUsername + "\nverification error"
	}
	if isauth {
		// 3. VÉRIFICATION DES DROITS (Peut-il se connecter sur cette machine ?)
		can, err := database.DidUserCanLogin(db, sshUser, trames_content.ClientSoftwareID)
		if err != nil || !can {
			logs.Write_Log("WARNING", sshUser+" permission denied for machine "+trames_content.ClientSoftwareID)
			return "03_03\nserveur_central\n" + trames_content.SessionIntegritykey + "\n" + sshUser + "@" + domaine + "\npermission denied"
		}
		userid, err := database.Get_User_ID_By_Username(db, sshUser)
		if err != nil {
			logs.Write_Log("ERROR", "User not found: "+sshUser)
			return "03_03\nserveur_central\n" + trames_content.SessionIntegritykey + "\n" + sshUser + "@" + domaine + "\nuser not found"
		}
		sshkey, err := database.Get_PublicKeys_ByUserID(db, userid)
		if err != nil {
			logs.Write_Log("ERROR", "Error retrieving SSH key for user "+sshUser)
			return "03_03\nserveur_central\n" + trames_content.SessionIntegritykey + "\n" + sshUser + "@" + domaine + "\nssh key error"
		}
		isadmin, err := database.IsUserAdmin(db, sshUser, trames_content.ClientSoftwareID)
		if err != nil {
			logs.Write_Log("ERROR", "Error checking admin status for user "+sshUser)
			return "03_03\nserveur_central\n" + trames_content.SessionIntegritykey + "\n" + sshUser + "@" + domaine + "\nadmin check error"
		}
		sshkeyString := strings.Join(sshkey, "\n")
		logs.Write_Log("INFO", "SSH access granted for user "+sshUser+" (Admin: "+strconv.FormatBool(isadmin)+")")
		return "03_02\nserveur_central\n" + trames_content.SessionIntegritykey + "\n" + sshUser + "@" + domaine + "\n" + strconv.FormatBool(isadmin) + "\n" + sshkeyString
	}
	logs.Write_Log("WARNING", "Invalid proof for user "+sshUser)
	return "03_03\nserveur_central\n" + trames_content.SessionIntegritykey + "\n" + sshUser + "@" + domaine + "\ninvalid proof"
}

func SSH_SEND_SALT(trames_content storage.Trames_struct_client) string {

	content := strings.Split(trames_content.Content, "\n")
	if len(content) < 1 {
		logs.Write_Log("ERROR", "Trame SSH 03_04 invalide : contenu incomplet")
		return "03_03\nserveur_central\n" + trames_content.SessionIntegritykey + "\n" + "vaultaire" + "@vaultaire" + "\nmalformed_trame"
	}
	// Logique : Le client demande les clés publiques pour l'utilisateur X
	username, domaine := domain.ExctractDomainFromUsername(content[0])
	db := database.GetDatabase()

	ok, _ := permission.CanUserConnectToDomain(username + "@" + domaine)
	if !ok || username == "vaultaire" {
		logs.Write_Log("WARNING", username+" permission denied for machine "+trames_content.ClientSoftwareID)
		return "03_03\nserveur_central\n" + trames_content.SessionIntegritykey + "\n" + username + "@" + domaine + "\npermission denied"
		// 03_03\nserveur_central\n<session_integrity_key>\n<username>@<domain>\n<reason>
		// reason explique pourquoi (refusé, utilisateur inconnu, etc.)
	}

	// 3. VÉRIFICATION DES DROITS (Peut-il se connecter sur cette machine ?)
	can, err := database.DidUserCanLogin(db, username, trames_content.ClientSoftwareID)
	if err != nil || !can {
		logs.Write_Log("WARNING", username+" permission denied for machine "+trames_content.ClientSoftwareID)
		return "03_03\nserveur_central\n" + trames_content.SessionIntegritykey + "\n" + username + "@" + domaine + "\npermission denied"
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
	return "03_05\nserveur_central\n" + trames_content.SessionIntegritykey + "\nvaultaire\n" + username + "@" + domaine + "\n" + salt + "\n" + nonce
}

func SSH_SEND_Fetch_Pubkey(trames_content storage.Trames_struct_client) string {
	content := strings.Split(strings.TrimSpace(trames_content.Content), "\n")
	if len(content) < 1 || content[0] == "" {
		logs.Write_Log("ERROR", "Malformed SSH fetch-key request")
		return "" // Pas de reponse si la requete est malformee
	}

	db := database.GetDatabase()
	sshUser, domaine := domain.ExctractDomainFromUsername(content[0])

	// 1. Verification des droits (peut-il se connecter sur cette machine ?)
	can, err := database.DidUserCanLogin(db, sshUser, trames_content.ClientSoftwareID)
	if err != nil || !can || sshUser == "vaultaire" {
		logs.Write_Log("WARNING", sshUser+" permission denied for machine "+trames_content.ClientSoftwareID+" (fetch-key)")
		return "" // Pas de reponse : on ne revele pas si le user existe ou non
	}

	// 2. Recuperation des clés publiques
	userid, err := database.Get_User_ID_By_Username(db, sshUser)
	if err != nil {
		logs.Write_Log("ERROR", "User not found: "+sshUser+" (fetch-key)")
		return ""
	}

	sshkeys, err := database.Get_PublicKeys_ByUserID(db, userid)
	if err != nil {
		logs.Write_Log("ERROR", "Error retrieving SSH key for user "+sshUser+" (fetch-key)")
		return ""
	}

	logs.Write_Log("INFO", "Cles publiques transmises pour "+sshUser+"@"+domaine+" (fetch-key)")

	sshkeyString := strings.Join(sshkeys, "\n")
	return "03_07\nserveur_central\n" + trames_content.SessionIntegritykey + "\nvaultaire\n" + "\n" + sshUser + "@" + domaine + "\n" + sshkeyString
}
