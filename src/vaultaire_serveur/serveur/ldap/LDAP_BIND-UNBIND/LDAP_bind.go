package ldapbindunbind

import (
	"vaultaire/serveur/database"
	gc "vaultaire/serveur/global/security"
	ldaptools "vaultaire/serveur/ldap/LDAP-TOOLS"
	ldapsessionmanager "vaultaire/serveur/ldap/LDAP_SESSION-Manager"
	ldapstorage "vaultaire/serveur/ldap/LDAP_Storage"
	"vaultaire/serveur/logs"
	"vaultaire/serveur/permission"
	"fmt"
	"net"
)

// Construire une réponse LDAP Bind
func buildLDAPBindResponse(messageID int, resultCode byte, matchedDN string, diagMsg string) []byte {
	// Encode message ID
	msgID := []byte{
		0x02, 0x01, byte(messageID), // INTEGER, 1 byte long, value
	}

	// Encode resultCode ENUMERATED
	result := []byte{
		0x0A, 0x01, resultCode,
	}

	// Encode matchedDN (string)
	matched := []byte{0x04, byte(len(matchedDN))}
	matched = append(matched, []byte(matchedDN)...)

	// Encode diagnosticMessage (string)
	diag := []byte{0x04, byte(len(diagMsg))}
	diag = append(diag, []byte(diagMsg)...)

	// BindResponse [APPLICATION 1]
	bindPayload := append(result, matched...)
	bindPayload = append(bindPayload, diag...)
	bind := []byte{0x61, byte(len(bindPayload))}
	bind = append(bind, bindPayload...)

	// Final LDAPMessage (SEQUENCE)
	payload := append(msgID, bind...)
	full := []byte{0x30, byte(len(payload))}
	full = append(full, payload...)

	return full
}
func respondBindSuccess(messageID int, conn net.Conn) {
	res := buildLDAPBindResponse(messageID, 0x00, "", "Bind successful")
	_, err := conn.Write(res)
	if err != nil {
		logs.Write_Log("ERROR", "Error sending bind success response: "+err.Error())
		return
	}
}

func respondInvalidCredentials(messageID int, conn net.Conn) {
	res := buildLDAPBindResponse(messageID, 0x31, "", "Invalid credentials")
	_, err := conn.Write(res)
	if err != nil {
		logs.Write_Log("ERROR", "Error sending invalid credentials response: "+err.Error())
		return
	}
}

func respondProtocolError(messageID int, conn net.Conn) {
	res := buildLDAPBindResponse(messageID, 0x02, "", "Protocol error")
	_, err := conn.Write(res)
	if err != nil {
		logs.Write_Log("ERROR", fmt.Sprintf("Erreur lors de l'envoi de la réponse Bind: %s", err.Error()))
		return
	}
}

// func respondStrongAuthRequired(messageID int, conn net.Conn) {
// 	res := buildLDAPBindResponse(messageID, 0x08, "", "Strong auth required")
// 	_, err := conn.Write(res)
// 	if err != nil {
// 		logs.Write_Log("ERROR", fmt.Sprintf("Erreur lors de l'envoi de la réponse Bind: %s", err.Error()))
// 		return
// 	}
// }

// func respondBusy(messageID int, conn net.Conn) {
// 	res := buildLDAPBindResponse(messageID, 0x33, "", "Server is busy")
// 	_, err := conn.Write(res)
// 	if err != nil {
// 		logs.Write_Log("ERROR", fmt.Sprintf("Erreur lors de l'envoi de la réponse Bind: %s", err.Error()))
// 		return
// 	}
// }

// func respondUnavailable(messageID int, conn net.Conn) {
// 	res := buildLDAPBindResponse(messageID, 0x34, "", "Server unavailable")
// 	_, err := conn.Write(res)
// 	if err != nil {
// 		logs.Write_Log("ERROR", fmt.Sprintf("Erreur lors de l'envoi de la réponse Bind: %s", err.Error()))
// 		return
// 	}
// }

// func respondUnwillingToPerform(messageID int, conn net.Conn) {
// 	res := buildLDAPBindResponse(messageID, 0x35, "", "Refusing operation")
// 	_, err := conn.Write(res)
// 	if err != nil {
// 		logs.Write_Log("ERROR", fmt.Sprintf("Erreur lors de l'envoi de la réponse Bind: %s", err.Error()))
// 		return
// 	}
// }

func HandleBindRequest(op ldapstorage.BindRequest, messageID int, conn net.Conn) {
	user, domain, ou := ldaptools.ExtractUsernameAndDomain(op.Name)

	logs.Write_Log("DEBUG", fmt.Sprintf("ldap: bind request messageID=%d dn=%s user=%s ou=%s domain=%s password_len=%d", messageID, op.Name, user, ou, domain, len(op.Authentication)))

	// 🔒 Interdiction d'utiliser le compte système Vaultaire
	if user == "vaultaire" {
		logs.Write_Log("WARNING", fmt.Sprintf("Tentative de connexion avec l'utilisateur 'vaultaire' depuis %s", conn.RemoteAddr().String()))
		ldapsessionmanager.ClearSession(conn)
		respondInvalidCredentials(messageID, conn)
		return
	}

	// 🔍 Vérification que l'utilisateur existe
	userID, err := database.Get_User_ID_By_Username(database.GetDatabase(), user)
	if err != nil {
		logs.Write_Log("WARNING", fmt.Sprintf("Utilisateur inconnu (%s) depuis %s", user, conn.RemoteAddr().String()))
		respondInvalidCredentials(messageID, conn)
		return
	}

	// 🔐 Vérification du mot de passe
	Hpassword, salt, err := database.Get_User_Password_By_ID(database.GetDatabase(), userID)
	if err != nil {
		logs.Write_Log("ERROR", fmt.Sprintf("Erreur lors de la récupération du mot de passe pour %s : %v", user, err))
		respondProtocolError(messageID, conn)
		return
	}

	if !gc.ComparePasswords(string(op.Authentication), salt, Hpassword) {
		logs.Write_Log("WARNING", fmt.Sprintf("Échec de connexion pour %s (%s) : mot de passe incorrect", user, conn.RemoteAddr().String()))
		respondInvalidCredentials(messageID, conn)
		return
	}

	// ✅ Authentification réussie — maintenant vérification de la permission
	groupIDs, normalizedAction, err := permission.PrePermissionCheck(user, "auth")
	if err != nil {
		logs.Write_Log("WARNING", fmt.Sprintf("Échec pré-permission pour %s : %v", user, err))
		respondInvalidCredentials(messageID, conn)
		return
	}

	// On vérifie s'il a le droit d'exécuter "auth" sur ce domaine
	ok, msg := permission.CheckPermissionsMultipleDomains(groupIDs, normalizedAction, []string{domain})
	if !ok {
		logs.Write_Log("WARNING", fmt.Sprintf("Permission refusée pour %s sur domaine %s : %s", user, domain, msg))
		respondInvalidCredentials(messageID, conn)
		return
	}

	// 🔁 Mise à jour de la session
	ldapsessionmanager.SetBindInfo(conn, user, op.Name)

	// 🟢 Log succès
	logs.Write_Log("INFO", fmt.Sprintf("Bind réussi pour %s sur domaine %s depuis %s", user, domain, conn.RemoteAddr().String()))

	// ✅ Réponse LDAP
	respondBindSuccess(messageID, conn)
}
