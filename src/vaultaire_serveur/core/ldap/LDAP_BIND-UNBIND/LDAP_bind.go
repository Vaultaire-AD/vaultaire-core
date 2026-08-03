package ldapbindunbind

import (
	"fmt"
	"net"
	"vaultaire/core/auth/passwordpolicy"
	"vaultaire/core/database"
	gc "vaultaire/core/global/security"
	ldaptools "vaultaire/core/ldap/LDAP-TOOLS"
	ldapsessionmanager "vaultaire/core/ldap/LDAP_SESSION-Manager"
	ldapstorage "vaultaire/core/ldap/LDAP_Storage"
	"vaultaire/core/logs"
	"vaultaire/core/permission"
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
		logs.Write_LogCode("ERROR", logs.CodeLDAPListen, "ldap bind: send success response failed: "+err.Error())
		return
	}
}

func respondInvalidCredentials(messageID int, conn net.Conn) {
	res := buildLDAPBindResponse(messageID, 0x31, "", "Invalid credentials")
	_, err := conn.Write(res)
	if err != nil {
		logs.Write_LogCode("ERROR", logs.CodeLDAPListen, "ldap bind: send invalid credentials response failed: "+err.Error())
		return
	}
}

func respondProtocolError(messageID int, conn net.Conn) {
	res := buildLDAPBindResponse(messageID, 0x02, "", "Protocol error")
	_, err := conn.Write(res)
	if err != nil {
		logs.Write_LogCode("ERROR", logs.CodeLDAPListen, "ldap bind: send protocol error response failed: "+err.Error())
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

	logs.Write_Log("DEBUG", fmt.Sprintf("ldap: bind request messageID=%d dn=%s user=%s ou=%s domain=%s", messageID, op.Name, user, ou, domain))

	// 🔒 Interdiction d'utiliser le compte système Vaultaire
	if user == "vaultaire" {
		logs.Write_LogCode("WARNING", logs.CodeAuthFailed, fmt.Sprintf("ldap bind: system user rejected from %s", conn.RemoteAddr().String()))
		ldapsessionmanager.ClearSession(conn)
		respondInvalidCredentials(messageID, conn)
		return
	}

	// Selon la RFC 4511, un bind avec un DN vide est une demande d'anonymat.
	if op.Name == "" || op.Anonymous {
		logs.Write_Log("INFO", fmt.Sprintf("ldap: anonymous bind request from %s", conn.RemoteAddr().String()))

		// On marque la session comme "Bound" mais sans utilisateur (Anonymous)
		ldapsessionmanager.SetAnonymousBindInfo(conn)

		// Succès LDAP (code 0)
		respondBindSuccess(messageID, conn)
		return
	}

	// 🔍 Vérification que l'utilisateur existe
	userID, err := database.Get_User_ID_By_Username(database.GetDatabase(), user)
	if err != nil {
		logs.Write_LogCode("WARNING", logs.CodeAuthFailed, fmt.Sprintf("ldap bind: unknown user=%s from %s", user, conn.RemoteAddr().String()))
		respondInvalidCredentials(messageID, conn)
		return
	}

	// 🔐 Vérification du mot de passe
	Hpassword, salt, err := database.Get_User_Password_By_ID(database.GetDatabase(), userID)
	if err != nil {
		logs.Write_LogCode("ERROR", logs.CodeDBQuery, fmt.Sprintf("ldap bind: password lookup failed for user=%s: %v", user, err))
		respondProtocolError(messageID, conn)
		return
	}

	if !gc.ComparePasswords(string(op.Authentication), salt, Hpassword) {
		logs.Write_LogCode("WARNING", logs.CodeAuthFailed, fmt.Sprintf("ldap bind: invalid password user=%s from %s", user, conn.RemoteAddr().String()))
		respondInvalidCredentials(messageID, conn)
		return
	}

	// ⏳ EXPIRATION DU MOT DE PASSE — après vérification réussie du mot de passe.
	//
	// La réponse reste un invalidCredentials générique, contrairement au chemin
	// Ducky qui, lui, annonce explicitement l'expiration. L'asymétrie n'est pas
	// une inattention :
	//
	//   - LDAP n'a pas de moyen standard de signaler une expiration. Le contrôle
	//     de politique de mot de passe est resté à l'état de brouillon IETF et
	//     n'est pas implémenté de façon homogène par les bibliothèques clientes.
	//     Un code de résultat exotique serait interprété au mieux comme un échec,
	//     au pire comme une erreur de protocole ;
	//   - de l'autre côté d'un bind, il y a une application, pas un humain. Elle
	//     ne peut rien faire de l'information — le changement de mot de passe
	//     passe par l'interface web, qui reste ouverte.
	//
	// Le log serveur, lui, distingue les deux cas : sans cela, un administrateur
	// verrait une vague de « invalid password » le jour où la politique prend
	// effet et chercherait une attaque là où il n'y a qu'une expiration.
	if status, err := passwordpolicy.Check(database.GetDatabase(), user); err != nil {
		logs.Write_LogCode("ERROR", logs.CodeDBQuery, fmt.Sprintf(
			"ldap bind: état d'expiration illisible pour user=%s (%v) — connexion autorisée", user, err))
	} else if status.IsExpired() {
		logs.Write_LogCode("SECURITY", logs.CodeAuthFailed, fmt.Sprintf(
			"ldap bind: refusé, mot de passe expiré depuis %d jour(s) user=%s from %s",
			-status.DaysUntilExpiry, user, conn.RemoteAddr().String()))
		respondInvalidCredentials(messageID, conn)
		return
	}

	// ✅ Authentification réussie — maintenant vérification de la permission
	groupIDs, normalizedAction, err := permission.PrePermissionCheck(user, "auth")
	if err != nil {
		logs.Write_LogCode("WARNING", logs.CodeAuthPermission, fmt.Sprintf("ldap bind: pre-permission failed user=%s: %v", user, err))
		respondInvalidCredentials(messageID, conn)
		return
	}

	ok, msg := permission.CheckPermissionsMultipleDomains(groupIDs, normalizedAction, []string{domain})
	if !ok {
		logs.Write_LogCode("WARNING", logs.CodeAuthPermission, fmt.Sprintf("ldap bind: permission denied user=%s domain=%s reason=%s", user, domain, msg))
		respondInvalidCredentials(messageID, conn)
		return
	}

	ldapsessionmanager.SetBindInfo(conn, user, op.Name)
	logs.Write_LogCodeMeta("INFO", logs.CodeNone, fmt.Sprintf("ldap bind: success user=%s domain=%s from %s", user, domain, conn.RemoteAddr().String()), logs.UserMeta(userID))

	// ✅ Réponse LDAP
	respondBindSuccess(messageID, conn)
}
