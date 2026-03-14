package ldapextendedrequest

import (
	"fmt"
	"net"
	ldapsessionmanager "vaultaire/core/ldap/LDAP_SESSION-Manager"
	ldapstorage "vaultaire/core/ldap/LDAP_Storage"
	"vaultaire/core/logs"
	"vaultaire/core/permission"
)

func buildLDAPExtendedResponse(messageID int, resultCode byte, matchedDN, diagMsg, responseOID, responseValue string) []byte {
	msgID := []byte{0x02, 0x01, byte(messageID)}
	result := []byte{0x0A, 0x01, resultCode}

	matched := []byte{0x04, byte(len(matchedDN))}
	matched = append(matched, []byte(matchedDN)...)

	diag := []byte{0x04, byte(len(diagMsg))}
	diag = append(diag, []byte(diagMsg)...)

	var respName []byte
	if responseOID != "" {
		respName = []byte{0x8A, byte(len(responseOID))}
		respName = append(respName, []byte(responseOID)...)
	}
	var respValue []byte
	if responseValue != "" {
		respValue = []byte{0x8B, byte(len(responseValue))}
		respValue = append(respValue, []byte(responseValue)...)
	}

	extendedPayload := append(result, matched...)
	extendedPayload = append(extendedPayload, diag...)
	extendedPayload = append(extendedPayload, respName...)
	extendedPayload = append(extendedPayload, respValue...)

	extended := []byte{0x78, byte(len(extendedPayload))}
	extended = append(extended, extendedPayload...)

	payload := append(msgID, extended...)
	full := []byte{0x30, byte(len(payload))}
	full = append(full, payload...)

	return full
}

func HandleExtendedRequest(op ldapstorage.ExtendedRequest, messageID int, conn net.Conn) {
	logs.Write_Log("DEBUG", fmt.Sprintf("ldap: extended request name=%s value=%s", op.RequestName, op.RequestValue))

	// --- 🔐 Étape 1 : Identification de l’utilisateur
	session, ok := ldapsessionmanager.GetLDAPSession(conn)
	username := "anonymous"
	if ok && session.IsBound && session.Username != "" {
		username = session.Username
	}

	// --- 🔐 Étape 2 : Vérification des permissions
	var action string
	switch op.RequestName {
	case "1.3.6.1.4.1.4203.1.11.3": // WHOAMI
		action = "auth"
	default:
		action = "none"
	}

	groupIDs, action, err := permission.PrePermissionCheck(username, action)
	if err != nil {
		logs.Write_Log("ERROR", fmt.Sprintf("Erreur permission préliminaire pour %s : %v", username, err))
		response := buildLDAPExtendedResponse(messageID, 0x32, "", "Erreur de permission", "", "")
		conn.Write(response)
		return
	}

	ok, msg := permission.CheckPermissionsMultipleDomains(groupIDs, action, []string{"*"})
	if !ok {
		logs.Write_Log("WARNING", fmt.Sprintf("Permission refusée pour %s : %s", username, msg))
		response := buildLDAPExtendedResponse(messageID, 0x32, "", "Permission refusée", "", "")
		conn.Write(response)
		return
	}

	// --- ✅ Étape 3 : Exécution de la requête autorisée
	if op.RequestName == "1.3.6.1.4.1.4203.1.11.3" {
		logs.Write_Log("DEBUG", fmt.Sprintf("ldap: WHOAMI messageID=%d", messageID))
		authzID := fmt.Sprintf("dn:uid=%s,ou=system", username)
		response := buildLDAPExtendedResponse(messageID, 0x00, "", "", "", authzID)
		_, err := conn.Write(response)
		if err != nil {
			logs.Write_Log("ERROR", fmt.Sprintf("Erreur envoi ExtendedResponse: %s", err.Error()))
			return
		}
	} else {
		logs.Write_Log("WARNING", fmt.Sprintf("ExtendedRequest non supportée : %s", op.RequestName))
		response := buildLDAPExtendedResponse(messageID, 0x40, "", "ExtendedRequest non supportée", "", "")
		conn.Write(response)
	}
}
