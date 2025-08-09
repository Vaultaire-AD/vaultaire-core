package ldapextendedrequest

import (
	ldapstorage "DUCKY/serveur/ldap/LDAP_Storage"
	"DUCKY/serveur/logs"
	"DUCKY/serveur/storage"
	"fmt"
	"net"
)

func buildLDAPExtendedResponse(messageID int, resultCode byte, matchedDN string, diagMsg string, responseOID string, responseValue string) []byte {
	// Encode message ID
	msgID := []byte{0x02, 0x01, byte(messageID)}
	// Encode resultCode
	result := []byte{0x0A, 0x01, resultCode}
	// Encode matchedDN
	matched := []byte{0x04, byte(len(matchedDN))}
	matched = append(matched, []byte(matchedDN)...)
	// Encode diagnosticMessage
	diag := []byte{0x04, byte(len(diagMsg))}
	diag = append(diag, []byte(diagMsg)...)
	// Optional: responseName [10] = 0x8A
	var respName []byte
	if responseOID != "" {
		respName = []byte{0x8A, byte(len(responseOID))}
		respName = append(respName, []byte(responseOID)...)
	}
	// Optional: responseValue [11] = 0x8B
	var respValue []byte
	if responseValue != "" {
		respValue = []byte{0x8B, byte(len(responseValue))}
		respValue = append(respValue, []byte(responseValue)...)
	}
	// Construct ExtendedResponse: [APPLICATION 24] = 0x78
	extendedPayload := append(result, matched...)
	extendedPayload = append(extendedPayload, diag...)
	extendedPayload = append(extendedPayload, respName...)
	extendedPayload = append(extendedPayload, respValue...)
	extended := []byte{0x78, byte(len(extendedPayload))}
	extended = append(extended, extendedPayload...)
	// Final LDAPMessage: SEQUENCE
	payload := append(msgID, extended...)
	full := []byte{0x30, byte(len(payload))}
	full = append(full, payload...)
	return full
}

func HandleExtendedRequest(op ldapstorage.ExtendedRequest, messageID int, conn net.Conn) {
	if storage.Ldap_Debug {
		fmt.Println("Handling Extended Request")
		fmt.Printf("RequestName: %s\n", op.RequestName)
		fmt.Printf("RequestValue: %s\n", op.RequestValue)
	}

	if op.RequestName == "1.3.6.1.4.1.4203.1.11.3" {
		if storage.Ldap_Debug {
			fmt.Println("Traitement de la requête WHOAMI")
			fmt.Printf("MessageID: %d\n", messageID)
		}
		authzID := "dn:uid=vaultaire,ou=system"
		response := buildLDAPExtendedResponse(
			messageID,
			0x00, // success
			"",   // matchedDN
			"",   // diagnosticMessage
			"",   // responseOID optionnel
			authzID,
		)
		conn.Write(response)
	} else {
		logs.Write_Log("WARNING", fmt.Sprintf("ExtendedRequest non supportée : %s", op.RequestName))
		// gérer autres cas ou erreur
	}
}
