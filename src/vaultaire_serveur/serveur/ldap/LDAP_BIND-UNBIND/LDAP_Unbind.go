package ldapbindunbind

import (
	ldapsessionmanager "DUCKY/serveur/ldap/LDAP_SESSION-Manager"
	"fmt"
	"net"
)

func parseUnbindRequestManual(data []byte) error {
	if len(data) < 2 || data[0] != 0x42 {
		return fmt.Errorf("not an Unbind Request tag")
	}
	length := int(data[1])
	if length != 0 {
		return fmt.Errorf("unexpected length for Unbind request")
	}
	return nil
}

func buildLDAPUnbindResponse(messageID int) []byte {
	// Par exemple, un LDAPMessage vide de type 'Success' (similaire à BindResponse)
	// Mais c'est non standard pour Unbind

	// MessageID
	msgID := []byte{
		0x02, 0x01, byte(messageID),
	}

	// ResultCode Success (0), matchedDN vide, diagMsg vide
	result := []byte{
		0x0A, 0x01, 0x00,
	}
	matched := []byte{0x04, 0x00}
	diag := []byte{0x04, 0x00}

	// Utilisation tag [APPLICATION 1] (BindResponse) pour la démo
	bindPayload := append(result, matched...)
	bindPayload = append(bindPayload, diag...)
	bind := []byte{0x61, byte(len(bindPayload))}
	bind = append(bind, bindPayload...)

	payload := append(msgID, bind...)
	full := []byte{0x30, byte(len(payload))}
	full = append(full, payload...)

	return full
}

func HandleUnbindRequest(messageID int, conn net.Conn) {
	fmt.Println("Handling Unbind Request")
	// Normalement pas de réponse à un Unbind
	// Mais si tu veux envoyer une réponse, décommenter la ligne suivante :
	conn.Write(buildLDAPUnbindResponse(messageID))
	// Puis fermer la connexion (fin de session)
	ldapsessionmanager.ClearSession(conn)
}
