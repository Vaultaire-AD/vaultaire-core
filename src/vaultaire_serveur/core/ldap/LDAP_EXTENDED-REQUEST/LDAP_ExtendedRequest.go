package ldapextendedrequest

import (
	"fmt"
	"net"
	ldapresponse "vaultaire/core/ldap/LDAP_RESPONSE"
	ldapsessionmanager "vaultaire/core/ldap/LDAP_SESSION-Manager"
	ldapstorage "vaultaire/core/ldap/LDAP_Storage"
	"vaultaire/core/logs"
	"vaultaire/core/permission"
)

// OIDWhoAmI — RFC 4532.
//
// La seule extension implémentée. Elle n'est volontairement PAS annoncée dans le
// RootDSE : un client qui s'en sert est déjà authentifié, et l'annoncer à un
// anonyme ne lui apprendrait que la surface d'attaque.
const OIDWhoAmI = "1.3.6.1.4.1.4203.1.11.3"

// respond envoie une ExtendedResponse.
//
// L'encodage passe par ldapresponse. La version antérieure construisait les
// octets à la main avec des longueurs sur un octet, et renvoyait `0x40` comme
// code de refus — 0x40 vaut 64, qui n'est pas un code de résultat LDAP. Un
// client ne pouvait rien en faire.
func respond(conn net.Conn, messageID, resultCode int, diagnostic, responseName, responseValue string) {
	if err := ldapresponse.SendExtendedResult(conn, messageID, resultCode, "",
		diagnostic, responseName, responseValue); err != nil {
		logs.Write_Log("ERROR", "ldap extended: "+err.Error())
	}
}

func HandleExtendedRequest(op ldapstorage.ExtendedRequest, messageID int, conn net.Conn) {
	logs.Write_Log("DEBUG", fmt.Sprintf("ldap: extended request name=%s value=%s", op.RequestName, op.RequestValue))

	// --- 🔐 Étape 1 : Identification de l’utilisateur
	session, ok := ldapsessionmanager.GetLDAPSession(conn)
	// Nom VIDE pour une session non liée, jamais « anonymous » : cette chaîne
	// part au RBAC, et un compte réellement nommé ainsi verrait ses permissions
	// accordées aux sessions non authentifiées.
	username := ""
	if ok && session.IsBound && session.Username != "" {
		username = session.Username
	}

	// --- 🔐 Étape 2 : Vérification des permissions
	var action string
	switch op.RequestName {
	case OIDWhoAmI:
		action = "auth"
	default:
		action = "none"
	}

	groupIDs, action, err := permission.PrePermissionCheck(username, action)
	if err != nil {
		logs.Write_Log("ERROR", fmt.Sprintf("Erreur permission préliminaire pour %s : %v", username, err))
		respond(conn, messageID, ldapstorage.ResultInsufficientAccessRights, "permission check failed", "", "")
		return
	}

	ok, msg := permission.CheckPermissionsMultipleDomains(groupIDs, action, []string{"*"})
	if !ok {
		logs.Write_Log("WARNING", fmt.Sprintf("Permission refusée pour %s : %s", username, msg))
		respond(conn, messageID, ldapstorage.ResultInsufficientAccessRights, "insufficient access rights", "", "")
		return
	}

	// --- ✅ Étape 3 : Exécution de la requête autorisée
	if op.RequestName == OIDWhoAmI {
		logs.Write_Log("DEBUG", fmt.Sprintf("ldap: WHOAMI messageID=%d", messageID))
		authzID := fmt.Sprintf("dn:uid=%s,ou=system", username)
		respond(conn, messageID, ldapstorage.ResultSuccess, "", "", authzID)
		return
	}

	// StartTLS (1.3.6.1.4.1.1466.20037) tombe ici, et c'est correct tant qu'il
	// n'est pas implémenté : le RootDSE ne l'annonce plus, et le refus porte
	// désormais un code que le client sait lire. Pour du chiffrement, LDAPS.
	logs.Write_Log("WARNING", fmt.Sprintf("ExtendedRequest non supportée : %s", op.RequestName))
	respond(conn, messageID, ldapstorage.ResultProtocolError, "extended operation not supported", "", "")
}
