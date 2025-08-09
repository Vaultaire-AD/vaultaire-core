package ldapbindunbind

import (
	"DUCKY/serveur/authentification/client"
	"DUCKY/serveur/database"
	ldaptools "DUCKY/serveur/ldap/LDAP-TOOLS"
	ldapsessionmanager "DUCKY/serveur/ldap/LDAP_SESSION-Manager"
	ldapstorage "DUCKY/serveur/ldap/LDAP_Storage"
	"DUCKY/serveur/logs"
	"DUCKY/serveur/storage"
	"fmt"
	"net"
)

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
	conn.Write(res)
}

func respondInvalidCredentials(messageID int, conn net.Conn) {
	res := buildLDAPBindResponse(messageID, 0x31, "", "Invalid credentials")
	conn.Write(res)
}

func respondProtocolError(messageID int, conn net.Conn) {
	res := buildLDAPBindResponse(messageID, 0x02, "", "Protocol error")
	conn.Write(res)
}

func respondStrongAuthRequired(messageID int, conn net.Conn) {
	res := buildLDAPBindResponse(messageID, 0x08, "", "Strong auth required")
	conn.Write(res)
}

func respondBusy(messageID int, conn net.Conn) {
	res := buildLDAPBindResponse(messageID, 0x33, "", "Server is busy")
	conn.Write(res)
}

func respondUnavailable(messageID int, conn net.Conn) {
	res := buildLDAPBindResponse(messageID, 0x34, "", "Server unavailable")
	conn.Write(res)
}

func respondUnwillingToPerform(messageID int, conn net.Conn) {
	res := buildLDAPBindResponse(messageID, 0x35, "", "Refusing operation")
	conn.Write(res)
}

func HandleBindRequest(op ldapstorage.BindRequest, messageID int, conn net.Conn) {
	user, domain, ou := ldaptools.ExtractUsernameAndDomain(op.Name)
	// Affichage propre et clair des infos reçues
	if storage.Ldap_Debug {
		fmt.Println("===== LDAP Bind Request Received =====")
		fmt.Printf("Message ID : %d\n", messageID)
		fmt.Printf("Bind DN    : %s\n", op.Name)
		fmt.Printf("Username   : %s\n", user)
		fmt.Printf("Ou         : %s\n", ou)
		fmt.Printf("Domain     : %s\n", domain)
		fmt.Printf("Authentication (Password) length: %d bytes\n", len(op.Authentication))
		fmt.Println("=====================================")
	}
	if user == "vaultaire" {
		logs.Write_Log("WARNING", "Tentative de connexion avec l'utilisateur 'vaultaire' depuis : "+conn.RemoteAddr().String())
		ldapsessionmanager.ClearSession(conn)
		return
	}
	user_ID, err := database.Get_User_ID_By_Username(database.GetDatabase(), user)
	if err != nil {
		logs.Write_Log("WARNING", "Erreur lors de la récupération de l'ID utilisateur pour "+user+": "+err.Error())
		// 🔴 Répond avec un code d'erreur pour les identifiants invalides
		respondInvalidCredentials(messageID, conn)
		return
	}
	Hpassword, salt, err := database.Get_User_Password_By_ID(database.GetDatabase(), user_ID)
	if err != nil {
		fmt.Println("Erreur lors de la récupération du mot de passe pour :", user)
		respondProtocolError(messageID, conn)
		return
	}
	if !client.ComparePasswords(string(op.Authentication), salt, Hpassword) {
		logs.Write_Log("WARNING", "Tentative de connexion échouée pour l'utilisateur "+user+" depuis : "+conn.RemoteAddr().String()+" wrong password")
		respondInvalidCredentials(messageID, conn)

		return
	}
	// ✅ Répond toujours SUCCESS (code 0)

	// 🔁 Envoi de la réponse sur la connexion réseau
	ldapsessionmanager.SetBindInfo(conn, user, op.Name)
	logs.Write_Log("INFO", "Bind successful for user "+user+" in domain "+domain+" from "+conn.RemoteAddr().String())
	respondBindSuccess(messageID, conn)
}
