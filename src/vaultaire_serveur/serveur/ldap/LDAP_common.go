package ldap

import (
	ldapparser "vaultaire/serveur/ldap/LDAP_Parser"
	ldapsessionmanager "vaultaire/serveur/ldap/LDAP_SESSION-Manager"
	ldapstorage "vaultaire/serveur/ldap/LDAP_Storage"
	"vaultaire/serveur/logs"
	"fmt"
	"io"
	"net"
)

// Fonction générique utilisée par LDAP et LDAPS
func handleLDAPConnections(listener net.Listener, protocol string) {
	defer func() {
		if err := listener.Close(); err != nil {
			logs.Write_LogCode("ERROR", logs.CodeLDAPListen, "ldap: listener close failed: "+err.Error())
		}
	}()

	logs.Write_Log("INFO", "ldap: "+protocol+" listening on "+listener.Addr().String())

	for {
		conn, err := listener.Accept()
		if err != nil {
			logs.Write_LogCode("WARNING", logs.CodeLDAPListen, fmt.Sprintf("[%s] Erreur d’acceptation de connexion: %s", protocol, err))
			continue
		}

		go handleLDAPSession(conn, protocol)
	}
}

// Lecture et traitement d'une session LDAP unique
func handleLDAPSession(c net.Conn, protocol string) {
	defer func() {
		ldapsessionmanager.ClearSession(c)
		if err := c.Close(); err != nil {
			logs.Write_Log("DEBUG", "ldap: connection close failed: "+err.Error())
		}
	}()

	ldapsessionmanager.InitLDAPSession(c)
	clientAddr := c.RemoteAddr().String()
	logs.Write_Log("INFO", "ldap: connection from "+clientAddr)

	for {
		packet, err := readLDAPPacket(c)
		if err != nil {
			if err == io.EOF {
				logs.Write_Log("DEBUG", "ldap: client closed connection: "+clientAddr)
			} else {
				logs.Write_LogCode("ERROR", logs.CodeLDAPListen, "ldap: read packet failed from "+clientAddr+": "+err.Error())
			}
			return
		}

		logs.Write_Log("DEBUG", fmt.Sprintf("ldap: packet from %s: % X", clientAddr, packet))

		message, err := ldapparser.ParseLDAPMessage(packet)
		if err != nil {
			logs.Write_LogCode("ERROR", logs.CodeLDAPListen, "ldap: parse failed from "+clientAddr+": "+err.Error())
			continue
		}

		// if storage.Debug {
		// 	printLDAPMessageDebug(message, protocol, clientAddr)
		// }

		ldapparser.DispatchLDAPOperation(message, message.MessageID, c)
	}
}

// Affichage structuré des messages LDAP (uniquement si debug)
func printLDAPMessageDebug(message *ldapstorage.LDAPParsedReceivedMessage, protocol, client string) {
	logs.Write_Log("DEBUG", fmt.Sprintf("[%s] ===== LDAP Parsed Message (%s) =====", protocol, client))
	logs.Write_Log("DEBUG", fmt.Sprintf("[%s] Message ID       : %d", protocol, message.MessageID))
	logs.Write_Log("DEBUG", fmt.Sprintf("[%s] Operation (type) : %s", protocol, message.ProtocolOp.OpType()))

	if len(message.Controls) > 0 {
		logs.Write_Log("DEBUG", fmt.Sprintf("[%s] Controls (%d):", protocol, len(message.Controls)))
		for i, ctrl := range message.Controls {
			logs.Write_Log("DEBUG", fmt.Sprintf("[%s]   • Control #%d", protocol, i+1))
			logs.Write_Log("DEBUG", fmt.Sprintf("[%s]     - Type        : %s", protocol, ctrl.ControlType))
			logs.Write_Log("DEBUG", fmt.Sprintf("[%s]     - Criticalité : %v", protocol, ctrl.Criticality))
			logs.Write_Log("DEBUG", fmt.Sprintf("[%s]     - Valeur      : % X", protocol, ctrl.ControlValue))
		}
	} else {
		logs.Write_Log("DEBUG", fmt.Sprintf("[%s] Controls : Aucun", protocol))
	}
	logs.Write_Log("DEBUG", fmt.Sprintf("[%s] ===============================", protocol))
}

// Lecture binaire d’un paquet LDAP complet
func readLDAPPacket(conn net.Conn) ([]byte, error) {
	header := make([]byte, 2)
	if _, err := io.ReadFull(conn, header); err != nil {
		return nil, err
	}
	if header[0] != 0x30 {
		return nil, fmt.Errorf("invalid LDAP message: expected SEQUENCE (0x30), got 0x%x", header[0])
	}

	length := int(header[1])
	var lenBytes []byte

	if length&0x80 != 0 {
		numBytes := length & 0x7F
		if numBytes > 4 {
			return nil, fmt.Errorf("invalid BER length: too many length bytes")
		}
		lenBytes = make([]byte, numBytes)
		if _, err := io.ReadFull(conn, lenBytes); err != nil {
			return nil, err
		}
		length = 0
		for _, b := range lenBytes {
			length = (length << 8) | int(b)
		}
	}

	const maxLDAPMessageSize = 4 * 1024 * 1024 // 4 MiB, évite allocation DoS
	if length < 0 || length > maxLDAPMessageSize {
		return nil, fmt.Errorf("invalid LDAP message length: %d (max %d)", length, maxLDAPMessageSize)
	}

	message := make([]byte, length)
	if _, err := io.ReadFull(conn, message); err != nil {
		return nil, err
	}

	totalLen := 2 + len(lenBytes) + length
	fullPacket := make([]byte, totalLen)
	copy(fullPacket, header)
	copy(fullPacket[2:], lenBytes)
	copy(fullPacket[2+len(lenBytes):], message)
	return fullPacket, nil
}
