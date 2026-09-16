package ldap

import (
	"fmt"
	"net"
	"strconv"
	"vaultaire/core/logs"
	"vaultaire/core/storage"
)

func HandleLDAPserveur() {
	listener, err := net.Listen("tcp", ":"+strconv.Itoa(storage.Ldap_Port))
	if err != nil {
		logs.Write_Log("ERROR", fmt.Sprintf("[LDAP] Erreur lors de l'écoute: %s", err))
		return
	}
	handleLDAPConnections(listener, "LDAP")
}
