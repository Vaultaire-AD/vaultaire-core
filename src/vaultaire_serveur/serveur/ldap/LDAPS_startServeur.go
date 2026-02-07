package ldap

import (
	"vaultaire/serveur/logs"
	"vaultaire/serveur/storage"
	"crypto/tls"
	"fmt"
	"os"
	"strconv"

	ldaptools "vaultaire/serveur/ldap/LDAP-TOOLS"
)

func HandleLDAPSserveur() {
	const (
		certFile       = "/opt/vaultaire/.ssh/ldaps_server.crt"
		privateKeyPath = "/opt/vaultaire/.ssh/ldaps_server.key"
	)

	if _, err := os.Stat(certFile); os.IsNotExist(err) || ldaptools.FileEmpty(certFile) || ldaptools.FileEmpty(privateKeyPath) {
		logs.Write_Log("WARNING", "[LDAPS] Certificat TLS absent — génération auto-signée en cours...")
		if err := ldaptools.GenerateSelfSignedCert(certFile, privateKeyPath); err != nil {
			logs.Write_Log("ERROR", fmt.Sprintf("[LDAPS] Erreur génération certificats: %v", err))
			return
		}
	}

	cert, err := tls.LoadX509KeyPair(certFile, privateKeyPath)
	if err != nil {
		logs.Write_Log("ERROR", fmt.Sprintf("[LDAPS] Erreur chargement clé TLS: %s", err))
		return
	}

	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{cert},
		MinVersion:   tls.VersionTLS12,
	}

	listener, err := tls.Listen("tcp", ":"+strconv.Itoa(storage.Ldaps_Port), tlsConfig)
	if err != nil {
		logs.Write_Log("ERROR", fmt.Sprintf("[LDAPS] Erreur écoute TLS: %s", err))
		return
	}

	handleLDAPConnections(listener, "LDAPS")
}
