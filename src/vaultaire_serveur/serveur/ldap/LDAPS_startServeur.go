package ldap

import (
	"vaultaire/serveur/logs"
	"vaultaire/serveur/storage"
	duckykey "vaultaire/serveur/ducky-network/key_management"
	ldaptools "vaultaire/serveur/ldap/LDAP-TOOLS"
	"crypto/tls"
	"strconv"
)

func HandleLDAPSserveur() {
	certPEM, keyPEM, err := duckykey.GetCertificatePEMFromDB(duckykey.LDAPSServerCertName)
	if err != nil {
		logs.Write_Log("INFO", "ldaps: TLS certificate not in database, generating self-signed")
		certPEM, keyPEM, err = ldaptools.GenerateSelfSignedCertPEM()
		if err != nil {
			logs.Write_LogCode("ERROR", logs.CodeLDAPTLS, "ldaps: certificate generation failed: "+err.Error())
			return
		}
		if errSave := duckykey.SaveCertificateToDB(duckykey.LDAPSServerCertName, "tls_cert", "Certificat TLS LDAPS", certPEM, keyPEM); errSave != nil {
			certPEM, keyPEM, err = duckykey.GetCertificatePEMFromDB(duckykey.LDAPSServerCertName)
			if err != nil {
				logs.Write_LogCode("ERROR", logs.CodeCertLoad, "ldaps: certificate load from database failed: "+err.Error())
				return
			}
		}
	}

	cert, err := tls.X509KeyPair([]byte(certPEM), []byte(keyPEM))
	if err != nil {
		logs.Write_LogCode("ERROR", logs.CodeLDAPTLS, "ldaps: TLS key pair load failed: "+err.Error())
		return
	}

	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{cert},
		MinVersion:   tls.VersionTLS12,
	}

	listener, err := tls.Listen("tcp", ":"+strconv.Itoa(storage.Ldaps_Port), tlsConfig)
	if err != nil {
		logs.Write_LogCode("ERROR", logs.CodeLDAPListen, "ldaps: TLS listen failed: "+err.Error())
		return
	}

	handleLDAPConnections(listener, "LDAPS")
}
