package ldap

import (
	"crypto/tls"
	"strconv"
	ldaptools "vaultaire/core/ldap/LDAP-TOOLS"
	"vaultaire/core/logs"
	"vaultaire/core/storage"
	duckykey "vaultaire/ducky-network/key_management"
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

	// Contrôle de ce qui est RÉELLEMENT servi.
	//
	// Le certificat vient de la base : corriger le générateur ne remplace pas
	// celui d'un parc déjà déployé. Et l'échec de poignée de main est muet côté
	// serveur — le client affiche « SSLHandshakeFailed », le journal ne montre
	// qu'une connexion ouverte puis fermée. Rien ne relie les deux.
	//
	// On ne remplace RIEN automatiquement : changer un certificat sans qu'on le
	// demande casserait tous les clients qui l'ont importé dans leur magasin de
	// confiance. On dit ce qui ne va pas, et comment le corriger.
	attendus := ldaptools.BuildSANSet(ldaptools.ConfiguredDNSNames(), ldaptools.ConfiguredIPs())
	logs.Write_Log("INFO", "ldaps: "+ldaptools.CertSummary(certPEM))
	for _, issue := range ldaptools.AuditServedCertificate(certPEM, attendus) {
		niveau := "WARNING"
		if issue.Grave {
			niveau = "ERROR"
		}
		logs.Write_LogCode(niveau, logs.CodeLDAPTLS, "ldaps: "+issue.Message)
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
