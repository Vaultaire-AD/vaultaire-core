package keymanagement

import (
	"vaultaire/serveur/logs"
)

func GetPublicKey() string {
	pubKeyPEM, err := GetPublicKeyPEMFromDB(ServerMainKeyName)
	if err != nil {
		logs.Write_LogCode("CRITICAL", logs.CodeCertNotFound, "keymanagement: server public key missing (server_main): "+err.Error())
		panic("clé publique serveur non trouvée en base de données — exécuter le serveur une fois pour générer les clés ou importer le certificat server_main")
	}
	return pubKeyPEM
}
