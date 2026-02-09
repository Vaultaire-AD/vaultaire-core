package keymanagement

import (
	"vaultaire/serveur/logs"
)

func GetPrivateKey() string {
	privKeyPEM, err := GetPrivateKeyPEMFromDB(ServerMainKeyName)
	if err != nil {
		logs.Write_LogCode("CRITICAL", logs.CodeCertNotFound, "keymanagement: server private key missing (server_main): "+err.Error())
		panic("clé privée serveur non trouvée en base de données — exécuter le serveur une fois pour générer les clés ou importer le certificat server_main")
	}
	return privKeyPEM
}
