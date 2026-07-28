package keydecodeencode

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"vaultaire/core/database"
	"vaultaire/core/logs"
	"vaultaire/ducky-network/sessionmgr"
)

func EncryptMessageWithClientPublic(message string, clientSoftwareID string) ([]byte, error) {
	// On tague chaque log avec le clientSoftwareID (toujours disponible) et,
	// quand la session correspondante est encore enregistrée, son SessionID :
	// avant ça, deux fetchs de clé concurrents qui échouaient produisaient des
	// lignes de log strictement identiques ("error decoding public key" x2),
	// impossible à rattacher à l'une ou l'autre session.
	sessionID := ""
	if sess, ok := sessionmgr.Sessions.GetByClientSoftwareID(clientSoftwareID); ok {
		sessionID = sess.SessionID
	}
	meta := logs.WithMeta(sessionID, clientSoftwareID)

	clt_publicKey, err := database.Get_Client_Software_PublicKey(database.GetDatabase(), clientSoftwareID)
	if err != nil {
		logs.Write_LogCodeMeta("ERROR", logs.CodeNone,
			"Error during the recover of the client software pubkey for "+clientSoftwareID+": "+err.Error(), meta)
	}
	block, _ := pem.Decode([]byte(clt_publicKey))
	if block == nil || (block.Type != "RSA PUBLIC KEY" && block.Type != "PUBLIC KEY") {
		logs.Write_LogCodeMeta("ERROR", logs.CodeNone, "Error decoding public key for "+clientSoftwareID, meta)
		return nil, fmt.Errorf("error decoding public key for %s", clientSoftwareID)
	}
	publicKey, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		logs.Write_LogCodeMeta("ERROR", logs.CodeNone, "Error parsing public key for "+clientSoftwareID+": "+err.Error(), meta)
		return nil, fmt.Errorf("error parsing public key for %s: %v", clientSoftwareID, err)
	}

	rsaPublicKey, ok := publicKey.(*rsa.PublicKey)
	if !ok {
		logs.Write_LogCodeMeta("ERROR", logs.CodeNone, "The rsa key is not a valid rsa key for "+clientSoftwareID, meta)
		return nil, fmt.Errorf("the rsa key is not a valid rsa key for %s", clientSoftwareID)
	}
	ciphertext, err := rsa.EncryptPKCS1v15(rand.Reader, rsaPublicKey, []byte(message))
	if err != nil {
		logs.Write_LogCodeMeta("ERROR", logs.CodeNone, "Error during the encryption for "+clientSoftwareID+": "+err.Error(), meta)
		return nil, fmt.Errorf("error during the encryption for %s: %v", clientSoftwareID, err)
	}
	return ciphertext, nil
}
