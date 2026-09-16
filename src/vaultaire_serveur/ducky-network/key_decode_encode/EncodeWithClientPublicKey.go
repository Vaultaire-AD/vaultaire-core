package keydecodeencode

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"vaultaire/core/database"
	dbclients "vaultaire/core/database/db_clients"
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

	clt_publicKey, err := dbclients.Get_Client_Software_PublicKey(database.GetDatabase(), clientSoftwareID)
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
	// OAEP — voir oaep_params.go. Les paramètres doivent être identiques à ceux
	// de l'agent, sans quoi le client ne peut plus déchiffrer les réponses.
	//
	// L'erreur la plus probable ici n'est plus une clé invalide mais un message
	// trop long : OAEP réduit la charge utile de 501 à 446 octets sur RSA-4096.
	// Le message le dit, pour éviter de chercher du côté des clés.
	ciphertext, err := rsa.EncryptOAEP(oaepHash(), rand.Reader, rsaPublicKey, []byte(message), oaepLabel)
	if err != nil {
		logs.Write_LogCodeMeta("ERROR", logs.CodeNone, fmt.Sprintf(
			"Error during the encryption for %s (%d octets, maximum %d) : %v",
			clientSoftwareID, len(message), MaxOAEPPayload(rsaPublicKey.Size()), err), meta)
		return nil, fmt.Errorf("error during the encryption for %s: %v", clientSoftwareID, err)
	}
	return ciphertext, nil
}
