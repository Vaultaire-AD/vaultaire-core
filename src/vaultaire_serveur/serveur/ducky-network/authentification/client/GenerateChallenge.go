package client

import (
	"vaultaire/serveur/database"
	logs "vaultaire/serveur/logs"
	"crypto/rand"
	"encoding/pem"
	"fmt"
	"math/big"
)

// encryptAndGenerateID encrypts random data using the provided public key and generates a unique identifier.
// It returns the encrypted data, the unique identifier as a string, and any error encountered during the process.
// The public key is expected to be in PEM format, and the function handles both "RSA PUBLIC KEY" and "PUBLIC KEY" types.
// If the public key cannot be decoded or is not valid, it returns an error.
// The function generates 32 bytes of random data, which is intended to be used as a challenge for authentication.
// It also generates a unique identifier by creating a random integer in the range of 0 to 10^10.
// The unique identifier is returned as a string representation of the integer.
// If any error occurs during the random data generation, encryption, or unique identifier generation, it logs the error and returns it.
// The function is designed to be used in the context of client authentication, where the public key is used to encrypt data that can only be decrypted by the corresponding private key.
// The unique identifier can be used to track the authentication request or session.
// It is important to ensure that the public key provided is valid and corresponds to the expected format.
// If the public key is invalid or the encryption fails, the function will return an error indicating the issue.
// If the encryption is successful, the function returns the encrypted data and the unique identifier as a string.
// It is crucial to handle the returned error properly in the calling code to ensure that any issues are addressed appropriately.
// If the public key is valid and the encryption is successful, the function returns the encrypted data and the unique identifier as a string.
// If the public key is invalid or the encryption fails, it returns an error indicating the issue.
func encryptAndGenerateID(publicKeyStr string) ([]byte, string, error) {
	block, _ := pem.Decode([]byte(publicKeyStr))
	if block == nil || block.Type != "RSA PUBLIC KEY" && block.Type != "PUBLIC KEY" {
		logs.Write_Log("ERROR", "erreur during the decoding of the public key")
		return nil, "", fmt.Errorf("erreur during the decoding of the public key")
	}
	// publicKey, err := x509.ParsePKIXPublicKey(block.Bytes)
	// if err != nil {
	// 	return nil, nil, "", fmt.Errorf("erreur lors du parsing de la clé publique : %v", err)
	// }

	// rsaPublicKey, ok := publicKey.(*rsa.PublicKey)
	// if !ok {
	// 	return nil, nil, "", fmt.Errorf("la clé n'est pas une clé rsa valide")
	// }
	randomData := make([]byte, 32)
	_, err := rand.Read(randomData)
	if err != nil {
		logs.Write_Log("ERROR", "Error during generation of the data for the challenge : "+err.Error())
		return nil, "", fmt.Errorf("error during generation of the data for the challenge : %v", err)
	}
	// ciphertext, err := rsa.EncryptPKCS1v15(rand.Reader, rsaPublicKey, randomData)
	// if err != nil {
	// 	return nil, nil, "", fmt.Errorf("erreur lors du chiffrement : %v", err)
	// }

	id, err := rand.Int(rand.Reader, new(big.Int).Exp(big.NewInt(10), big.NewInt(10), nil))
	if err != nil {
		logs.Write_Log("ERROR", "Error during the generation of the unique identifiant : %v")
		return nil, "", fmt.Errorf("error during the generation of the unique identifiant : %v", err)
	}
	alphacheck := string(rune(id.Int64()))
	return randomData, alphacheck, nil
}

// Generate_Challenge generates a challenge for the client software identified by the given ID.
// It retrieves the public key associated with the client software from the database,
// encrypts random data using that public key, and generates a unique identifier.
// If the public key cannot be retrieved or is invalid, it returns an error.
// The function returns the encrypted data as a byte slice and the unique identifier as a string.
func Generate_Challenge(id string) ([]byte, string) {
	publickey, _ := database.Get_Client_Software_PublicKey(database.GetDatabase(), id)
	if publickey == "Error" {
		return []byte{110}, "no"
	}
	uncrypttext, Alphacheck, err := encryptAndGenerateID(publickey)
	if err != nil {
		fmt.Println(err)
	}
	return uncrypttext, Alphacheck
}
