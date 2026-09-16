package keydecodeencode

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"vaultaire/core/logs"
)

func DecryptMessageWithPrivate(privateKeyStr string, ciphertext []byte) (string, error) {
	block, _ := pem.Decode([]byte(privateKeyStr))
	if block == nil || block.Type != "RSA PRIVATE KEY" {
		logs.Write_Log("CRITICAL", "Erreur decoding private key")
		return "", fmt.Errorf("error decoding private key")
	}

	privateKey, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		logs.Write_Log("CRITICAL", "Erreur Parsing"+err.Error())
		return "", fmt.Errorf("error parsing private key: %v", err)
	}

	// OAEP, et plus PKCS#1 v1.5 — voir oaep_params.go pour le raisonnement.
	//
	// C'est ce déchiffrement précis qui constituait l'oracle : il s'applique à
	// TOUTE trame reçue avant que IsSafe passe à true, donc à des données
	// entièrement choisies par un pair non authentifié.
	plaintext, err := rsa.DecryptOAEP(oaepHash(), rand.Reader, privateKey, ciphertext, oaepLabel)
	if err != nil {
		// Journalisé en WARNING et non en CRITICAL.
		//
		// Un échec ici n'est pas un incident serveur : c'est le cas normal quand
		// quelqu'un envoie n'importe quoi sur le port Ducky, ce qui est le bruit
		// de fond d'un service exposé. En CRITICAL, chaque paquet malformé
		// réveillait la supervision — et surtout, le niveau du journal était une
		// des façons dont l'échec de bourrage devenait observable de l'extérieur.
		logs.Write_LogCode("WARNING", logs.CodeNetKey,
			"ducky: déchiffrement asymétrique refusé (bourrage ou clé invalide)")
		return "", fmt.Errorf("error decrypting: %v", err)
	}

	return string(plaintext), nil
}
