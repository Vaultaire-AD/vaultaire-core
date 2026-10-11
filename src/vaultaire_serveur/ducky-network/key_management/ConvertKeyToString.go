package keymanagement

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"vaultaire/core/logs"
)

// Convert_Public_Key_To_String rend la clé en PEM, ou "" si elle ne se convertit pas (journalisé).
func Convert_Public_Key_To_String(publicKey *rsa.PublicKey) string {
	pubKeyBytes, err := x509.MarshalPKIXPublicKey(publicKey)
	if err != nil {
		// Chaîne vide plutôt que log.Fatalf : cette conversion est sur le chemin
		// d'enrôlement, une clé refusée ne doit pas arrêter le core.
		logs.Write_LogCode("ERROR", logs.CodeNetBuild, "clés : conversion de la clé PUBLIQUE impossible : "+err.Error())
		return ""
	}

	// Encoder en format PEM
	pubKeyPem := pem.EncodeToMemory(&pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: pubKeyBytes,
	})

	// Convertir en chaîne
	pubKeyStr := string(pubKeyPem)
	return pubKeyStr
}

// Convert_Private_Key_To_String rend la clé en PEM, ou "" si elle ne se convertit pas (journalisé).
func Convert_Private_Key_To_String(privateKey *rsa.PrivateKey) string {
	prvKeyBytes, err := x509.MarshalPKCS8PrivateKey(privateKey)
	if err != nil {
		logs.Write_LogCode("ERROR", logs.CodeNetBuild, "clés : conversion de la clé PRIVÉE impossible : "+err.Error())
		return ""
	}

	// Encoder en format PEM
	prvKeyPem := pem.EncodeToMemory(&pem.Block{
		Type:  "PRIVATE KEY",
		Bytes: prvKeyBytes,
	})

	// Convertir en chaîne
	prvKeyStr := string(prvKeyPem)
	return prvKeyStr
}
