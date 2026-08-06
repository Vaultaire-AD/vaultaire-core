package tools

import (
	"crypto/rand"
	"encoding/hex"
)

func GenerateKey() string {
	idBytes := make([]byte, 16)
	if _, err := rand.Read(idBytes); err != nil {

		return "error during the generation of the unique identifiant : " + err.Error()
	}
	alphacheck := hex.EncodeToString(idBytes)
	return alphacheck
}
