package keydecodeencode

// import (
// 	"DUCKY/serveur/logs"
// 	"crypto/aes"
// 	"crypto/cipher"
// 	"crypto/rand"
// 	"io"
// 	"log"
// )

// func encryptAES(plainText, key []byte) ([]byte, []byte) {
// 	block, err := aes.NewCipher(key)
// 	if err != nil {
// 		logs.Write_Log("ERROR", "Error during the cipher AES creation: "+err.Error())
// 		log.Fatalf("Erreur lors de la création du cipher AES: %v", err)
// 	}

// 	gcm, err := cipher.NewGCM(block)
// 	if err != nil {
// 		logs.Write_Log("ERROR", "Error during the GCM creation: "+err.Error())
// 		log.Fatalf("Error during the GCM creation: %v", err)
// 	}

// 	nonce := make([]byte, gcm.NonceSize())
// 	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
// 		logs.Write_Log("ERROR", "Error during the nonce generation: "+err.Error())
// 		log.Fatalf("Error during the nonce generation: %v", err)
// 	}

// 	ciphertext := gcm.Seal(nonce, nonce, plainText, nil)
// 	return ciphertext, nonce
// }

// func decryptAES(cipherText, key, nonce []byte) []byte {
// 	block, err := aes.NewCipher(key)
// 	if err != nil {
// 		logs.Write_Log("ERROR", "Error during the cipher AES creation: "+err.Error())
// 		log.Fatalf("Error during the cipher AES creation: %v", err)
// 	}

// 	gcm, err := cipher.NewGCM(block)
// 	if err != nil {
// 		logs.Write_Log("ERROR", "Error during the GCM creation: "+err.Error())
// 		log.Fatalf("Error during the GCM creation: %v", err)
// 	}

// 	plainText, err := gcm.Open(nil, nonce, cipherText, nil)
// 	if err != nil {
// 		logs.Write_Log("ERROR", "Error during the decryption: "+err.Error())
// 		log.Fatalf("Error Error during the decryption : %v", err)
// 	}

// 	return plainText
// }
