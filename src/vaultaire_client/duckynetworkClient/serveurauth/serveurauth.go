package serveurauth

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"strings"
	keyencodedecode "vaultaire_client/duckynetworkClient/key_encode_decode"
	"vaultaire_client/duckynetworkClient/keymanagement"
	send "vaultaire_client/duckynetworkClient/sendmessage"
	br "vaultaire_client/duckynetworkClient/trames_manager"
	"vaultaire_client/logs"
	"vaultaire_client/storage"
	auth "vaultaire_client/storage"
)

func AskServerAuthentification(duckysession *storage.DuckySession) []byte {
	serveurkey := keymanagement.GetServeurPublicKey()
	_, randomdata, err := encrypt(serveurkey)
	if err != nil {
		fmt.Println(err)
	}
	auth.ServeurAUth = randomdata
	send.SendMessage(("01_01\nserver_central\n" + "INIT" + "\n" + auth.Username + "\n" + auth.Computeur_ID + "\n" + string(randomdata)), duckysession)
	for {
		headerSize, err := br.Read_Header_Size(duckysession.Conn)
		if err != nil {
			logs.Write_log("ERROR", fmt.Sprintf("Erreur lors de la lecture du header : %v", err))
			return nil
		}
		if headerSize != 0 {
			messagesize, err := br.Read_Message_Size(duckysession.Conn, headerSize)
			if err != nil {
				logs.Write_log("ERROR", fmt.Sprintf("Erreur lors de la lecture de la taille du message : %v", err))
				return nil
			}
			messageBuf := make([]byte, messagesize)
			_, err = duckysession.Conn.Read(messageBuf)
			if err != nil {
				logs.Write_log("ERROR", fmt.Sprintf("Erreur lors de la lecture du message : %v", err))
			}
			message, _ := keyencodedecode.DecryptMessageWithPrivate(keymanagement.Get_Client_Private_Key(), messageBuf)
			lines := strings.Split(string(message), "\n")
			if lines[0] == "01_02" {
				sessionIntegritykey := lines[2]

				data := strings.Join(lines[3:], "\n")
				if bytes.Equal(auth.ServeurAUth, []byte(data)) {
					logs.Print_Log("--------------------\nSERVEUR AUTHENTIFIER\n--------------------")
					auth.ServeurCheck = true
				} else {
					logs.Write_log("ERROR", "Erreur lors de l'authentification du serveur : les données ne correspondent pas")
				}
				return []byte(sessionIntegritykey)
			}

		}
	}
}

func encrypt(publicKeyStr string) ([]byte, []byte, error) {
	block, _ := pem.Decode([]byte(publicKeyStr))
	if block == nil { //|| block.Type != " RSA PUBLIC KEY" {
		return nil, nil, fmt.Errorf("erreur lors du décodage de la clé publique")
	}
	publicKey, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, nil, fmt.Errorf("erreur lors du parsing de la clé publique : %v", err)
	}

	rsaPublicKey, ok := publicKey.(*rsa.PublicKey)
	if !ok {
		return nil, nil, fmt.Errorf("la clé n'est pas une clé rsa valide")
	}
	randomData := make([]byte, 16)
	_, err = rand.Read(randomData)
	if err != nil {
		return nil, nil, fmt.Errorf("erreur lors de la génération de données aléatoires : %v", err)
	}
	ciphertext, err := rsa.EncryptPKCS1v15(rand.Reader, rsaPublicKey, randomData)
	if err != nil {
		return nil, nil, fmt.Errorf("erreur lors du chiffrement : %v", err)
	}
	return ciphertext, randomData, nil
}

func EncryptMessageWithPublic(publicKeyStr string, message string) ([]byte, error) {
	block, _ := pem.Decode([]byte(publicKeyStr))
	if block == nil || block.Type != "RSA PUBLIC KEY" {
		return nil, fmt.Errorf("erreur lors du décodage de la clé publique")
	}
	publicKey, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("erreur lors du parsing de la clé publique : %v", err)
	}

	rsaPublicKey, ok := publicKey.(*rsa.PublicKey)
	if !ok {
		return nil, fmt.Errorf("la clé n'est pas une clé rsa valide")
	}
	ciphertext, err := rsa.EncryptPKCS1v15(rand.Reader, rsaPublicKey, []byte(message))
	if err != nil {
		return nil, fmt.Errorf("erreur lors du chiffrement : %v", err)
	}
	return ciphertext, nil
}
