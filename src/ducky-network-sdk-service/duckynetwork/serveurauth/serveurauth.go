package serveurauth

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	keyencodedecode "duckynetworkclient/V1/duckynetwork/key_encode_decode"
	"duckynetworkclient/V1/duckynetwork/keymanagement"
	"duckynetworkclient/V1/duckynetwork/logs"
	"duckynetworkclient/V1/duckynetwork/sendmessage"
	"duckynetworkclient/V1/duckynetwork/storage"
	tramesmanager "duckynetworkclient/V1/duckynetwork/trames_manager"
	"encoding/pem"
	"fmt"
	"strings"
)

func AskServerAuthentification(duckysession *storage.DuckySession) []byte {
	serveurkey := keymanagement.GetServeurPublicKey()
	_, randomdata, err := encrypt(serveurkey)
	if err != nil {
		fmt.Println(err)
	}
	storage.ServeurAUth = randomdata
	sendmessage.SendMessage(("01_01\nserver_central\n" + "INIT" + "\n" + "vaultaire" + "\n" + storage.Computeur_ID + "\n" + string(randomdata)), duckysession)
	for {
		headerSize, err := tramesmanager.Read_Header_Size(duckysession.Conn)
		if err != nil {
			logs.Write_log("ERROR", fmt.Sprintf("Erreur lors de la lecture du header : %v", err))
			return nil
		}
		if headerSize != 0 {
			messagesize, err := tramesmanager.Read_Message_Size(duckysession.Conn, headerSize)
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
				if bytes.Equal(storage.ServeurAUth, []byte(data)) {
					logs.Print_Log("--------------------\nSERVEUR AUTHENTIFIER\n--------------------")
					storage.ServeurCheck = true
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
	// OAEP, avec les paramètres du paquet key_encode_decode — surtout pas une
	// copie locale de sha256.New() : les deux extrémités du canal doivent
	// s'accorder, et un troisième endroit à tenir en cohérence finirait par
	// diverger.
	ciphertext, err := rsa.EncryptOAEP(keyencodedecode.OAEPHash(), rand.Reader,
		rsaPublicKey, randomData, keyencodedecode.OAEPLabel)
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
	ciphertext, err := rsa.EncryptOAEP(keyencodedecode.OAEPHash(), rand.Reader,
		rsaPublicKey, []byte(message), keyencodedecode.OAEPLabel)
	if err != nil {
		return nil, fmt.Errorf("erreur lors du chiffrement (%d octets, maximum %d) : %v",
			len(message), keyencodedecode.MaxOAEPPayload(rsaPublicKey.Size()), err)
	}
	return ciphertext, nil
}
