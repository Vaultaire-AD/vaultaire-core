package serveurauth

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"net"
	"strings"
	keyencodedecode "vaultaire_client/duckynetworkClient/key_encode_decode"
	"vaultaire_client/duckynetworkClient/keymanagement"
	send "vaultaire_client/duckynetworkClient/sendmessage"
	br "vaultaire_client/duckynetworkClient/trames_manager"
	auth "vaultaire_client/storage"
)

func AskServerAuthentification(conn net.Conn) string {
	serveurkey := keymanagement.GetServeurPublicKey()
	_, randomdata, err := encrypt(serveurkey)
	if err != nil {
		fmt.Println(err)
	}
	auth.ServeurAUth = randomdata
	fmt.Println("Ask Serveur Auth\n", string(randomdata))
	send.SendMessage(("01_01\nserver_central\n" + "INIT" + "\n" + auth.Username + "\n" + auth.Computeur_ID + "\n" + string(randomdata)), conn)
	for {
		headerSize := br.Read_Header_Size(conn)
		if headerSize != 0 {
			messagesize := br.Read_Message_Size(conn, headerSize)
			fmt.Println("\nYou receive a message from : ", conn.RemoteAddr())
			messageBuf := make([]byte, messagesize)
			_, err := conn.Read(messageBuf)
			if err != nil {
				fmt.Println("Erreur lors de la lecture du message :", err)
			}
			message, _ := keyencodedecode.DecryptMessageWithPrivate(keymanagement.Get_Client_Private_Key(), messageBuf)
			lines := strings.Split(string(message), "\n")
			fmt.Println(lines[0])
			if lines[0] == "01_02" {
				sessionIntegritykey := lines[2]
				data := strings.Join(lines[3:], "\n")
				fmt.Println(string([]byte(data)))
				if bytes.Equal(auth.ServeurAUth, []byte(data)) {
					fmt.Println("--------------------\nSERVEUR AUTHENTIFIER\n--------------------")
					auth.ServeurCheck = true
				} else {
					fmt.Println("ERREUR lors de l'authentification du serveur")
				}
				return sessionIntegritykey
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
