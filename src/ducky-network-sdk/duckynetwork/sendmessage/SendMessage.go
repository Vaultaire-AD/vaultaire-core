// Package sendmessage construit et envoie les trames.
package sendmessage

import (
	"encoding/binary"
	"fmt"
	"strings"

	keyencodedecode "duckynetwork/duckynetwork/key_encode_decode"
	"duckynetwork/duckynetwork/logs"
	"duckynetwork/duckynetwork/storage"
)

// BuildClientTrame assemble une trame montante.
//
// Cinq champs d'en-tête puis le contenu, une ligne par élément. Le format est
// celui du core : action, destination, clé de session, utilisateur, identifiant
// machine.
func BuildClientTrame(action, dest, sessionKey, username, clientID string, contentLines ...string) string {
	parts := []string{action, dest, sessionKey, username, clientID}
	parts = append(parts, contentLines...)
	return strings.Join(parts, "\n")
}

// CompileMessageSize encode la taille sur deux octets.
//
// uint16 : le protocole plafonne donc une trame à 65 535 octets sur le fil. Au
// delà, la taille TRONQUE silencieusement — c'est la raison pour laquelle les
// GPO sont fragmentées.
func CompileMessageSize(message []byte) []byte {
	sizeBytes := make([]byte, 2)
	binary.BigEndian.PutUint16(sizeBytes, uint16(len(message)))
	return sizeBytes
}

// CompileHeaderSize encode la taille de l'en-tête de taille.
func CompileHeaderSize(messageSize []byte) byte { return byte(len(messageSize)) }

// SendMessage chiffre puis envoie une trame.
//
// # Le choix du chiffrement dépend de IsSafe, et de rien d'autre
//
// Tant que la poignée de main n'a pas eu lieu, tout part en RSA-OAEP avec la clé
// publique du core. Une fois la clé de session reçue, tout part en AES-GCM. Se
// tromper de branche produit un échec de déchiffrement côté serveur qui
// ressemble en tout point à une mauvaise clé.
func SendMessage(message string, duckysession *storage.DuckySession, serverPublicKeyPEM string) error {
	if message == "" || duckysession == nil || duckysession.Conn == nil {
		return nil
	}

	var cipherMsg string
	var err error

	if duckysession.IsSafe {
		cipherMsg, err = keyencodedecode.EncryptAESGCMString(duckysession.SessionKey, message)
		if err != nil {
			logs.Write("ERROR", "chiffrement symétrique : "+err.Error())
			return err
		}
	} else {
		cipherBytes, encErr := keyencodedecode.EncryptMessageWithPublic(serverPublicKeyPEM, message)
		if encErr != nil {
			logs.Write("ERROR", "chiffrement asymétrique : "+encErr.Error())
			return encErr
		}
		cipherMsg = string(cipherBytes)
	}

	return SendRaw(duckysession, []byte(cipherMsg))
}

// SendRaw envoie une charge déjà prête, en posant l'en-tête de taille.
//
// Utilisée par « askkey », qui voyage EN CLAIR : à ce stade nous n'avons pas
// encore la clé publique du serveur, c'est précisément ce qu'on va lui demander.
func SendRaw(duckysession *storage.DuckySession, payload []byte) error {
	if duckysession == nil || duckysession.Conn == nil {
		return fmt.Errorf("connexion absente")
	}
	messageSize := CompileMessageSize(payload)
	headerSize := []byte{CompileHeaderSize(messageSize)}
	data := append(append(headerSize, messageSize...), payload...)

	if _, err := duckysession.Conn.Write(data); err != nil {
		logs.Write("ERROR", "envoi au serveur échoué : "+err.Error())
		// La fermeture est volontaire : elle débloque la goroutine de lecture,
		// qui attend sinon indéfiniment sur une connexion morte.
		if cerr := duckysession.Conn.Close(); cerr != nil {
			logs.Write("ERROR", "fermeture de la connexion : "+cerr.Error())
		}
		return err
	}
	return nil
}
