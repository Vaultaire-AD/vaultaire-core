package sendmessage

import (
	keyencodedecode "duckynetworkclient/V1/duckynetwork/key_encode_decode"
	"duckynetworkclient/V1/duckynetwork/keymanagement"
	"duckynetworkclient/V1/duckynetwork/logs"
	"duckynetworkclient/V1/duckynetwork/storage"
	"encoding/binary"
	"fmt"
	"math"
	"strings"
)

// Côté client
func BuildClientTrame(action, dest, sessionKey, username, clientID string, contentLines ...string) string {
	parts := []string{action, dest, sessionKey, username, clientID}
	parts = append(parts, contentLines...)
	return strings.Join(parts, "\n")
}

// TailleMaxCorps est la plus grande taille de corps que le champ taille, sur
// deux octets, peut annoncer. Même valeur que tramesmanager.TailleMaxCorps et
// que le core.
const TailleMaxCorps = math.MaxUint16

// CompileMessageSize encode la taille du corps sur deux octets.
//
// Une ERREUR au-delà de TailleMaxCorps, jamais une troncature : `uint16(...)`
// annonçait la taille modulo 65536 alors que le corps entier partait, et le
// tunnel restait désynchronisé jusqu'à sa fermeture (TO-DO 101).
func CompileMessageSize(message []byte) ([]byte, error) {
	if len(message) > TailleMaxCorps {
		return nil, fmt.Errorf(
			"trame de %d octets : dépasse la taille maximale du protocole Ducky (%d) — non émise",
			len(message), TailleMaxCorps)
	}
	sizeBytes := make([]byte, 2)
	binary.BigEndian.PutUint16(sizeBytes, uint16(len(message)))

	return sizeBytes, nil
}

// CadrerTrame rend la trame prête à écrire : longueur du champ taille, taille,
// corps. Seul assemblage à employer.
func CadrerTrame(corps []byte) ([]byte, error) {
	taille, err := CompileMessageSize(corps)
	if err != nil {
		return nil, err
	}
	trame := make([]byte, 0, 1+len(taille)+len(corps))
	trame = append(trame, CompileHeaderSize(taille))
	trame = append(trame, taille...)
	return append(trame, corps...), nil
}

func CompileHeaderSize(messageSize []byte) byte {
	headerSize := byte(len(messageSize))
	return headerSize
}

func SendMessage(message string, duckysession *storage.DuckySession) {

	// 1. Vérification de sécurité
	if message == "" || duckysession.Conn == nil {
		return
	}

	var cipherMsg string
	var err error

	// 2. chiffrement (AES ou RSA)
	if duckysession.IsSafe {
		// Chiffrement symétrique AES-GCM avec clé de session
		cipherMsg, err = keyencodedecode.EncryptAESGCMString(duckysession.SessionKey, message)
		if err != nil {
			logs.Write_log("ERROR", fmt.Sprintf("Erreur lors du chiffrement symétrique : %v", err))
			return
		}
	} else {
		// Chiffrement asymétrique RSA avec clé publique du serveur
		cipherBytes, err := keyencodedecode.EncryptMessageWithPublic(keymanagement.GetServeurPublicKey(), message)
		if err != nil {
			logs.Write_log("ERROR", fmt.Sprintf("Erreur lors du chiffrement asymétrique : %v", err))
			return
		}
		cipherMsg = string(cipherBytes) // ou Base64 si nécessaire
	}

	// 3. Préparation du paquet (Header + Size + Payload)
	// Construction de la trame : [1 byte HeaderSize][2 bytes MessageSize][Payload].
	// Trop grande, elle n'est pas émise et la connexion reste ouverte : rien
	// n'est parti, le flux est intact.
	data, err := CadrerTrame([]byte(cipherMsg))
	if err != nil {
		logs.Write_log("ERROR", err.Error())
		return
	}

	// 4. Envoi sur la connexion
	_, err = duckysession.Conn.Write(data)
	if err != nil {
		logs.Write_log("ERROR", fmt.Sprintf("Échec d'envoi au serveur: %v", err))
		// CRITIQUE : Si l'envoi échoue, on force la fermeture du socket.
		// Cela va débloquer la goroutine handleConnection qui est en train de Read()
		duckysession.Conn.Close()
		return
	}
}
