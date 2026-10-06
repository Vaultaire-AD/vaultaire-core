package sendmessage

import (
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"math"
	"strings"
	"vaultaire/core/logs"
	"vaultaire/core/storage"
	keydecodeencode "vaultaire/ducky-network/key_decode_encode"
)

// Côté serveur
func BuildServerTrame(action, dest, sessionKey string, contentLines ...string) string {
	parts := []string{action, dest, sessionKey}
	parts = append(parts, contentLines...)
	return strings.Join(parts, "\n")
}

// TailleMaxCorps est la plus grande taille de corps que le champ taille, sur
// deux octets, peut annoncer. Même valeur que tramesmanager.TailleMaxCorps et
// que le SDK : les trois doivent bouger ensemble, ou pas du tout.
const TailleMaxCorps = math.MaxUint16

// CompileMessageSize encode la taille du corps sur deux octets.
//
// # Une ERREUR, jamais une troncature
//
// Elle faisait `uint16(len(message))` : au-delà de 65535 octets, le corps
// entier partait sur le socket, annoncé modulo 65536. Le pair lisait le
// début, prenait la suite pour un nouvel en-tête, et le tunnel restait
// désynchronisé jusqu'à sa fermeture. La trame 02_04 porte toutes les clés
// SSH d'un compte : un compte trop garni cassait ainsi l'authentification
// Ducky de tout le poste (TO-DO 101).
//
// Une trame trop grande n'a pas d'émission correcte possible. Le refus laisse
// au moins le tunnel intact : la trame suivante partira, et arrivera.
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

// surchargeAESGCM est ce qu'AES-GCM ajoute à un message : douze octets de
// nonce devant, seize d'étiquette d'authentification derrière.
const surchargeAESGCM = 12 + 16

// TailleChiffree rend la taille du corps qu'un message de n octets occupera sur
// le fil d'une session établie : chiffré en AES-GCM, puis encodé en base64,
// comme SendMessage le fait.
//
// Un CALCUL, pour ne pas chiffrer deux fois : qui veut savoir si une trame
// partira n'a besoin que de sa longueur. Le test TestTailleChiffree le tient
// égal à ce que le chiffrement rend réellement.
func TailleChiffree(n int) int {
	return base64.StdEncoding.EncodedLen(n + surchargeAESGCM)
}

// TientDansUneTrame dit si un message partira sur une session établie, ou si
// CadrerTrame le refusera pour sa taille (TO-DO 138).
//
// À demander AVANT de s'engager : SendMessage ne sait pas ce que porte la trame
// qu'il refuse, et son erreur ne peut nommer ni le compte ni la cause.
func TientDansUneTrame(message string) bool {
	return TailleChiffree(len(message)) <= TailleMaxCorps
}

// CadrerTrame rend la trame prête à écrire : longueur du champ taille, taille,
// corps. C'est le seul assemblage à employer — les trois copies qui
// existaient faisaient la même conversion sans contrôle.
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

func SendMessage(message string, clientSoftwareID string, duckysession *storage.DuckySession) error {
	meta := logs.WithMeta(duckysession.SessionID, clientSoftwareID)

	if duckysession.Conn == nil {
		logs.Write_LogCodeMeta("ERROR", logs.CodeNone, "Connection is nil", meta)
		return fmt.Errorf("connection is nil")
	}

	var cipherMsg string
	var err error

	if duckysession.IsSafe {
		// Chiffrement symétrique AES-GCM
		cipherMsg, err = keydecodeencode.EncryptAESGCMString(duckysession.SessionKey, message)
		if err != nil {
			logs.Write_LogCodeMeta("ERROR", logs.CodeNone, "Error during symmetric encryption: "+err.Error(), meta)
			return err
		}
	} else {
		// Chiffrement asymétrique RSA
		cipherBytes, err := keydecodeencode.EncryptMessageWithClientPublic(message, clientSoftwareID)
		if err != nil {
			logs.Write_LogCodeMeta("ERROR", logs.CodeNone, "Error during asymmetric encryption: "+err.Error(), meta)
			return err
		}
		cipherMsg = string(cipherBytes)
	}

	// Prépare le header et la taille du message.
	//
	// Une trame trop grande n'est PAS émise, et la connexion n'est pas fermée :
	// rien n'est parti, le flux est intact. L'erreur nomme la taille, seul
	// indice qui permette de remonter à la cause (des clés SSH trop
	// nombreuses, typiquement).
	data, err := CadrerTrame([]byte(cipherMsg))
	if err != nil {
		logs.Write_LogCodeMeta("ERROR", logs.CodeNone, err.Error(), meta)
		return err
	}

	// Envoi du message
	if _, err := duckysession.Conn.Write(data); err != nil {
		logs.Write_LogCodeMeta("ERROR", logs.CodeNone, "Error sending message: "+err.Error(), meta)
		if cerr := duckysession.Conn.Close(); cerr != nil {
			logs.Write_LogCodeMeta("ERROR", logs.CodeNone, "Error closing connection: "+cerr.Error(), meta)
		}
		return err
	}

	return nil
}
