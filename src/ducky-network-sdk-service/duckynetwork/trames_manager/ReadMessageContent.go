package tramesmanager

import (
	keyencodedecode "duckynetworkclient/V1/duckynetwork/key_encode_decode"
	"duckynetworkclient/V1/duckynetwork/keymanagement"
	"duckynetworkclient/V1/duckynetwork/logs"
	"duckynetworkclient/V1/duckynetwork/storage"
	"fmt"
	"strings"
)

// lignesMinimales : code, destination, clé d'intégrité. Une trame du core en
// a toujours au moins autant (sendmessage.BuildServerTrame côté core).
const lignesMinimales = 3

// ParseTrames découpe une trame déchiffrée.
//
// # Le garde-fou qui manquait de ce côté (TO-DO 101)
//
// Le core refuse une trame trop courte depuis l'audit de la 2.1 ; le SDK
// indexait lines[1], lines[2] et lines[3:] sans rien vérifier. Une trame d'une
// ligne paniquait donc chez l'agent, le proxy, Nexus et le client Windows.
// Une trame trop courte rend une structure VIDE, que Split_Action et
// l'enrôlement savent déjà écarter (Message_Order vide).
func ParseTrames(trames string) storage.Trames_struct_client {
	lines := strings.Split(trames, "\n")

	if len(lines) < lignesMinimales {
		logs.Write_log("WARNING", fmt.Sprintf(
			"trames: trame incomplète reçue (%d ligne(s), %d au minimum) — ignorée", len(lines), lignesMinimales))
		return storage.Trames_struct_client{}
	}

	message := strings.Join(lines[3:], "\n")
	action := strings.Split(lines[0], "_")

	return storage.Trames_struct_client{
		Message_Order:       action,
		Destination_Server:  lines[1],
		SessionIntegritykey: lines[2],
		Username:            "",
		Content:             message,
	}
}

// MessageReader lit le corps d'une trame et la traite.
//
// Une erreur rendue veut dire « fermer la connexion » : le corps n'a pas été
// lu en entier, la position dans le flux est perdue. Un échec de
// déchiffrement n'en est pas une — le corps a été lu jusqu'au bout — et il est
// journalisé ici.
func MessageReader(duckysession *storage.DuckySession, reconstructedMessageSize int) error {
	messageBuf, err := LireCorps(duckysession.Conn, reconstructedMessageSize)
	if err != nil {
		logs.Write_log("ERROR", fmt.Sprintf("Erreur lors de la lecture du message : %v", err))
		return err
	}

	var messageDecrypt string

	if duckysession.IsSafe {
		// Déchiffrement symétrique AES-GCM
		messageDecrypt, err = keyencodedecode.DecryptAESGCMString(duckysession.SessionKey, messageBuf)
		if err != nil {
			logs.Write_log("ERROR", fmt.Sprintf("Erreur lors du déchiffrement symétrique : %v", err))
			return nil
		}
	} else {
		// Déchiffrement asymétrique RSA
		privateKeyStr := keymanagement.Get_Client_Private_Key()
		messageDecrypt, err = keyencodedecode.DecryptMessageWithPrivate(privateKeyStr, messageBuf)
		if err != nil {
			logs.Write_log("ERROR", fmt.Sprintf("Erreur lors du déchiffrement RSA : %v", err))
			return nil
		}
	}

	// Traitement des trames
	trames_content := ParseTrames(messageDecrypt)
	Split_Action(trames_content, duckysession)
	return nil
}
