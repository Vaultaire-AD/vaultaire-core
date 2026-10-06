package tramesmanager

import (
	"strings"
	"vaultaire/core/domain"
	"vaultaire/core/logs"
	"vaultaire/core/storage"
	keydecodeencode "vaultaire/ducky-network/key_decode_encode"
	keymanagement "vaultaire/ducky-network/key_management"
	"vaultaire/ducky-network/sendmessage"
)

func parseTrames(trames string) storage.Trames_struct_client {
	lines := strings.Split(trames, "\n")

	// SÉCURITÉ : Vérifier qu'on a au moins le minimum vital (5 lignes pour atteindre l'index 4)
	if len(lines) < 5 {
		logs.Write_Log("ERROR", "Trame incomplète reçue : pas assez de lignes")
		return storage.Trames_struct_client{} // Ou gérer l'erreur autrement
	}

	// Vérifier que nous avons exactement trois lignes
	message := strings.Join(lines[5:], "\n")
	action := strings.Split(lines[0], "_")

	username := lines[3]
	domaine := ""
	username, domaine = domain.ExctractDomainFromUsername(username)

	return storage.Trames_struct_client{
		Message_Order:       action,
		Destination_Server:  lines[1],
		SessionIntegritykey: lines[2],
		Username:            username,
		Domain:              domaine,
		ClientSoftwareID:    lines[4],
		Content:             message,
	}
}

// MessageReader lit le corps d'une trame et la traite.
//
// Une erreur rendue veut dire « fermer la connexion » : le corps n'a pas pu
// être lu en entier, donc la position dans le flux est perdue. Un échec de
// DÉCHIFFREMENT, lui, n'en est pas une : le corps a été lu jusqu'au bout, la
// trame suivante commence au bon endroit, et l'échec est journalisé ici.
func MessageReader(duckysession *storage.DuckySession, reconstructedMessageSize int) error {
	// lireCorps et non conn.Read : TCP peut rendre le corps en plusieurs
	// morceaux, et le reste passait pour l'en-tête suivant (TO-DO 101).
	messageBuf, err := lireCorps(duckysession.Conn, reconstructedMessageSize)
	if err != nil {
		logs.Write_Log("ERROR", "Error during the read of the message: "+err.Error())
		return err
	}
	//fmt.Println("taille du message recu : ", reconstructedMessageSize)
	if string(messageBuf) == "askkey" {
		datatosend, err := sendmessage.CadrerTrame([]byte("getkey\n" +
			keymanagement.GetPublicKey()))
		if err != nil {
			logs.Write_Log("ERROR", "askkey: "+err.Error())
			return nil
		}
		if _, err := duckysession.Conn.Write(datatosend); err != nil {
			err := duckysession.Conn.Close()
			if err != nil {
				logs.Write_Log("ERROR", "Error closing connection: "+err.Error())
			}
			logs.Write_Log("ERROR", "Error during the send of the message: "+err.Error())
			return nil
		}
		return nil
	}
	privateKeyStr := keymanagement.GetPrivateKey()
	var messageDecrypt string

	if duckysession.IsSafe {
		// Déchiffrement symétrique
		messageDecrypt, err = keydecodeencode.DecryptAESGCMString(duckysession.SessionKey, messageBuf)
		if err != nil {
			logs.Write_Log("ERROR", "Error during symmetric decryption: "+err.Error())
			return nil
		}
	} else {
		// Déchiffrement asymétrique RSA
		messageDecrypt, err = keydecodeencode.DecryptMessageWithPrivate(privateKeyStr, messageBuf)
		if err != nil {
			logs.Write_Log("ERROR", "Error during asymmetric decryption: "+err.Error())
			return nil
		}
	}
	var trames_content = parseTrames(messageDecrypt)
	Split_Action(trames_content, duckysession)
	return nil
}
