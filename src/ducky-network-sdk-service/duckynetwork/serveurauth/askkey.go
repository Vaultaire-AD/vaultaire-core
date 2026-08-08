package serveurauth

import (
	"duckynetworkclient/V1/duckynetwork/logs"
	"duckynetworkclient/V1/duckynetwork/sendmessage"
	"duckynetworkclient/V1/duckynetwork/storage"
	tramesmanager "duckynetworkclient/V1/duckynetwork/trames_manager"
	"fmt"
	"strings"
)

func AskServerKey(duckysession *storage.DuckySession) bool {
	message := []byte("askkey")
	messageSize := sendmessage.CompileMessageSize(message)
	headerSize := []byte{sendmessage.CompileHeaderSize(messageSize)}
	data := append(append(headerSize, messageSize...), message...)
	if _, err := duckysession.Conn.Write(data); err != nil {
		defer func() {
			if err := duckysession.Conn.Close(); err != nil {
				// Handle or log the error
				logs.Write_log("ERROR", fmt.Sprintf("Erreur lors de la fermeture du fichier: %v", err))
			}
		}()
		logs.Write_log("ERROR", fmt.Sprintf("Erreur lors de l'envoi du message : %v", err))
		return false
	}

	for {
		headerSize, err := tramesmanager.Read_Header_Size(duckysession.Conn)
		if err != nil {
			logs.Write_log("ERROR", fmt.Sprintf("Erreur lors de la lecture du header : %v", err))
			return false
		}
		if headerSize != 0 {
			messagesize, err := tramesmanager.Read_Message_Size(duckysession.Conn, headerSize)
			if err != nil {
				logs.Write_log("ERROR", fmt.Sprintf("Erreur lors de la lecture de la taille du message : %v", err))
				return false
			}
			messageBuf := make([]byte, messagesize)
			_, err = duckysession.Conn.Read(messageBuf)
			if err != nil {
				logs.Write_log("ERROR", fmt.Sprintf("Erreur lors de la lecture du message : %v", err))
			}
			lines := strings.Split(string(messageBuf), "\n")
			if lines[0] == "getkey" {
				clePEM := strings.Join(lines[1:], "\n")

				// Le point d'acceptation. Voir coretrust.go : la clé écrite ici
				// ne sera plus jamais redemandée, HaveServeurKey se contentant
				// de constater la présence du fichier.
				avertissement, err := VerifierCleCore(clePEM)
				if err != nil {
					logs.Write_log("CRITICAL", "clé du core refusée : "+err.Error())
					return false
				}
				if avertissement != "" {
					logs.Write_log("WARNING", avertissement)
				} else {
					empreinte, _ := EmpreinteClePublique(clePEM)
					logs.Write_log("INFO", "clé du core vérifiée contre l'empreinte de référence : "+empreinte)
				}

				if err := WriteToFile(clePEM); err != nil {
					logs.Write_log("ERROR", fmt.Sprintf("Erreur lors de l'écriture du fichier : %v", err))
					return false
				}
				return true
			}

		}
	}

}
