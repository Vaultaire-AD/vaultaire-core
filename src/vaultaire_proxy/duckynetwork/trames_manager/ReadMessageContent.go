package tramesmanager

import (
	"io"
	"strings"

	keyencodedecode "vaultaire_proxy/duckynetwork/key_encode_decode"
	"vaultaire_proxy/duckynetwork/logs"
	"vaultaire_proxy/duckynetwork/storage"
)

// ParseTrames découpe une trame reçue.
//
// Les réponses du serveur portent trois champs d'en-tête — code, destination,
// clé de session — là où les trames montantes en portent cinq. Le découpage part
// donc de la ligne 3.
func ParseTrames(trames string) storage.Trames_struct_client {
	lines := strings.Split(trames, "\n")
	for len(lines) < 3 {
		lines = append(lines, "")
	}
	content := ""
	if len(lines) > 3 {
		content = strings.Join(lines[3:], "\n")
	}
	return storage.Trames_struct_client{
		Message_Order:       strings.Split(strings.TrimSpace(lines[0]), "_"),
		Destination_Server:  strings.TrimSpace(lines[1]),
		SessionIntegritykey: lines[2],
		Content:             content,
	}
}

// ReadPayload lit une charge complète depuis la connexion.
//
// io.ReadFull et non Read : une seule lecture peut rendre moins d'octets que
// demandé sur une trame fragmentée par TCP, et le déchiffrement échouerait alors
// sur un message tronqué — une panne intermittente, qui ne se reproduit qu'en
// charge.
func ReadPayload(session *storage.DuckySession) ([]byte, error) {
	headerSize, err := Read_Header_Size(session.Conn)
	if err != nil {
		return nil, err
	}
	size, err := Read_Message_Size(session.Conn, headerSize)
	if err != nil {
		return nil, err
	}
	buf := make([]byte, size)
	if _, err := io.ReadFull(session.Conn, buf); err != nil {
		return nil, err
	}
	return buf, nil
}

// Decrypt déchiffre une charge selon l'état de la session.
//
// C'est LE point où IsSafe décide : RSA tant que la clé de session n'est pas
// établie, AES-GCM ensuite. Le programme hôte n'a jamais à faire ce choix
// lui-même.
func Decrypt(session *storage.DuckySession, payload []byte, privateKeyPEM string) (string, error) {
	if session.IsSafe {
		return keyencodedecode.DecryptAESGCMString(session.SessionKey, payload)
	}
	return keyencodedecode.DecryptMessageWithPrivate(privateKeyPEM, payload)
}

// MessageReader lit, déchiffre et aiguille une trame.
//
// Boucle de réception du programme hôte : elle est appelée en continu tant que
// la connexion vit.
func MessageReader(session *storage.DuckySession, privateKeyPEM, serverPublicKeyPEM string, spliter *Spliter) error {
	payload, err := ReadPayload(session)
	if err != nil {
		return err
	}
	plain, err := Decrypt(session, payload, privateKeyPEM)
	if err != nil {
		logs.Write("ERROR", "déchiffrement de la trame : "+err.Error())
		return err
	}
	return spliter.Split_Action(ParseTrames(plain), session, serverPublicKeyPEM)
}
