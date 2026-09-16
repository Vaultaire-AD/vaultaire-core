package enrollment

import (
	"duckynetworkclient/V1/config"
	keyencodedecode "duckynetworkclient/V1/duckynetwork/key_encode_decode"
	"duckynetworkclient/V1/duckynetwork/keymanagement"
	"duckynetworkclient/V1/duckynetwork/logs"
	"duckynetworkclient/V1/duckynetwork/sendmessage"
	"duckynetworkclient/V1/duckynetwork/storage"
	tramesmanager "duckynetworkclient/V1/duckynetwork/trames_manager"
	"encoding/base64"
	"fmt"
	"io"
	"strings"
)

// requestEnrollment envoie 01_05 puis lit 01_06.
func requestEnrollment(session *storage.DuckySession, enroll config.EnrollmentConfig, tmpKey []byte) (Identity, error) {
	// 01_05 part en RSA : IsSafe est faux, SendMessage chiffre donc avec la clé
	// publique du core. Les trois champs d'en-tête sont vides — il n'y a ni
	// session, ni utilisateur, ni identifiant machine à ce stade.
	message := sendmessage.BuildClientTrame(
		"01_05", "serveur_central", "", "", "",
		strings.TrimSpace(enroll.Key),
		base64.StdEncoding.EncodeToString(tmpKey),
		enroll.Label)
	session.IsSafe = false
	sendmessage.SendMessage(message, session)

	// La bascule se fait AVANT la lecture : le core répond déjà en AES avec la
	// clé temporaire. Lire d'abord et basculer ensuite ferait échouer le
	// déchiffrement de la toute première réponse.
	session.SessionKey = tmpKey
	session.IsSafe = true

	trames, err := readFrame(session)
	if err != nil {
		return Identity{}, err
	}
	if code := frameCode(trames); code != "01_06" {
		return Identity{}, denial(session, trames, code)
	}

	lines := strings.Split(strings.TrimSpace(trames.Content), "\n")
	if len(lines) < 2 || strings.TrimSpace(lines[0]) == "" {
		return Identity{}, fmt.Errorf("trame 01_06 incomplète : identifiant ou type manquant")
	}
	identity := Identity{
		ComputeurID: strings.TrimSpace(lines[0]),
		ClientType:  strings.TrimSpace(lines[1]),
	}
	logs.Write_log("INFO", fmt.Sprintf(
		"enrôlement: le core attribue %s, type %s", identity.ComputeurID, identity.ClientType))
	return identity, nil
}

// sendPublicKey envoie 01_07 puis lit 01_08.
func sendPublicKey(session *storage.DuckySession, identity Identity, publicPEM string) error {
	// La clé publique voyage en base64 : le format de trame est ligne à ligne,
	// et un PEM en contient plusieurs.
	//
	// Elle passe sous la clé temporaire, donc en AES : c'est tout l'objet du
	// détour, ces 800 octets ne tiendraient pas dans une enveloppe RSA.
	message := sendmessage.BuildClientTrame(
		"01_07", "serveur_central", "", "", identity.ComputeurID,
		base64.StdEncoding.EncodeToString([]byte(publicPEM)))
	sendmessage.SendMessage(message, session)

	// Retour à l'asymétrique : le core chiffre 01_08 avec la clé publique qu'on
	// vient de lui donner. Savoir la lire PROUVE qu'on détient la privée
	// correspondante — et si on ne le peut pas, on l'apprend maintenant plutôt
	// qu'à la première poignée de main d'une session ultérieure.
	session.IsSafe = false
	session.SessionKey = nil

	trames, err := readFrame(session)
	if err != nil {
		return fmt.Errorf("lecture de la confirmation : %w", err)
	}
	if code := frameCode(trames); code != "01_08" {
		return denial(session, trames, code)
	}
	return nil
}

// readFrame lit une trame et la déchiffre selon l'état de la session.
//
// Écrite ici plutôt que réutilisée depuis trames_manager parce que l'enrôlement
// lit de façon SYNCHRONE, réponse par réponse : la boucle de réception
// ordinaire, elle, aiguille vers le Spliter et ne rend rien à l'appelant.
func readFrame(session *storage.DuckySession) (storage.Trames_struct_client, error) {
	headerSize, err := tramesmanager.Read_Header_Size(session.Conn)
	if err != nil {
		return storage.Trames_struct_client{}, fmt.Errorf("lecture de l'en-tête : %w", err)
	}
	size, err := tramesmanager.Read_Message_Size(session.Conn, headerSize)
	if err != nil {
		return storage.Trames_struct_client{}, fmt.Errorf("lecture de la taille : %w", err)
	}
	buf := make([]byte, size)
	if _, err := io.ReadFull(session.Conn, buf); err != nil {
		return storage.Trames_struct_client{}, fmt.Errorf("lecture de la charge : %w", err)
	}

	// Un refus (01_09) arrive EN CLAIR : le core n'a pas toujours de quoi
	// chiffrer — pas de clé publique du service, et pas de clé temporaire
	// utilisable si c'est justement elle qui était malformée. On tente donc de
	// lire un refus AVANT de déchiffrer.
	if plain := string(buf); strings.HasPrefix(plain, "01_09") {
		return tramesmanager.ParseTrames(plain), nil
	}

	var clear string
	if session.IsSafe {
		clear, err = keyencodedecode.DecryptAESGCMString(session.SessionKey, buf)
	} else {
		clear, err = keyencodedecode.DecryptMessageWithPrivate(keymanagement.Get_Client_Private_Key(), buf)
	}
	if err != nil {
		return storage.Trames_struct_client{}, fmt.Errorf("déchiffrement : %w", err)
	}
	return tramesmanager.ParseTrames(clear), nil
}

// frameCode reconstitue le code complet d'une trame.
func frameCode(t storage.Trames_struct_client) string {
	if len(t.Message_Order) < 2 {
		return strings.Join(t.Message_Order, "_")
	}
	return t.Message_Order[0] + "_" + t.Message_Order[1]
}

// denial transforme une réponse inattendue en erreur lisible.
//
// Le core répond volontairement `invalid_key` pour cinq motifs distincts — clé
// inconnue, expirée, épuisée, révoquée, type disparu. Détailler ferait du point
// d'enrôlement un oracle. Le vrai motif est dans SON journal, pas ici : c'est là
// qu'il faut regarder.
func denial(session *storage.DuckySession, t storage.Trames_struct_client, code string) error {
	reason := strings.TrimSpace(t.Content)
	if code == "01_09" {
		return fmt.Errorf("enrôlement refusé (%s) — le motif exact est dans le journal du core", reason)
	}
	return fmt.Errorf("réponse inattendue à l'enrôlement : %s", code)
}
