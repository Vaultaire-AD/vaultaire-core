package serveur

// Enrôlement d'un client service — trames 01_03 à 01_06.
//
// Un client SERVICE génère sa paire de clés sur son propre hôte et vient faire
// enregistrer sa clé PUBLIQUE en présentant une clé d'enrôlement. Sa clé privée
// ne voyage jamais, contrairement à celle d'un agent de poste, que le core génère
// et livre avec sa configuration.
//
// # Pourquoi cette trame échappe au contrôle par type de client
//
// Elle le précède : au moment où elle arrive, le client n'existe pas, donc son
// type non plus. C'est la clé d'enrôlement qui l'autorise, et c'est LE TYPE
// PORTÉ PAR LA CLÉ qui décide de ce que le service pourra émettre ensuite.
//
// Le service ne déclare donc jamais son type. S'il le pouvait, il suffirait de
// s'enrôler pour se déclarer `vaultaire_web` et obtenir avec lui le droit d'agir
// au nom de n'importe quel utilisateur de l'annuaire.

import (
	"crypto/rsa"
	"crypto/x509"
	"database/sql"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"fmt"
	"net"
	"strings"

	"vaultaire/core/clienttype"
	"vaultaire/core/database"
	dbclients "vaultaire/core/database/db_clients"
	dbenrollment "vaultaire/core/database/db_enrollment"
	"vaultaire/core/logs"
	"vaultaire/core/storage"
	keymanagement "vaultaire/ducky-network/key_management"
	"vaultaire/ducky-network/sendmessage"
)

// minimumKeyBits refuse une clé trop courte pour le tunnel.
//
// Le projet génère du RSA-4096 partout. On accepte 2048 pour ne pas casser un
// service tiers raisonnable, mais pas moins : sous cette taille, la charge utile
// OAEP ne suffirait même plus aux trames d'authentification.
const minimumKeyBits = 2048

// HandleEnrollment traite une trame 01_03 et répond 01_04, 01_05 ou 01_06.
//
// Retourne toujours la chaîne vide : la réponse est envoyée ici plutôt que
// remontée à Split_Action, parce qu'elle doit être chiffrée avec la clé publique
// du client qui vient d'être créé — un identifiant que la trame entrante ne
// portait pas.
func HandleEnrollment(trames storage.Trames_struct_client, duckysession *storage.DuckySession) string {
	source := remoteIP(duckysession)

	lines := strings.Split(strings.TrimSpace(trames.Content), "\n")
	if len(lines) < 2 {
		logs.Write_Log("WARNING", "enrôlement: trame 01_03 malformée depuis "+source)
		replyDenied(duckysession, "invalid_request")
		return ""
	}
	secret := strings.TrimSpace(lines[0])
	encodedKey := strings.TrimSpace(lines[1])
	label := ""
	if len(lines) >= 3 {
		label = strings.TrimSpace(lines[2])
	}

	// La clé publique est validée AVANT de consommer une utilisation : une clé
	// publique illisible ne doit pas coûter un jeton d'enrôlement à
	// l'administrateur qui l'a émis.
	publicKeyPEM, err := decodeSubmittedPublicKey(encodedKey)
	if err != nil {
		logs.Write_Log("WARNING", "enrôlement: clé publique refusée depuis "+source+" : "+err.Error())
		replyDenied(duckysession, "bad_public_key")
		return ""
	}

	db := database.GetDatabase()

	reservation, err := dbenrollment.Reserve(db, secret)
	if err != nil {
		// Le motif exact est journalisé côté serveur mais N'EST PAS renvoyé.
		//
		// Distinguer « expirée » de « inconnue » ferait du point d'enrôlement un
		// oracle : l'attaquant apprendrait qu'une clé a existé, donc que son
		// format est le bon, donc où concentrer ses essais.
		logs.Write_Log("SECURITY", fmt.Sprintf(
			"enrôlement refusé depuis %s : %v", source, err))
		if isKeyError(err) {
			replyDenied(duckysession, "invalid_key")
		} else {
			replyDenied(duckysession, "server_error")
		}
		return ""
	}

	// Le type est re-vérifié à la consommation. Une clé émise pour un type
	// retiré du catalogue depuis doit être refusée, pas enrôler un service que
	// plus rien ne décrit.
	if err := clienttype.Validate(reservation.ClientType); err != nil || !clienttype.IsService(reservation.ClientType) {
		logs.Write_Log("SECURITY", fmt.Sprintf(
			"enrôlement refusé depuis %s : la clé %d vise le type %q, qui n'est plus un service valide",
			source, reservation.KeyID, reservation.ClientType))
		release(db, reservation)
		replyDenied(duckysession, "unknown_type")
		return ""
	}

	computeurID, err := newServiceID()
	if err != nil {
		logs.Write_LogCode("ERROR", logs.CodeInternal, "enrôlement: génération d'identifiant : "+err.Error())
		release(db, reservation)
		replyDenied(duckysession, "server_error")
		return ""
	}

	// isServeur = false : un service n'est pas un serveur membre du domaine. Ce
	// drapeau commande la distribution des GPO et l'inventaire, dont un service
	// n'a que faire.
	if err := dbclients.Create_ClientSoftware(db, computeurID, reservation.ClientType, publicKeyPEM, false); err != nil {
		logs.Write_LogCode("ERROR", logs.CodeDBQuery, "enrôlement: création du client : "+err.Error())
		release(db, reservation)
		replyDenied(duckysession, "server_error")
		return ""
	}

	// Le client existe : l'utilisation est définitivement consommée.
	if err := dbenrollment.Confirm(db, reservation, computeurID, source); err != nil {
		// La trace est perdue, le service est créé. On ne défait rien : annuler
		// la création laisserait un jeton consommé sans client, ce qui est le
		// pire des deux. L'échec est journalisé, il reste visible.
		logs.Write_Log("WARNING", "enrôlement: trace de consommation non écrite pour "+computeurID)
	}

	logs.Write_Log("SECURITY", fmt.Sprintf(
		"enrôlement: service %s créé, type %s, libellé %q, depuis %s",
		computeurID, reservation.ClientType, label, source))

	// La réponse est chiffrée avec la clé publique qui vient d'être enregistrée.
	// Seul le détenteur de la clé privée correspondante peut donc lire son
	// identifiant : la preuve de possession est acquise sans défi explicite,
	// exactement comme en 01_02.
	message := fmt.Sprintf("01_04\nserver_central\n\n%s\n%s", computeurID, reservation.ClientType)
	if err := sendmessage.SendMessage(message, computeurID, duckysession); err != nil {
		logs.Write_Log("ERROR", "enrôlement: envoi de 01_04 échoué : "+err.Error())
	}
	return ""
}

// decodeSubmittedPublicKey valide la clé publique reçue et la renormalise.
//
// Le client l'envoie en base64 parce que le format de trame est ligne à ligne et
// qu'un PEM en contient plusieurs.
//
// La clé est reconstruite avec le sérialiseur du projet plutôt que stockée telle
// que reçue : c'est ce qui garantit que la forme en base est exactement celle que
// le chemin de déchiffrement sait relire, quelle que soit la variante de PEM
// produite par le client.
func decodeSubmittedPublicKey(encoded string) (string, error) {
	raw, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		return "", fmt.Errorf("base64 illisible : %w", err)
	}
	block, _ := pem.Decode(raw)
	if block == nil || (block.Type != "PUBLIC KEY" && block.Type != "RSA PUBLIC KEY") {
		return "", errors.New("bloc PEM absent ou de type inattendu")
	}
	parsed, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return "", fmt.Errorf("clé publique illisible : %w", err)
	}
	rsaKey, ok := parsed.(*rsa.PublicKey)
	if !ok {
		return "", errors.New("seules les clés RSA sont acceptées")
	}
	if bits := rsaKey.N.BitLen(); bits < minimumKeyBits {
		return "", fmt.Errorf("clé de %d bits, minimum %d", bits, minimumKeyBits)
	}
	return keymanagement.Convert_Public_Key_To_String(rsaKey), nil
}

// newServiceID tire un identifiant de machine pour le service.
func newServiceID() (string, error) {
	return generateServiceRandomID(12)
}

func release(db *sql.DB, r dbenrollment.Reservation) {
	if err := dbenrollment.Release(db, r); err != nil {
		logs.Write_Log("ERROR", "enrôlement: restitution de l'utilisation échouée : "+err.Error())
	}
}

func isKeyError(err error) bool {
	return errors.Is(err, dbenrollment.ErrUnknownKey) ||
		errors.Is(err, dbenrollment.ErrExpiredKey) ||
		errors.Is(err, dbenrollment.ErrExhaustedKey) ||
		errors.Is(err, dbenrollment.ErrRevokedKey)
}

// replyDenied envoie 01_05 en CLAIR.
//
// Le serveur n'a pas forcément de clé publique exploitable à ce stade : c'est
// précisément ce qui peut avoir échoué. Le refus ne contient aucun secret, seulement
// un code.
func replyDenied(duckysession *storage.DuckySession, code string) {
	message := "01_05\nserver_central\n\n" + code
	data := []byte(message)
	size := sendmessage.CompileMessageSize(data)
	header := []byte{sendmessage.CompileHeaderSize(size)}
	if _, err := duckysession.Conn.Write(append(append(header, size...), data...)); err != nil {
		logs.Write_Log("ERROR", "enrôlement: envoi du refus échoué : "+err.Error())
	}
}

// remoteIP extrait l'adresse d'origine, pour la trace de consommation.
func remoteIP(duckysession *storage.DuckySession) string {
	if duckysession == nil || duckysession.Conn == nil {
		return ""
	}
	addr := duckysession.Conn.RemoteAddr()
	if addr == nil {
		return ""
	}
	host, _, err := net.SplitHostPort(addr.String())
	if err != nil {
		return addr.String()
	}
	return host
}
