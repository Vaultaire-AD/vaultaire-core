package serveur

// Enrôlement d'un client service — trames 01_05 à 01_09.
//
// Un client SERVICE génère sa paire de clés sur son propre hôte et vient faire
// enregistrer sa clé PUBLIQUE en présentant une clé d'enrôlement. Sa clé privée
// ne voyage jamais, contrairement à celle d'un agent de poste, que le core
// génère et livre avec sa configuration.
//
// # Le flux, et pourquoi il est en deux temps
//
//	01_05  →  clé d'enrôlement + clé de session TEMPORAIRE   (RSA, clé du core)
//	01_06  ←  identifiant attribué + type de client          (AES, clé temporaire)
//	01_07  →  clé publique du service                        (AES, clé temporaire)
//	01_08  ←  confirmation                                   (RSA, clé du service)
//	01_09  ←  refus, EN CLAIR
//
// Une clé publique RSA-4096 pèse environ 800 octets en PEM. Une charge RSA-OAEP
// sur clé 4096 en accepte 446. Elle NE PEUT DONC PAS voyager dans une enveloppe
// asymétrique — c'est structurel, aucun encodage n'y change rien.
//
// D'où la clé temporaire : le client l'envoie chiffrée en RSA, où elle tient
// sans peine, et elle ouvre un canal symétrique qui n'a plus de limite de taille.
// C'est le mécanisme de 01_02, avancé d'un cran pour servir avant même que le
// client existe.
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

// tmpKeyBytes est la taille attendue de la clé de session temporaire.
//
// AES-256, comme la clé de session ordinaire. Le client l'envoie en base64,
// le format de trame étant ligne à ligne.
const tmpKeyBytes = 32

// HandleEnrollRequest traite 01_05 et répond 01_06.
//
// Contenu attendu : clé d'enrôlement, clé temporaire en base64, libellé.
func HandleEnrollRequest(trames storage.Trames_struct_client, duckysession *storage.DuckySession) string {
	source := remoteIP(duckysession)

	lines := strings.Split(strings.TrimSpace(trames.Content), "\n")
	if len(lines) < 2 {
		logs.Write_Log("WARNING", "enrôlement: trame 01_05 malformée depuis "+source)
		replyDenied(duckysession, "invalid_request")
		return ""
	}
	secret := strings.TrimSpace(lines[0])
	label := ""
	if len(lines) >= 3 {
		label = strings.TrimSpace(lines[2])
	}

	// La clé temporaire est validée AVANT de consommer une utilisation : une clé
	// mal formée ne doit pas coûter un jeton à l'administrateur qui l'a émis.
	tmpKey, err := base64.StdEncoding.DecodeString(strings.TrimSpace(lines[1]))
	if err != nil || len(tmpKey) != tmpKeyBytes {
		logs.Write_Log("WARNING", fmt.Sprintf(
			"enrôlement: clé temporaire invalide depuis %s (%d octets attendus)", source, tmpKeyBytes))
		replyDenied(duckysession, "invalid_request")
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
		logs.Write_Log("SECURITY", fmt.Sprintf("enrôlement refusé depuis %s : %v", source, err))
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

	// Le client est créé SANS clé publique : il ne l'a pas encore envoyée, elle
	// vient en 01_07. La ligne existe donc un instant avec une clé vide.
	//
	// C'est inerte : un client sans clé publique ne peut rien faire, puisque la
	// poignée de main 01_01 lui répondrait un chiffré que personne ne sait lire.
	//
	// isServeur = false : un service n'est pas un serveur membre du domaine. Ce
	// drapeau commande la distribution des GPO et l'inventaire, dont un service
	// n'a que faire.
	if err := dbclients.Create_ClientSoftware(db, computeurID, reservation.ClientType, "", false); err != nil {
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

	// Bascule du canal : la clé temporaire devient la clé de session.
	//
	// À partir d'ici tout passe en AES-GCM, dans les deux sens, par le chemin
	// ordinaire. Rien de particulier à prévoir pour lire 01_07, qui portera une
	// clé publique de 800 octets — impossible à faire tenir en RSA.
	duckysession.SessionKey = tmpKey
	duckysession.IsSafe = true
	duckysession.EnrollmentComputeurID = computeurID
	duckysession.EnrollmentClientType = reservation.ClientType

	logs.Write_Log("SECURITY", fmt.Sprintf(
		"enrôlement: service %s créé, type %s, libellé %q, depuis %s — en attente de sa clé publique",
		computeurID, reservation.ClientType, label, source))

	return fmt.Sprintf("01_06\nserver_central\n\n%s\n%s", computeurID, reservation.ClientType)
}

// HandleEnrollPublicKey traite 01_07 et répond 01_08.
//
// Contenu attendu : la clé publique du service, PEM encodé en base64.
func HandleEnrollPublicKey(trames storage.Trames_struct_client, duckysession *storage.DuckySession) string {
	source := remoteIP(duckysession)

	// L'identifiant vient de la SESSION, jamais de la trame.
	//
	// Le lire dans la trame laisserait quiconque a passé un enrôlement écraser
	// la clé publique d'un AUTRE client, donc prendre sa place. C'est la seule
	// chose qui rend cette trame sûre.
	computeurID := duckysession.EnrollmentComputeurID
	if computeurID == "" {
		logs.Write_Log("SECURITY", "enrôlement: 01_07 reçue hors d'un enrôlement en cours, depuis "+source)
		return ""
	}

	publicKeyPEM, err := decodeSubmittedPublicKey(strings.TrimSpace(trames.Content))
	if err != nil {
		logs.Write_Log("WARNING", "enrôlement: clé publique refusée depuis "+source+" : "+err.Error())
		replyDenied(duckysession, "bad_public_key")
		return ""
	}

	db := database.GetDatabase()
	if err := dbclients.Update_Client_Software_PublicKey(db, computeurID, publicKeyPEM); err != nil {
		logs.Write_LogCode("ERROR", logs.CodeDBQuery, "enrôlement: enregistrement de la clé publique : "+err.Error())
		replyDenied(duckysession, "server_error")
		return ""
	}

	logs.Write_Log("SECURITY", fmt.Sprintf(
		"enrôlement: clé publique de %s enregistrée depuis %s — enrôlement terminé", computeurID, source))

	// La confirmation repasse en ASYMÉTRIQUE, chiffrée avec la clé publique qui
	// vient d'être enregistrée.
	//
	// Ce n'est pas décoratif : savoir la lire prouve que le service détient bien
	// la clé privée correspondante. S'il ne le peut pas, il vient d'enregistrer
	// une clé qu'il ne possède pas et il le découvre TOUT DE SUITE, au lieu de
	// s'en apercevoir à la première poignée de main d'une session ultérieure.
	duckysession.IsSafe = false
	duckysession.SessionKey = nil
	if err := sendmessage.SendMessage("01_08\nserver_central\n\nok", computeurID, duckysession); err != nil {
		logs.Write_Log("ERROR", "enrôlement: envoi de 01_08 échoué : "+err.Error())
	}

	// La connexion est fermée : elle a servi à l'enrôlement et n'est pas une
	// session. Le service rouvre une connexion neuve pour 01_01, avec son
	// identité cette fois. Laisser celle-ci ouverte donnerait un canal chiffré
	// sans machine liée ni type — précisément l'état que le fail-closed du
	// Spliter existe pour ne pas laisser traîner.
	duckysession.EnrollmentComputeurID = ""
	duckysession.EnrollmentClientType = ""
	if err := duckysession.Conn.Close(); err != nil {
		logs.Write_Log("DEBUG", "enrôlement: fermeture de la connexion : "+err.Error())
	}
	return ""
}

// decodeSubmittedPublicKey valide la clé publique reçue et la renormalise.
//
// Le client l'envoie en base64 parce que le format de trame est ligne à ligne et
// qu'un PEM en contient plusieurs.
//
// La clé est reconstruite avec le sérialiseur du projet plutôt que stockée telle
// que reçue : c'est ce qui garantit que la forme en base est exactement celle
// que le chemin de déchiffrement sait relire, quelle que soit la variante de PEM
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

// replyDenied envoie 01_09 en CLAIR, puis ferme.
//
// En clair parce que le serveur n'a rien pour chiffrer : pas de clé publique du
// client — c'est précisément ce qui peut manquer —, et pas de clé temporaire
// utilisable si c'est elle qui était malformée. Le refus ne contient aucun
// secret, seulement un code.
func replyDenied(duckysession *storage.DuckySession, code string) {
	message := "01_09\nserver_central\n\n" + code
	data := []byte(message)
	size := sendmessage.CompileMessageSize(data)
	header := []byte{sendmessage.CompileHeaderSize(size)}
	if _, err := duckysession.Conn.Write(append(append(header, size...), data...)); err != nil {
		logs.Write_Log("ERROR", "enrôlement: envoi du refus échoué : "+err.Error())
	}
	// L'état d'enrôlement est effacé et la connexion fermée : sans cela, un
	// client refusé garderait un canal ouvert et pourrait réessayer en boucle
	// sur la même connexion, ce qui contourne toute limitation par tentative.
	duckysession.EnrollmentComputeurID = ""
	duckysession.EnrollmentClientType = ""
	duckysession.IsSafe = false
	duckysession.SessionKey = nil
	if err := duckysession.Conn.Close(); err != nil {
		logs.Write_Log("DEBUG", "enrôlement: fermeture après refus : "+err.Error())
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
