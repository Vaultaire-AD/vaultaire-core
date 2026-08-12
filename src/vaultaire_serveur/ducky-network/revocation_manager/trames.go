package revocationmanager

import (
	"fmt"
	"strconv"
	"strings"

	"vaultaire/core/database"
	dbrevocation "vaultaire/core/database/db_revocation"
	"vaultaire/core/logs"
	"vaultaire/core/revocation"
	"vaultaire/core/storage"
)

// Trames de la catégorie 06 — voir Protocole_Ducky.md.
//
//	06_01  revoke_order          serveur → client
//	  06_02  revoke_ack          client → serveur
//	  06_03  revoke_error        client → serveur
//	06_04  ask_revocations       client → serveur
//	  06_05  revocations_list    serveur → client
//	  06_06  revocations_error   serveur → client

// maxOrdersPerFrame borne le nombre d'ordres transmis en une fois.
//
// La taille d'une trame est bornée par un uint16 et la charge est
// base64(AES-GCM), soit environ 48 Kio utiles. Un ordre pèse une centaine
// d'octets ; 200 laisse une marge confortable. Au-delà, le client rappelle
// 06_04 et reçoit la suite.
const maxOrdersPerFrame = 200

// Revocation_Trame_Manager route les sous-ordres de la catégorie 06.
func Revocation_Trame_Manager(trames storage.Trames_struct_client, duckysession *storage.DuckySession) string {
	if len(trames.Message_Order) < 2 {
		logs.Write_Log("WARNING", "revocation: trame 06 sans sous-ordre")
		return ""
	}
	sub := trames.Message_Order[1]

	logs.Write_Log("DEBUG", fmt.Sprintf(
		"revocation: 06_%s reçue de %s (%d octets de contenu)",
		sub, trames.ClientSoftwareID, len(trames.Content)))

	switch sub {
	case "02":
		return handleAck(trames)
	case "03":
		return handleError(trames)
	case "04":
		return handleAskRevocations(trames)
	case "01", "05", "06":
		// Trames que le SERVEUR émet. Les recevoir signale un client qui rejoue
		// nos propres messages, ou un début de confusion de rôles : on le
		// signale plutôt que de l'ignorer en silence.
		logs.Write_Log("WARNING", fmt.Sprintf(
			"revocation: sous-ordre 06_%s inattendu en réception serveur (client %s)",
			sub, trames.ClientSoftwareID))
		return ""
	default:
		logs.Write_Log("WARNING", "revocation: sous-ordre 06_"+sub+" inconnu")
		return ""
	}
}

// buildOrderFrame construit la trame 06_01.
func buildOrderFrame(sessionKey string, order revocation.Order) string {
	return strings.Join([]string{
		"06_01",
		"serveur_central",
		sessionKey,
		strconv.Itoa(order.ID),
		string(order.Mode),
		order.Username,
		string(order.Reason),
	}, "\n")
}

// handleAck traite 06_02 : une machine confirme avoir appliqué un ordre.
func handleAck(trames storage.Trames_struct_client) string {
	lines := strings.Split(trames.Content, "\n")
	orderID, err := strconv.Atoi(strings.TrimSpace(lineAt(lines, 0)))
	if err != nil || orderID <= 0 {
		logs.Write_Log("WARNING", fmt.Sprintf(
			"revocation: acquittement à identifiant illisible de %s", trames.ClientSoftwareID))
		return ""
	}
	result := revocation.Result(strings.TrimSpace(lineAt(lines, 1)))
	if !revocation.IsValidResult(result) {
		logs.Write_Log("WARNING", fmt.Sprintf(
			"revocation: résultat inconnu %q de %s pour l'ordre %d",
			result, trames.ClientSoftwareID, orderID))
		return ""
	}

	db := database.GetDatabase()
	if db == nil {
		return ""
	}
	// Les trois résultats sont des succès : « compte absent » sur une machine
	// où l'utilisateur ne s'est jamais connecté n'est pas un échec, et le
	// marquer comme tel provoquerait un rejeu sans fin.
	if err := dbrevocation.MarkTarget(db, orderID, trames.ClientSoftwareID,
		revocation.StatusAcked, string(result)); err != nil {
		logs.Write_Log("ERROR", "revocation: enregistrement de l'acquittement échoué : "+err.Error())
		return ""
	}

	logs.Write_Log("INFO", fmt.Sprintf(
		"revocation: ordre %d acquitté par %s (%s)", orderID, trames.ClientSoftwareID, result))

	// Pas de réponse : l'acquittement clôt l'échange. Répondre déclencherait un
	// aller-retour supplémentaire sans rien apporter.
	return ""
}

// handleError traite 06_03 : une machine signale un échec.
func handleError(trames storage.Trames_struct_client) string {
	lines := strings.Split(trames.Content, "\n")
	orderID, err := strconv.Atoi(strings.TrimSpace(lineAt(lines, 0)))
	if err != nil || orderID <= 0 {
		logs.Write_Log("WARNING", "revocation: rapport d'erreur à identifiant illisible de "+trames.ClientSoftwareID)
		return ""
	}
	code := strings.TrimSpace(lineAt(lines, 1))
	message := strings.TrimSpace(lineAt(lines, 2))

	db := database.GetDatabase()
	if db == nil {
		return ""
	}
	if err := dbrevocation.MarkTarget(db, orderID, trames.ClientSoftwareID,
		revocation.StatusFailed, code+" : "+message); err != nil {
		logs.Write_Log("ERROR", "revocation: enregistrement de l'échec impossible : "+err.Error())
	}

	// Niveau ERROR : une machine qui n'a pas pu couper un compte reste un accès
	// ouvert pour la personne révoquée. C'est un incident, pas une information.
	logs.Write_Log("ERROR", fmt.Sprintf(
		"revocation: ordre %d EN ÉCHEC sur %s — %s : %s (sera rejoué)",
		orderID, trames.ClientSoftwareID, code, message))

	return ""
}

// handleAskRevocations traite 06_04 et répond 06_05 ou 06_06.
//
// Appelée par l'agent après authentification, à chaque démarrage et à chaque
// reconnexion. C'est le chemin de rattrapage : une machine éteinte au moment du
// déclenchement récupère ici les ordres qu'elle a manqués.
func handleAskRevocations(trames storage.Trames_struct_client) string {
	db := database.GetDatabase()
	if db == nil {
		return replyError(trames.SessionIntegritykey, revocation.ErrInternal, "base indisponible")
	}

	orders, err := dbrevocation.PendingOrdersForClient(db, trames.ClientSoftwareID, maxOrdersPerFrame)
	if err != nil {
		logs.Write_Log("ERROR", "revocation: lecture des ordres en attente échouée : "+err.Error())
		return replyError(trames.SessionIntegritykey, revocation.ErrInternal, "lecture impossible")
	}

	if len(orders) == 0 {
		logs.Write_Log("DEBUG", "revocation: aucun ordre en attente pour "+trames.ClientSoftwareID)
	} else {
		logs.Write_Log("INFO", fmt.Sprintf(
			"revocation: %d ordre(s) en attente remis à %s", len(orders), trames.ClientSoftwareID))
	}

	parts := []string{"06_05", "serveur_central", trames.SessionIntegritykey, strconv.Itoa(len(orders))}
	for _, o := range orders {
		parts = append(parts, strings.Join([]string{
			strconv.Itoa(o.ID), string(o.Mode), o.Username, string(o.Reason),
		}, "|"))
	}
	return strings.Join(parts, "\n")
}

// replyError construit une trame 06_06.
func replyError(sessionKey, code, message string) string {
	return strings.Join([]string{"06_06", "serveur_central", sessionKey, code, message}, "\n")
}

// lineAt retourne la ligne demandée, ou la chaîne vide si elle n'existe pas.
//
// Un contenu tronqué ne doit pas provoquer de panique : les trames viennent du
// réseau, leur longueur n'est jamais acquise.
func lineAt(lines []string, i int) string {
	if i < 0 || i >= len(lines) {
		return ""
	}
	return lines[i]
}
