package revocation

import (
	"fmt"
	"strconv"
	"strings"
	"vaultaire_client/pamstate"

	"duckynetworkclient/V1/duckynetwork/logs"
	"duckynetworkclient/V1/duckynetwork/storage"
)

// Traitement des trames 06 côté agent.
//
//	06_01  revoke_order        reçue    -> on applique, puis 06_02 ou 06_03
//	06_04  ask_revocations     émise    -> au démarrage et à chaque reconnexion
//	06_05  revocations_list    reçue    -> on applique chaque ordre
//	06_06  revocations_error   reçue    -> journalisée, on réessaiera au cycle suivant

// Codes d'erreur renvoyés dans une trame 06_03.
const (
	errUnknownMode    = "unknown_mode"
	errCommandFailed  = "command_failed"
	errMalformedOrder = "malformed_order"
)

// HandleTrame traite un sous-ordre de la catégorie 06 et retourne la réponse à
// envoyer, ou la chaîne vide s'il n'y a rien à répondre.
func HandleTrame(sub, sessionKey, content string) string {
	switch sub {
	case "01":
		return handleOrder(sessionKey, content)
	case "05":
		return handleOrderList(sessionKey, content)
	case "06":
		lines := strings.Split(content, "\n")
		logs.Write_log("WARNING", fmt.Sprintf(
			"revocation: le serveur refuse la demande d'ordres (%s) : %s",
			lineAt(lines, 0), lineAt(lines, 1)))
		return ""
	default:
		logs.Write_log("WARNING", "revocation: sous-ordre 06_"+sub+" inattendu côté client")
		return ""
	}
}

// AskPendingFrame construit la trame 06_04.
//
// Émise après authentification, à chaque démarrage et à chaque reconnexion.
// C'est le rattrapage : une machine éteinte au moment d'une révocation récupère
// ici les ordres qu'elle a manqués. Sans ça, éteindre son poste suffirait à
// échapper à une révocation.
func AskPendingFrame(sessionKey string) string {
	return strings.Join([]string{
		"06_04",
		"serveur_central",
		sessionKey,
		pamstate.Username,
		storage.Computeur_ID,
	}, "\n")
}

// handleOrder traite 06_01 : un ordre unique, poussé par le serveur.
func handleOrder(sessionKey, content string) string {
	lines := strings.Split(content, "\n")
	orderID, err := strconv.Atoi(strings.TrimSpace(lineAt(lines, 0)))
	if err != nil || orderID <= 0 {
		logs.Write_log("ERROR", "revocation: ordre reçu avec un identifiant illisible")
		return errorFrame(sessionKey, 0, errMalformedOrder, "identifiant illisible")
	}
	mode := strings.TrimSpace(lineAt(lines, 1))
	username := strings.TrimSpace(lineAt(lines, 2))
	reason := strings.TrimSpace(lineAt(lines, 3))

	return applyAndReply(sessionKey, orderID, mode, username, reason)
}

// handleOrderList traite 06_05 : les ordres en attente, après une demande 06_04.
//
// Les ordres sont appliqués DANS L'ORDRE reçu, du plus ancien au plus récent.
// Un verrouillage suivi d'un déverrouillage doit être rejoué dans cet ordre,
// sinon la machine finirait verrouillée alors que le compte a été rétabli.
//
// Une seule réponse est renvoyée ici — celle du premier ordre traité — parce
// qu'une trame ne porte qu'un message. Les suivantes partent par la connexion
// via SendPending, appelé par le cycle de l'agent.
func handleOrderList(sessionKey, content string) string {
	lines := strings.Split(content, "\n")
	count, err := strconv.Atoi(strings.TrimSpace(lineAt(lines, 0)))
	if err != nil {
		logs.Write_log("ERROR", "revocation: liste d'ordres au format inattendu")
		return ""
	}
	if count == 0 {
		logs.Write_log("DEBUG", "revocation: aucun ordre en attente")
		return ""
	}

	logs.Write_log("INFO", fmt.Sprintf("revocation: %d ordre(s) en attente reçu(s) du serveur", count))

	var firstReply string
	for i := 1; i < len(lines); i++ {
		raw := strings.TrimSpace(lines[i])
		if raw == "" {
			continue
		}
		parts := strings.Split(raw, "|")
		if len(parts) < 4 {
			logs.Write_log("WARNING", "revocation: ligne d'ordre malformée ignorée : "+raw)
			continue
		}
		orderID, err := strconv.Atoi(strings.TrimSpace(parts[0]))
		if err != nil || orderID <= 0 {
			logs.Write_log("WARNING", "revocation: identifiant d'ordre illisible ignoré : "+parts[0])
			continue
		}
		reply := applyAndReply(sessionKey, orderID, parts[1], parts[2], parts[3])
		if firstReply == "" {
			firstReply = reply
		} else {
			queueReply(reply)
		}
	}
	return firstReply
}

// applyAndReply exécute un ordre et construit la trame de réponse.
func applyAndReply(sessionKey string, orderID int, mode, username, reason string) string {
	// Déjà appliqué : on ne rejoue pas, mais on ré-acquitte. Sans cet
	// acquittement, le serveur considérerait la machine comme n'ayant jamais
	// répondu et rejouerait l'ordre à chaque connexion, indéfiniment.
	if prev, ok := AlreadyApplied(orderID); ok {
		logs.Write_log("DEBUG", fmt.Sprintf(
			"revocation: ordre %d déjà appliqué le %s, ré-acquittement", orderID, prev.AppliedAt))
		return ackFrame(sessionKey, orderID, prev.Result)
	}

	logs.Write_log("WARNING", fmt.Sprintf(
		"revocation: ordre %d reçu — %s sur %s (motif %s)", orderID, mode, username, reason))

	result, err := Apply(mode, username)
	if err != nil {
		code := errCommandFailed
		if mode != ModeSoft && mode != ModeUnlock && mode != ModeHard {
			code = errUnknownMode
		}
		logs.Write_log("ERROR", fmt.Sprintf(
			"revocation: ordre %d EN ÉCHEC sur %s : %v", orderID, username, err))
		return errorFrame(sessionKey, orderID, code, err.Error())
	}

	RecordApplied(orderID, mode, username, result)
	return ackFrame(sessionKey, orderID, result)
}

// ackFrame construit une trame 06_02.
func ackFrame(sessionKey string, orderID int, result string) string {
	return strings.Join([]string{
		"06_02", "serveur_central", sessionKey,
		pamstate.Username, storage.Computeur_ID,
		strconv.Itoa(orderID), result,
	}, "\n")
}

// errorFrame construit une trame 06_03.
func errorFrame(sessionKey string, orderID int, code, message string) string {
	// Le message part vers le serveur et finit en base : borné, et sur une
	// seule ligne, sinon il décalerait la lecture des champs suivants.
	message = strings.ReplaceAll(message, "\n", " ")
	if len(message) > 300 {
		message = message[:300]
	}
	return strings.Join([]string{
		"06_03", "serveur_central", sessionKey,
		pamstate.Username, storage.Computeur_ID,
		strconv.Itoa(orderID), code, message,
	}, "\n")
}

// lineAt retourne la ligne demandée, ou la chaîne vide si elle n'existe pas.
func lineAt(lines []string, i int) string {
	if i < 0 || i >= len(lines) {
		return ""
	}
	return lines[i]
}
