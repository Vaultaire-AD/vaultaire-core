package revocation

import (
	"sync"

	"duckynetworkclient/V1/duckynetwork/logs"
)

// Émission de trames hors réponse directe.
//
// Le routeur de trames ne peut renvoyer QU'UNE réponse par message reçu. Or une
// trame 06_05 en apporte potentiellement plusieurs dizaines d'un coup, chacune
// devant être acquittée séparément. Les acquittements supplémentaires passent
// donc par l'émetteur injecté, exactement comme le paquet gpo pour ses demandes
// de fragments.
//
// Injecté plutôt qu'importé : la couche d'envoi a besoin de ce paquet pour
// router les trames 06, un import direct dans l'autre sens créerait un cycle.

// Sender envoie une trame vers le serveur.
type Sender func(trame string)

var (
	senderMu sync.RWMutex
	sender   Sender
)

// Configure installe l'émetteur de trames.
func Configure(send Sender) {
	senderMu.Lock()
	sender = send
	senderMu.Unlock()
	logs.Write_log("DEBUG", "revocation: transport configuré")
}

// queueReply émet une trame de réponse supplémentaire.
//
// Un échec d'envoi n'est pas rattrapé ici : l'ordre a été appliqué localement
// et enregistré, seul son acquittement manque. Le serveur le rejouera à la
// prochaine connexion, l'agent verra qu'il est déjà appliqué et ré-acquittera
// sans rien réexécuter. La boucle se referme d'elle-même.
func queueReply(trame string) {
	if trame == "" {
		return
	}
	senderMu.RLock()
	s := sender
	senderMu.RUnlock()

	if s == nil {
		logs.Write_log("WARNING", "revocation: transport non configuré, acquittement différé")
		return
	}
	s(trame)
}

// AskPending demande au serveur les ordres en attente pour cette machine.
//
// Appelée après authentification, à chaque démarrage et à chaque reconnexion du
// tunnel. C'est le seul chemin qui rattrape les ordres émis pendant que la
// machine était éteinte.
func AskPending(sessionKey string) {
	if sessionKey == "" {
		logs.Write_log("DEBUG", "revocation: pas de session, demande d'ordres différée")
		return
	}
	queueReply(AskPendingFrame(sessionKey))
	logs.Write_log("DEBUG", "revocation: demande des ordres en attente envoyée")
}
