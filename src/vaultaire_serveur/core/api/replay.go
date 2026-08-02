package api

import (
	"fmt"
	"sync"
	"time"

	"vaultaire/core/logs"
)

// Protection contre le rejeu des commandes signées.
//
// La signature SSH prouve qui a écrit la requête, jamais quand. Sans horodatage
// ni mémoire des nonces, une requête capturée restait rejouable indéfiniment :
// il suffisait d'avoir vu passer un `delete -u ...` une fois pour le refaire à
// volonté, sans jamais posséder la clé privée.
//
// Deux verrous complémentaires, aucun ne suffit seul :
//
//   - l'horodatage borne la fenêtre d'attaque, mais à lui seul il laisse rejouer
//     autant qu'on veut pendant cette fenêtre ;
//   - le nonce à usage unique interdit le doublon, mais sans horodatage il
//     faudrait mémoriser tous les nonces pour toujours.
//
// Ensemble : on ne mémorise que la fenêtre courante, et rien n'y passe deux fois.

const (
	// replayWindow est la tolérance d'écart d'horloge entre client et serveur.
	//
	// Deux minutes : assez large pour des machines dont l'heure dérive un peu
	// sans NTP, assez étroite pour qu'une capture réseau n'ait pas d'intérêt
	// pratique. C'est aussi la durée pendant laquelle un nonce est mémorisé.
	replayWindow = 2 * time.Minute

	// replayPurgeEvery espace les nettoyages du registre. Purger à chaque appel
	// ferait payer un parcours complet à chaque commande.
	replayPurgeEvery = 30 * time.Second
)

// nonceRegistry mémorise les nonces vus dans la fenêtre courante.
type nonceRegistry struct {
	mu        sync.Mutex
	seen      map[string]time.Time
	lastPurge time.Time
}

var seenNonces = &nonceRegistry{seen: make(map[string]time.Time)}

// remember enregistre un nonce et dit s'il est nouveau.
//
// Le test et l'insertion sont faits sous le même verrou : deux requêtes
// identiques arrivant en parallèle ne doivent pas passer toutes les deux parce
// que chacune a vu le registre avant que l'autre n'écrive.
func (r *nonceRegistry) remember(nonce string, now time.Time) bool {
	r.mu.Lock()
	defer r.mu.Unlock()

	if now.Sub(r.lastPurge) > replayPurgeEvery {
		for key, at := range r.seen {
			if now.Sub(at) > replayWindow {
				delete(r.seen, key)
			}
		}
		r.lastPurge = now
	}

	if _, exists := r.seen[nonce]; exists {
		return false
	}
	r.seen[nonce] = now
	return true
}

// checkFreshness valide l'horodatage et l'unicité du nonce d'une requête.
//
// L'écart est comparé en valeur absolue : une requête datée dans le futur est
// tout aussi suspecte qu'une trop ancienne. Une horloge client en avance est un
// symptôme de désynchronisation, pas une raison d'être plus permissif.
func checkFreshness(req *CommandRequest) error {
	if req.Nonce == "" {
		return fmt.Errorf("nonce manquant")
	}
	if req.Timestamp == 0 {
		return fmt.Errorf("horodatage manquant")
	}

	now := time.Now()
	sent := time.Unix(req.Timestamp, 0)
	drift := now.Sub(sent)
	if drift < 0 {
		drift = -drift
	}
	if drift > replayWindow {
		return fmt.Errorf("horodatage hors fenêtre (écart %s, tolérance %s)",
			drift.Round(time.Second), replayWindow)
	}

	if !seenNonces.remember(req.Nonce, now) {
		// Ce cas n'arrive pas par accident : les nonces sont tirés
		// aléatoirement côté client. Une collision dans une fenêtre de deux
		// minutes signale un rejeu, d'où le niveau SECURITY.
		logs.Write_Log("SECURITY", fmt.Sprintf(
			"api: rejeu détecté pour l'utilisateur %s (nonce déjà utilisé)", req.Username))
		return fmt.Errorf("nonce déjà utilisé")
	}

	return nil
}
