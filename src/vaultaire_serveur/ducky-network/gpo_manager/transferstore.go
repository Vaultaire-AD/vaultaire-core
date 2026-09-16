package gpomanager

import (
	"fmt"
	"sync"
	"time"

	"vaultaire/core/gpo"
	"vaultaire/core/logs"
)

// Magasin des transferts de politique en cours.
//
// Une politique dépassant une trame est servie fragment par fragment (05_09 /
// 05_10). Il faut donc conserver la charge sérialisée entre le manifeste et le
// dernier fragment. La conserver plutôt que de la recalculer à chaque fragment
// n'est pas une optimisation : recalculer exposerait le client à recevoir des
// fragments issus de deux résolutions différentes si une GPO change entre-temps,
// et l'assemblage serait un document incohérent qui passerait la validation de
// forme.
//
// Chaque transfert porte l'empreinte de sa politique. Le client la renvoie à
// chaque fragment, ce qui permet de détecter l'écart et de répondre 05_11
// plutôt que de livrer un mélange.

// transferTTL borne la durée de vie d'un transfert. Un client qui abandonne en
// cours de route ne doit pas laisser sa charge en mémoire indéfiniment.
const transferTTL = 5 * time.Minute

// maxTransfersPerClient borne le nombre de transferts simultanés d'un même
// client : un scope machine plus une poignée de connexions utilisateur. Au-delà,
// c'est soit un bug soit un abus, et la mémoire du serveur ne doit pas suivre.
const maxTransfersPerClient = 16

// transferKey identifie un transfert : client, scope et utilisateur cible.
// L'utilisateur fait partie de la clé pour que deux connexions simultanées sur
// la même machine ne se marchent pas dessus.
type transferKey struct {
	ClientID string
	Scope    gpo.Scope
	Username string
}

func (k transferKey) String() string {
	if k.Username == "" {
		return fmt.Sprintf("%s/%s", k.ClientID, k.Scope)
	}
	return fmt.Sprintf("%s/%s/%s", k.ClientID, k.Scope, k.Username)
}

// pendingTransfer est un transfert en attente de récupération.
type pendingTransfer struct {
	transfer  *gpo.Transfer
	createdAt time.Time
}

var (
	transfersMu sync.Mutex
	transfers   = map[transferKey]*pendingTransfer{}
)

// storeTransfer enregistre un transfert, en remplaçant celui du même couple
// client/scope/utilisateur s'il existe.
func storeTransfer(key transferKey, t *gpo.Transfer) {
	transfersMu.Lock()
	defer transfersMu.Unlock()

	purgeExpiredLocked()

	if countForClientLocked(key.ClientID) >= maxTransfersPerClient {
		if _, replacing := transfers[key]; !replacing {
			logs.Write_LogCode("WARNING", logs.CodeGPOTransfer, fmt.Sprintf(
				"gpo: le client %s a déjà %d transferts en cours, le plus ancien est évincé",
				key.ClientID, maxTransfersPerClient))
			evictOldestForClientLocked(key.ClientID)
		}
	}

	transfers[key] = &pendingTransfer{transfer: t, createdAt: time.Now()}
	logs.Write_LogCode("DEBUG", logs.CodeGPOTransfer, fmt.Sprintf(
		"gpo: transfert %s enregistré — empreinte %s, %d fragment(s), %d octets",
		key, shortFingerprint(t.Manifest.Fingerprint), t.Manifest.ChunkCount, t.Manifest.TotalSize))
}

// getTransfer retourne un transfert si son empreinte correspond.
//
// Une empreinte différente n'est pas une erreur de programmation : c'est le cas
// normal où un administrateur a modifié une GPO pendant le transfert. On le
// distingue explicitement d'un transfert inconnu, parce que la conduite à tenir
// côté client n'est pas la même.
func getTransfer(key transferKey, fingerprint string) (*gpo.Transfer, string) {
	transfersMu.Lock()
	defer transfersMu.Unlock()

	purgeExpiredLocked()

	pending, ok := transfers[key]
	if !ok {
		return nil, "unknown_transfer"
	}
	if pending.transfer.Manifest.Fingerprint != fingerprint {
		return nil, "stale_fingerprint"
	}
	return pending.transfer, ""
}

// dropTransfer retire un transfert du magasin.
func dropTransfer(key transferKey) {
	transfersMu.Lock()
	defer transfersMu.Unlock()
	if _, ok := transfers[key]; ok {
		delete(transfers, key)
		logs.Write_LogCode("DEBUG", logs.CodeGPOTransfer, "gpo: transfert "+key.String()+" libéré")
	}
}

// DropTransfersForClient libère tous les transferts d'un client, à la fermeture
// de sa session.
func DropTransfersForClient(clientID string) {
	transfersMu.Lock()
	defer transfersMu.Unlock()

	removed := 0
	for key := range transfers {
		if key.ClientID == clientID {
			delete(transfers, key)
			removed++
		}
	}
	if removed > 0 {
		logs.Write_LogCode("DEBUG", logs.CodeGPOTransfer, fmt.Sprintf(
			"gpo: %d transfert(s) libéré(s) à la fermeture de session du client %s", removed, clientID))
	}
}

// purgeExpiredLocked retire les transferts périmés. Appelée sous verrou.
func purgeExpiredLocked() {
	now := time.Now()
	for key, pending := range transfers {
		if now.Sub(pending.createdAt) > transferTTL {
			delete(transfers, key)
			logs.Write_LogCode("DEBUG", logs.CodeGPOTransfer, fmt.Sprintf(
				"gpo: transfert %s expiré après %s sans récupération complète", key, transferTTL))
		}
	}
}

// countForClientLocked compte les transferts d'un client. Appelée sous verrou.
func countForClientLocked(clientID string) int {
	count := 0
	for key := range transfers {
		if key.ClientID == clientID {
			count++
		}
	}
	return count
}

// evictOldestForClientLocked évince le transfert le plus ancien d'un client.
// Appelée sous verrou.
func evictOldestForClientLocked(clientID string) {
	var oldestKey transferKey
	var oldestAt time.Time
	found := false

	for key, pending := range transfers {
		if key.ClientID != clientID {
			continue
		}
		if !found || pending.createdAt.Before(oldestAt) {
			oldestKey, oldestAt, found = key, pending.createdAt, true
		}
	}
	if found {
		delete(transfers, oldestKey)
	}
}

// shortFingerprint raccourcit une empreinte pour les journaux : 64 caractères
// hexadécimaux par ligne de log rendraient les journaux illisibles.
func shortFingerprint(fingerprint string) string {
	if fingerprint == "" {
		return "none"
	}
	if len(fingerprint) <= 12 {
		return fingerprint
	}
	return fingerprint[:12] + "…"
}
