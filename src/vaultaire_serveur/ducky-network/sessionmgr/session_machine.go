package sessionmgr

import (
	"sort"
	"strings"
	"time"

	"vaultaire/core/reglages"
	"vaultaire/core/storage"
)

// CompteMachine est le compte sous lequel le tunnel d'une machine s'authentifie.
const CompteMachine = "vaultaire"

// SessionMachine est une session à qui pousser une trame destinée à une
// machine, par VALEUR : l'appelant l'emploie hors verrou (voir StaleSession).
type SessionMachine struct {
	SessionID        string
	ClientSoftwareID string // tel qu'annoncé par la machine — la forme canonique
	DuckySession     *storage.DuckySession
}

// SessionsMachine rend les sessions par lesquelles on peut POUSSER une trame à
// une machine, dans l'ordre où les essayer (TO-DO 89).
//
// # Le défaut que cette fonction ferme
//
// Les poussées du core — rafraîchissement GPO (05_18), ordre de révocation —
// prenaient GetByClientSoftwareID : la PREMIÈRE session portant l'identifiant,
// dans l'ordre aléatoire d'une map, quel que soit son état. Or une machine en
// a souvent plusieurs, car l'identité est posée dès la 01_01, avant toute
// authentification :
//
//   - son tunnel permanent, sous CompteMachine ;
//   - les connexions de quelques secondes du « --fetch-key » de sshd, sous le
//     même compte, une par connexion SSH ;
//   - les sessions des utilisateurs qui s'y connectent ;
//   - des sessions encore en poignée de main, sans DuckySession.
//
// Tomber sur une session en attente faisait répondre « hors ligne » à une
// machine connectée ; sur celle d'un utilisateur, la trame partait vers une
// connexion qui ne traite pas les GPO, et la commande annonçait un succès.
//
// # L'ordre rendu
//
//  1. seules les sessions AUTHENTIFIÉES du compte machine, avec une session
//     Ducky ;
//  2. celles vues depuis moins de `fraicheur` d'abord : le tunnel répond au
//     battement 02_11, un tunnel mort après une coupure — encore inscrit
//     jusqu'au balayage — ne répond plus ;
//  3. puis la plus ANCIENNE d'abord : le tunnel dure, un « --fetch-key »
//     vit quelques secondes.
//
// L'appelant essaie dans cet ordre jusqu'au premier envoi qui passe.
//
// L'identifiant est comparé sans la casse : la base le compare ainsi
// (collation _ci), donc « pc-01 » tapé par un administrateur y désigne bien
// « PC-01 » — et le registre en mémoire ne doit pas être plus strict qu'elle.
func (m *Manager) SessionsMachine(clientSoftwareID string, fraicheur time.Duration) []SessionMachine {
	id := strings.TrimSpace(clientSoftwareID)
	if id == "" {
		return nil
	}

	m.mu.RLock()
	type candidat struct {
		s       SessionMachine
		cree    time.Time
		fraiche bool
	}
	var cands []candidat
	now := time.Now()
	for _, s := range m.sessions {
		if s.Status != SessionAuthenticated || s.Username != CompteMachine || s.DuckySession == nil {
			continue
		}
		if !strings.EqualFold(strings.TrimSpace(s.ClientSoftwareID), id) {
			continue
		}
		cands = append(cands, candidat{
			s:       SessionMachine{SessionID: s.SessionID, ClientSoftwareID: s.ClientSoftwareID, DuckySession: s.DuckySession},
			cree:    s.CreatedAt,
			fraiche: fraicheur <= 0 || now.Sub(s.LastSeen) <= fraicheur,
		})
	}
	m.mu.RUnlock()

	sort.SliceStable(cands, func(i, j int) bool {
		if cands[i].fraiche != cands[j].fraiche {
			return cands[i].fraiche
		}
		return cands[i].cree.Before(cands[j].cree)
	})
	out := make([]SessionMachine, len(cands))
	for i, c := range cands {
		out[i] = c.s
	}
	return out
}

// FraicheurTunnel est l'ancienneté au-delà de laquelle un tunnel machine est
// SUSPECT : passé derrière les autres, pas écarté.
//
// Deux cadences de vérification en ligne (le 02_11 que le core envoie, et
// auquel le tunnel répond) plus une minute de marge : un tunnel vivant ne
// dépasse jamais ce délai, un tunnel coupé le dépasse vite. Une fonction, pour
// suivre le réglage sans redémarrage.
var FraicheurTunnel = func() time.Duration {
	return 2*reglages.Duree(reglages.CleVerificationEnLigne) + time.Minute
}
