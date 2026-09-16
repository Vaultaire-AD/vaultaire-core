package sessionmgr

import (
	"duckynetworkclient/V1/duckynetwork/logs"
	"duckynetworkclient/V1/duckynetwork/storage"
	"fmt"
	"net"
	"sort"
	"time"
)

func NewManager(timeout time.Duration) *Manager {
	m := &Manager{
		sessions: make(map[string]*Session),
		timeout:  timeout,
	}
	go m.cleanupLoop()
	return m
}

// AddOrUpdate enregistre ou met à jour une session. La clé est toujours
// sessionID : le username ne suffit pas à identifier une session de façon
// fiable (plusieurs logins PAM du même utilisateur, ou la session vaultaire
// qui persiste à travers les reconnexions).
func (m *Manager) AddOrUpdate(sessionID, username string, conn net.Conn, status SessionStatus, duckysession *storage.DuckySession) {
	m.mu.Lock()
	defer m.mu.Unlock()

	if s, ok := m.sessions[sessionID]; ok {
		s.Username = username
		s.Conn = conn
		s.DuckySession = duckysession
		s.Status = status
		s.LastSeen = time.Now()
		return
	}

	m.sessions[sessionID] = &Session{
		SessionID:    sessionID,
		Username:     username,
		DuckySession: duckysession,
		Conn:         conn,
		Status:       status,
		CreatedAt:    time.Now(),
		LastSeen:     time.Now(),
	}
}

// SetStatus met à jour uniquement le statut d'une session déjà enregistrée
// (typiquement Pending -> Authenticated une fois l'auth confirmée par le
// serveur).
func (m *Manager) SetStatus(sessionID string, status SessionStatus) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if s, ok := m.sessions[sessionID]; ok {
		s.Status = status
	}
}

// GetStatus reste indexé par sessionID, comme tout le reste. Pour retrouver
// spécifiquement la session machine "vaultaire", préférer
// GetValidVaultaireSession.
func (m *Manager) GetStatus(sessionID string) (SessionStatus, bool) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	s, ok := m.sessions[sessionID]
	if !ok {
		return SessionFailed, false
	}
	return s.Status, true
}

// GetBySessionID récupère une session par son identifiant unique.
func (m *Manager) GetBySessionID(sessionID string) (*Session, bool) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	s, ok := m.sessions[sessionID]
	return s, ok
}

// GetByUsername retourne toutes les sessions actuellement enregistrées pour
// un username donné. Peut en retourner plusieurs (voir SessionID).
func (m *Manager) GetByUsername(username string) []*Session {
	m.mu.RLock()
	defer m.mu.RUnlock()

	var out []*Session
	for _, s := range m.sessions {
		if s.Username == username {
			out = append(out, s)
		}
	}
	return out
}

// GetValidVaultaireSession retourne la première session "vaultaire"
// authentifiée et utilisable trouvée dans la map. Il n'y a pas de clé
// réservée unique : plusieurs sessions vaultaire peuvent être ouvertes en
// même temps (ex : plusieurs tunnels machine). Cette fonction n'en retourne
// qu'une — la première valide rencontrée — ce qui suffit pour tout ce qui a
// juste besoin d'UN tunnel machine utilisable (fetch de clé SSH,
// heartbeat...), à la place d'une lecture directe d'un pointeur global.
//
// Retourne nil si aucune session vaultaire authentifiée et utilisable n'est
// disponible.
func (m *Manager) GetValidVaultaireSession() *Session {
	m.mu.RLock()
	defer m.mu.RUnlock()

	for _, s := range m.sessions {
		if s.Username != "vaultaire" {
			continue
		}
		if s.Status != SessionAuthenticated || s.DuckySession == nil || s.Conn == nil {
			continue
		}
		return s
	}
	return nil
}

func (m *Manager) WaitForVaultaireSession() (*Session, error) {

	timeout := time.After(5 * time.Second)
	ticker := time.NewTicker(200 * time.Millisecond)

	defer ticker.Stop()

	for {
		select {

		case <-ticker.C:
			sess := m.GetValidVaultaireSession()

			if sess != nil {
				return sess, nil
			}

		case <-timeout:
			return nil, fmt.Errorf("timeout attente session Vaultaire")
		}
	}
}

// ResolveForClose détermine quelle session fermer pour une demande de
// logout qui ne porte qu'un username (cas du hook PAM, qui ne connaît pas
// le sessionID).
//
//   - username != "vaultaire" : cas normal d'une session utilisateur. On
//     cible la plus récente (il ne devrait normalement y en avoir qu'une).
//   - username == "vaultaire" : on cible la session machine la plus
//     récente, SAUF s'il n'en reste qu'une et que ce noeud est configuré
//     comme serveur (storage.IsServeur) — dans ce cas le tunnel machine doit
//     rester ouvert et on refuse la fermeture (ok=false).
//
// Ne modifie rien : la suppression effective se fait via RemoveSession une
// fois le message de fermeture envoyé au serveur.
func (m *Manager) ResolveForClose(username string) (*Session, bool) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	var candidates []*Session
	for _, s := range m.sessions {
		if s.Username == username {
			candidates = append(candidates, s)
		}
	}
	if len(candidates) == 0 {
		return nil, false
	}

	sort.Slice(candidates, func(i, j int) bool {
		return candidates[i].CreatedAt.After(candidates[j].CreatedAt)
	})

	if username == "vaultaire" && len(candidates) == 1 && storage.IsServeur {
		logs.Write_log("INFO", fmt.Sprintf(
			"Fermeture refusée pour la session vaultaire id=%s : dernière session machine sur un noeud serveur, on la garde ouverte",
			candidates[0].SessionID))
		return nil, false
	}

	return candidates[0], true
}

// RemoveSession ferme le socket et retire la session de la map. C'est la
// primitive bas niveau ; ResolveForClose sert à déterminer QUELLE session y
// passer quand on ne dispose que d'un username.
func (m *Manager) RemoveSession(sessionID string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if s, ok := m.sessions[sessionID]; ok {
		if s.Conn != nil {
			_ = s.Conn.Close()
		}
		delete(m.sessions, sessionID)
	}
}

// FastRemoveSession est une version qui combine Remove Session et ResolveForClose : elle ferme la session la plus récente pour un username donné, et retourne true si une session a été fermée. Si aucune session n'est trouvée, ou si c'est la dernière session vaultaire sur un noeud serveur, elle ne fait rien et retourne false.
func (m *Manager) FastRemoveSession(sess *Session) bool {
	ResolvedSess, ok := m.ResolveForClose(sess.Username)
	if ResolvedSess != nil {
		m.RemoveSession(ResolvedSess.SessionID)
	}
	return ok
}

// Touch rafraîchit le LastSeen d'une session (identifiée par sessionID),
// pour le cleanupLoop d'inactivité.
func (m *Manager) Touch(sessionID string) {
	m.mu.Lock()
	defer m.mu.Unlock()

	if s, ok := m.sessions[sessionID]; ok {
		s.LastSeen = time.Now()
	}
}

func (m *Manager) cleanupLoop() {
	ticker := time.NewTicker(1 * time.Minute)
	defer ticker.Stop()

	for range ticker.C {
		now := time.Now()
		m.mu.Lock()
		for id, s := range m.sessions {
			// On ne check QUE le timeout d'inactivité
			// Si aucune donnée n'a transité depuis m.timeout
			if now.Sub(s.LastSeen) > m.timeout {
				logs.Write_log("WARNING", fmt.Sprintf(
					"Session timeout pour %s (id=%s). Fermeture du tunnel.", s.Username, id))
				if s.Conn != nil {
					_ = s.Conn.Close()
				}
				delete(m.sessions, id)
			}
		}
		m.mu.Unlock()
	}
}

// //FOR DEBUG : Affiche les sessions en cours et leur statut
// func (m *Manager) cleanupLoop() {
// 	ticker := time.NewTicker(1 * time.Minute)
// 	defer ticker.Stop()

// 	for range ticker.C {
// 		now := time.Now()

// 		m.mu.Lock()

// 		logs.Write_log("DEBUG", fmt.Sprintf(
// 			"=== Nettoyage sessions (%d sessions actives) ===",
// 			len(m.sessions),
// 		))

// 		for id, s := range m.sessions {

// 			inactive := now.Sub(s.LastSeen)

// 			logs.Write_log("DEBUG", fmt.Sprintf(
// 				"Session id=%s user=%s inactive depuis=%v timeout=%v",
// 				id,
// 				s.Username,
// 				inactive,
// 				m.timeout,
// 			))

// 			if inactive > m.timeout {

// 				logs.Write_log("WARNING", fmt.Sprintf(
// 					"Session timeout pour %s (id=%s). Fermeture du tunnel.",
// 					s.Username,
// 					id,
// 				))

// 				if s.Conn != nil {
// 					err := s.Conn.Close()
// 					if err != nil {
// 						logs.Write_log("ERROR", fmt.Sprintf(
// 							"Erreur fermeture connexion id=%s : %v",
// 							id,
// 							err,
// 						))
// 					} else {
// 						logs.Write_log("DEBUG", fmt.Sprintf(
// 							"Connexion fermée id=%s",
// 							id,
// 						))
// 					}
// 				}

// 				delete(m.sessions, id)

// 				logs.Write_log("DEBUG", fmt.Sprintf(
// 					"Session supprimée id=%s",
// 					id,
// 				))

// 			} else {

// 				logs.Write_log("DEBUG", fmt.Sprintf(
// 					"Session conservée id=%s",
// 					id,
// 				))
// 			}
// 		}

// 		m.mu.Unlock()

// 		logs.Write_log("DEBUG", "=== Fin nettoyage sessions ===")
// 	}
// }
