package sessionmgr

import (
	"net"
	"time"
	"vaultaire/core/storage"
)

// Sessions est le registre global des connexions actives côté serveur.
// Chaque connexion acceptée par le listener (voir startDuckyServer.go) y
// est enregistrée dès l'accept(), avant même la moindre trame lue.
var Sessions = NewManager()

// AddOrUpdate enregistre ou met à jour une session, indexée par SessionID.
// Ne touche jamais Username/ClientSoftwareID : voir SetIdentity.
func (m *Manager) AddOrUpdate(sessionID string, conn net.Conn, status SessionStatus, duckysession *storage.DuckySession) {
	m.mu.Lock()
	defer m.mu.Unlock()

	if s, ok := m.sessions[sessionID]; ok {
		s.Conn = conn
		s.DuckySession = duckysession
		s.Status = status
		s.LastSeen = time.Now()
		return
	}

	remote := ""
	if conn != nil {
		remote = conn.RemoteAddr().String()
	}
	m.sessions[sessionID] = &Session{
		SessionID:    sessionID,
		RemoteAddr:   remote,
		Conn:         conn,
		DuckySession: duckysession,
		Status:       status,
		CreatedAt:    time.Now(),
		LastSeen:     time.Now(),
	}
}

// IsSessionExpired a été retirée au profit de StaleSessions.
//
// Elle portait un délai en dur de 5 minutes, appliqué indifféremment à toutes
// les sessions, et surtout elle lisait `sess.LastSeen` hors verrou depuis
// l'appelant. StaleSessions prend la même décision sous verrou, avec un délai
// distinct selon que la poignée de main est terminée ou non.

// SetIdentity attache le username / ClientSoftwareID annoncés par le client
// à une session déjà enregistrée. Appelée dès la première trame (identité
// revendiquée, pas encore prouvée) puis reconfirmée après authentification :
// ça permet de tracer une tentative dans les logs même si elle échoue avant
// la fin du login.
func (m *Manager) SetIdentity(sessionID, username, clientSoftwareID string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if s, ok := m.sessions[sessionID]; ok {
		s.Username = username
		s.ClientSoftwareID = clientSoftwareID
	}
}

// SetStatus met à jour uniquement le statut d'une session déjà enregistrée.
func (m *Manager) SetStatus(sessionID string, status SessionStatus) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if s, ok := m.sessions[sessionID]; ok {
		s.Status = status
	}
}

// Rekey remplace la clé temporaire générée à l'accept() par le
// SessionIntegritykey réel une fois la poignée de main terminée (trame
// 01_01/01_02). Après cet appel, SessionID correspond exactement à la clé
// qui circule dans trames_content.SessionIntegritykey pour le reste de la
// vie de la connexion — les logs et le protocole partagent alors le même
// identifiant.
func (m *Manager) Rekey(oldID, newID string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if oldID == newID {
		return
	}
	s, ok := m.sessions[oldID]
	if !ok {
		return
	}
	delete(m.sessions, oldID)
	s.SessionID = newID
	m.sessions[newID] = s
}

// GetBySessionID récupère une session par son identifiant unique.
func (m *Manager) GetBySessionID(sessionID string) (*Session, bool) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	s, ok := m.sessions[sessionID]
	return s, ok
}

// GetByClientSoftwareID retourne la première session correspondant à cet
// identifiant machine. Utile pour rattacher un log qui n'a accès qu'au
// ClientSoftwareID (pas au *storage.DuckySession) à sa session, par exemple
// dans le code de chiffrement.
func (m *Manager) GetByClientSoftwareID(clientSoftwareID string) (*Session, bool) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	for _, s := range m.sessions {
		if s.ClientSoftwareID == clientSoftwareID {
			return s, true
		}
	}
	return nil, false
}

// ListAuthenticatedByUsername retourne toutes les sessions authentifiées
// pour un username donné.
func (m *Manager) ListAuthenticatedByUsername(username string) []*Session {
	m.mu.RLock()
	defer m.mu.RUnlock()
	var out []*Session
	for _, s := range m.sessions {
		if s.Username == username && s.Status == SessionAuthenticated {
			out = append(out, s)
		}
	}
	return out
}

// ListAuthenticated retourne toutes les sessions authentifiées, tous
// usernames confondus. Remplace l'ancienne slice globale non protégée
// storage.Serveur_Online, qui ne couvrait que les pairs "vaultaire" : le
// heartbeat porte maintenant sur toute session authentifiée.
func (m *Manager) ListAuthenticated() []*Session {
	m.mu.RLock()
	defer m.mu.RUnlock()
	var out []*Session
	for _, s := range m.sessions {
		if s.Status == SessionAuthenticated {
			out = append(out, s)
		}
	}
	return out
}

// StaleSession décrit une session à fermer, par VALEUR.
//
// Pas de pointeur, et c'est le point important. ListAuthenticated retourne des
// `*Session` que l'appelant lit ensuite hors verrou, pendant que Touch et
// SetStatus les écrivent depuis les goroutines de connexion : c'est une course
// de données, bénigne en pratique mais réelle. Ici la décision d'expiration est
// prise SOUS le verrou et seules des copies en sortent, donc il n'y a plus rien
// à lire de concurrent.
type StaleSession struct {
	SessionID        string
	Username         string
	ClientSoftwareID string
	RemoteAddr       string
	Status           SessionStatus
	Idle             time.Duration
}

// StaleSessions retourne toutes les sessions inactives, authentifiées OU NON.
//
// POURQUOI DEUX DÉLAIS. Une session authentifiée est légitimement silencieuse
// entre deux battements de cœur : son délai doit couvrir plusieurs cycles de
// heartbeat. Une session qui n'a pas terminé sa poignée de main, elle, n'a
// aucune raison de traîner — un client réel enchaîne accept(), 01_01 et 02_01
// en une fraction de seconde. Leur appliquer le même délai reviendrait à
// accorder cinq minutes de socket ouvert à quiconque ouvre une connexion TCP
// sans rien envoyer.
//
// C'est ce que le registre ne faisait pas : le balayage ne parcourait que
// ListAuthenticated(), donc les sessions en attente — les seules qu'un
// attaquant obtient sans posséder le moindre identifiant — n'étaient jamais
// nettoyées.
//
// Les sessions en échec (SessionFailed) suivent le délai court : une
// authentification refusée n'a pas à conserver son socket.
func (m *Manager) StaleSessions(authIdle, handshakeIdle time.Duration) []StaleSession {
	m.mu.RLock()
	defer m.mu.RUnlock()

	now := time.Now()
	var out []StaleSession
	for _, s := range m.sessions {
		idle := now.Sub(s.LastSeen)

		limit := handshakeIdle
		if s.Status == SessionAuthenticated {
			limit = authIdle
		}
		if idle <= limit {
			continue
		}

		out = append(out, StaleSession{
			SessionID:        s.SessionID,
			Username:         s.Username,
			ClientSoftwareID: s.ClientSoftwareID,
			RemoteAddr:       s.RemoteAddr,
			Status:           s.Status,
			Idle:             idle,
		})
	}
	return out
}

// CountByStatus retourne le nombre de sessions par statut, pour la supervision.
//
// Une population de sessions « pending » qui gonfle est la signature d'un
// balayage qui ne fait pas son travail, ou d'ouvertures de connexions muettes.
// Sans compteur distinct, Count() les noie dans le total.
func (m *Manager) CountByStatus() map[SessionStatus]int {
	m.mu.RLock()
	defer m.mu.RUnlock()
	out := make(map[SessionStatus]int, 3)
	for _, s := range m.sessions {
		out[s.Status]++
	}
	return out
}

// RemoveSession ferme le socket et retire la session du registre.
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

// Touch rafraîchit le LastSeen d'une session.
//
// Ce n'est plus purement informatif : depuis l'ajout de StaleSessions, c'est
// cette date qui décide de la fermeture d'une connexion inactive. Un chemin de
// lecture de trame qui oublierait d'appeler Touch ferait couper des connexions
// bien vivantes.
func (m *Manager) Touch(sessionID string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if s, ok := m.sessions[sessionID]; ok {
		s.LastSeen = time.Now()
	}
}

// Count retourne le nombre de sessions actuellement enregistrées (debug /
// web UI).
func (m *Manager) Count() int {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return len(m.sessions)
}
