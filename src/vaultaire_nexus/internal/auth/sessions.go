package auth

import (
	"sync"
	"time"
)

// Session est une session web.
type Session struct {
	ID        string
	CSRF      string
	Principal *Principal
	Created   time.Time
	Expires   time.Time
	IP        string
}

// Sessions tient les sessions web en mémoire. Un redémarrage déconnecte tout
// le monde : c'est acceptable pour un portail d'administration, et cela évite
// d'écrire sur disque des jetons de session.
type Sessions struct {
	mu  sync.Mutex
	ttl time.Duration
	m   map[string]*Session
}

// NewSessions crée le magasin.
func NewSessions(ttl time.Duration) *Sessions {
	return &Sessions{ttl: ttl, m: map[string]*Session{}}
}

// Create ouvre une session.
func (s *Sessions) Create(p *Principal, ip string) *Session {
	now := time.Now()
	sess := &Session{ID: RandomSecret(32), CSRF: RandomSecret(24), Principal: p, Created: now, Expires: now.Add(s.ttl), IP: ip}
	s.mu.Lock()
	s.m[sess.ID] = sess
	s.mu.Unlock()
	return sess
}

// Get rend une session valide et prolonge son échéance (glissante).
func (s *Sessions) Get(id string) (*Session, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	sess, ok := s.m[id]
	if !ok {
		return nil, false
	}
	if time.Now().After(sess.Expires) {
		delete(s.m, id)
		return nil, false
	}
	sess.Expires = time.Now().Add(s.ttl)
	return sess, true
}

// Delete ferme une session.
func (s *Sessions) Delete(id string) {
	s.mu.Lock()
	delete(s.m, id)
	s.mu.Unlock()
}

// Purge retire les sessions échues.
func (s *Sessions) Purge() {
	s.mu.Lock()
	defer s.mu.Unlock()
	now := time.Now()
	for id, sess := range s.m {
		if now.After(sess.Expires) {
			delete(s.m, id)
		}
	}
}

// LDAPUsers rend les comptes LDAP ayant une session ouverte.
func (s *Sessions) LDAPUsers() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	seen := map[string]bool{}
	var out []string
	for _, sess := range s.m {
		if sess.Principal.Source == SourceLDAP && !seen[sess.Principal.Username] {
			seen[sess.Principal.Username] = true
			out = append(out, sess.Principal.Username)
		}
	}
	return out
}

// UpdateUser applique de nouveaux groupes ; un compte sans rôle est déconnecté.
func (s *Sessions) UpdateUser(user string, groups []string, role string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for id, sess := range s.m {
		if sess.Principal.Source != SourceLDAP || sess.Principal.Username != user {
			continue
		}
		if role == "" {
			delete(s.m, id)
			continue
		}
		cp := *sess.Principal
		cp.Groups, cp.Role = groups, role
		sess.Principal = &cp
	}
}

// Count rend le nombre de sessions ouvertes.
func (s *Sessions) Count() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.m)
}
