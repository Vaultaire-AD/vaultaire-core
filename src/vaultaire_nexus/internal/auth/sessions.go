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

// DirectoryUsers rend les comptes Vaultaire (LDAP ou Ducky) ayant une session
// ouverte, avec la source de leur authentification.
func (s *Sessions) DirectoryUsers() map[string]string {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := map[string]string{}
	for _, sess := range s.m {
		switch sess.Principal.Source {
		case SourceLDAP, SourceDucky:
			out[sess.Principal.Username] = sess.Principal.Source
		}
	}
	return out
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

// UpdateUser applique une nouvelle identité ; un compte sans rôle est
// déconnecté.
func (s *Sessions) UpdateUser(user string, groups, rights []string, role string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for id, sess := range s.m {
		src := sess.Principal.Source
		if (src != SourceLDAP && src != SourceDucky) || sess.Principal.Username != user {
			continue
		}
		if role == "" {
			delete(s.m, id)
			continue
		}
		cp := *sess.Principal
		cp.Groups, cp.Rights, cp.Role = groups, rights, role
		sess.Principal = &cp
	}
}

// Count rend le nombre de sessions ouvertes.
func (s *Sessions) Count() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.m)
}
