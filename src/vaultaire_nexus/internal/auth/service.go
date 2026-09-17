package auth

import (
	"context"
	"errors"
	"log/slog"
	"strings"
	"sync"
	"time"

	"vaultaire_nexus/internal/config"
)

// Service rassemble les sources d'identité, les sessions et le frein aux
// essais répétés.
type Service struct {
	cfg      config.AuthConfig
	Local    *Local
	LDAP     *LDAP
	Tokens   *Tokens
	Sessions *Sessions
	lock     *lockout
	log      *slog.Logger

	// cache des Basic auth réussis : docker envoie l'en-tête à CHAQUE requête,
	// un pull de 30 couches ferait 30 binds LDAP sans lui.
	cacheMu sync.Mutex
	cache   map[string]cached
}

type cached struct {
	p       *Principal
	expires time.Time
}

// NewService assemble l'authentification.
func NewService(cfg config.AuthConfig, dataDir string, log *slog.Logger) (*Service, string, error) {
	local, initial, err := OpenLocal(cfg.LocalAdmin, dataDir)
	if err != nil {
		return nil, "", err
	}
	tokens, err := OpenTokens(dataDir)
	if err != nil {
		return nil, "", err
	}
	s := &Service{
		cfg:      cfg,
		Local:    local,
		Tokens:   tokens,
		Sessions: NewSessions(time.Duration(cfg.SessionMinutes) * time.Minute),
		lock:     newLockout(cfg.Lockout.MaxFailures, time.Duration(cfg.Lockout.WindowMinutes)*time.Minute),
		log:      log,
		cache:    map[string]cached{},
	}
	if cfg.Mode == config.AuthLDAP {
		s.LDAP = NewLDAP(cfg.LDAP, cfg.Roles)
	}
	return s, initial, nil
}

// Mode rend le mode configuré.
func (s *Service) Mode() string { return s.cfg.Mode }

// Login vérifie un couple identifiant / mot de passe (formulaire ou Basic).
func (s *Service) Login(username, password, ip string) (*Principal, error) {
	username = strings.TrimSpace(username)
	if s.lock.locked(username, ip) {
		return nil, ErrLocked
	}
	p, err := s.login(username, password)
	if err != nil {
		if errors.Is(err, ErrBadCredentials) {
			s.lock.fail(username, ip)
			s.log.Warn("auth: échec", "user", username, "ip", ip, "raison", err.Error())
		}
		return nil, err
	}
	s.lock.success(username, ip)
	return p, nil
}

func (s *Service) login(username, password string) (*Principal, error) {
	if s.Local.IsLocalName(username) {
		// Le nom est réservé au compte local : jamais d'essai LDAP derrière, un
		// homonyme dans l'annuaire ne doit pas pouvoir prendre sa place.
		if s.Local.Check(username, password) {
			return s.Local.Principal(), nil
		}
		return nil, ErrBadCredentials
	}
	if s.LDAP == nil {
		return nil, ErrBadCredentials
	}
	p, err := s.LDAP.Authenticate(username, password)
	if err != nil {
		return nil, err
	}
	s.Tokens.UpdateGroups(p.Username, p.Groups)
	return p, nil
}

// FromToken authentifie un jeton.
func (s *Service) FromToken(raw, ip string) (*Principal, bool) {
	tk, ok := s.Tokens.Verify(raw, ip)
	if !ok {
		s.lock.fail("jeton", ip)
		return nil, false
	}
	p := &Principal{
		Username: tk.Owner, Display: tk.Owner + " (jeton " + tk.Label + ")",
		Source: SourceToken, Groups: tk.Groups, TokenID: tk.ID, TokenScope: tk.Scope,
		AuthAt: time.Now(),
	}
	if tk.Source == SourceLocal {
		if !s.Local.Enabled() || tk.Owner != s.Local.Username() {
			return nil, false
		}
		p.Role = config.RoleAdmin
	} else {
		p.Role = RoleFor(s.cfg.Roles, tk.Groups)
		if p.Role == "" {
			// Le titulaire a perdu tout rôle : le jeton ne vaut plus rien.
			return nil, false
		}
	}
	return p, true
}

// Basic authentifie un en-tête Basic : jeton ou mot de passe, avec cache.
func (s *Service) Basic(username, password, ip string) (*Principal, error) {
	if LooksLikeToken(password) {
		p, ok := s.FromToken(password, ip)
		if !ok {
			return nil, ErrBadCredentials
		}
		return p, nil
	}
	key := username + "\x00" + hashSecret(password)
	s.cacheMu.Lock()
	if c, ok := s.cache[key]; ok && time.Now().Before(c.expires) {
		s.cacheMu.Unlock()
		return c.p, nil
	}
	s.cacheMu.Unlock()
	p, err := s.Login(username, password, ip)
	if err != nil {
		return nil, err
	}
	s.cacheMu.Lock()
	if len(s.cache) > 10000 {
		s.cache = map[string]cached{}
	}
	s.cache[key] = cached{p: p, expires: time.Now().Add(2 * time.Minute)}
	s.cacheMu.Unlock()
	return p, nil
}

// RefreshLoop relit périodiquement les groupes des sessions LDAP ouvertes et
// purge les sessions échues.
func (s *Service) RefreshLoop(ctx context.Context) {
	t := time.NewTicker(time.Minute)
	defer t.Stop()
	n := 0
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
		s.Sessions.Purge()
		n++
		if s.LDAP == nil || n%5 != 0 {
			continue
		}
		for _, u := range s.Sessions.LDAPUsers() {
			groups, ok, err := s.LDAP.Refresh(u)
			if err != nil || !ok {
				continue
			}
			role := RoleFor(s.cfg.Roles, groups)
			s.Sessions.UpdateUser(u, groups, role)
			s.Tokens.UpdateGroups(u, groups)
		}
		s.cacheMu.Lock()
		s.cache = map[string]cached{}
		s.cacheMu.Unlock()
	}
}

// lockout : fenêtre glissante d'échecs par compte et par adresse.
type lockout struct {
	mu     sync.Mutex
	max    int
	window time.Duration
	fails  map[string][]time.Time
}

func newLockout(max int, window time.Duration) *lockout {
	return &lockout{max: max, window: window, fails: map[string][]time.Time{}}
}

func (l *lockout) keys(user, ip string) []string {
	return []string{"u:" + strings.ToLower(user), "ip:" + ip}
}

func (l *lockout) prune(k string) []time.Time {
	cut := time.Now().Add(-l.window)
	v := l.fails[k]
	i := 0
	for i < len(v) && v[i].Before(cut) {
		i++
	}
	v = v[i:]
	if len(v) == 0 {
		delete(l.fails, k)
	} else {
		l.fails[k] = v
	}
	return v
}

func (l *lockout) locked(user, ip string) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	for i, k := range l.keys(user, ip) {
		limit := l.max
		if i == 1 {
			limit = l.max * 4 // une adresse (NAT, CI) porte plusieurs comptes
		}
		if len(l.prune(k)) >= limit {
			return true
		}
	}
	return false
}

func (l *lockout) fail(user, ip string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	now := time.Now()
	for _, k := range l.keys(user, ip) {
		l.fails[k] = append(l.prune(k), now)
	}
}

func (l *lockout) success(user, ip string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	delete(l.fails, "u:"+strings.ToLower(user))
}
