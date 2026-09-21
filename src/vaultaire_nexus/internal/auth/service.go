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
	Ducky    *Ducky
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

// role applique la politique de rôle configurée.
func (s *Service) role(groups, rights []string) string {
	return RoleFrom(s.cfg.Roles, groups, rights, s.cfg.Ducky.RequireRight)
}

// NewService assemble l'authentification. verifier n'est utilisé qu'en mode
// ducky ; il peut être nil sinon.
func NewService(cfg config.AuthConfig, dataDir string, log *slog.Logger, verifier DuckyVerifier) (*Service, string, error) {
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
	if cfg.Mode == config.AuthLDAP || (cfg.Mode == config.AuthDucky && cfg.Ducky.FallbackLDAP) {
		s.LDAP = NewLDAP(cfg.LDAP, cfg.Roles)
		s.LDAP.rightsOnly = cfg.Ducky.RequireRight
	}
	if cfg.Mode == config.AuthDucky {
		if verifier == nil {
			return nil, "", errors.New("auth.mode ducky exige le raccordement au cluster (ducky.enable)")
		}
		s.Ducky = &Ducky{v: verifier, roles: s}
	}
	return s, initial, nil
}

// Mode rend le mode configuré.
func (s *Service) Mode() string { return s.cfg.Mode }

// Login vérifie un couple identifiant / mot de passe (formulaire ou Basic).
// otp est le code du second facteur, vide s'il n'a pas (encore) été demandé.
func (s *Service) Login(username, password, otp, ip string) (*Principal, error) {
	username = strings.TrimSpace(username)
	if s.lock.locked(username, ip) {
		return nil, ErrLocked
	}
	p, err := s.login(username, password, otp, ip)
	if err != nil {
		switch {
		case errors.Is(err, ErrBadCredentials), errors.Is(err, ErrMFAInvalid):
			s.lock.fail(username, ip)
			s.log.Warn("auth: échec", "user", username, "ip", ip, "raison", err.Error())
		case errors.Is(err, ErrMFARequired):
			// Étape normale : le formulaire va demander le code.
		default:
			s.log.Warn("auth: refus", "user", username, "ip", ip, "raison", err.Error())
		}
		return nil, err
	}
	s.lock.success(username, ip)
	return p, nil
}

func (s *Service) login(username, password, otp, ip string) (*Principal, error) {
	if s.Local.IsLocalName(username) {
		// Le nom est réservé au compte local : jamais d'essai LDAP derrière, un
		// homonyme dans l'annuaire ne doit pas pouvoir prendre sa place.
		if s.Local.Check(username, password) {
			return s.Local.Principal(), nil
		}
		return nil, ErrBadCredentials
	}
	var (
		p   *Principal
		err error
	)
	switch {
	case s.Ducky != nil:
		p, err = s.Ducky.Authenticate(username, password, otp, ip)
		if errors.Is(err, ErrUnavailable) && s.LDAP != nil {
			// Repli : le core ne répond pas par le réseau Ducky. Au bind LDAP,
			// un compte soumis au second facteur accole son code au mot de
			// passe (sauf `ldap.mfa_bypass` côté core) : on le fait pour lui
			// quand le code a été saisi.
			s.log.Warn("auth: réseau Ducky indisponible, repli LDAP", "user", username, "err", err.Error())
			p, err = s.LDAP.Authenticate(username, password+otp)
		}
	case s.LDAP != nil:
		// En mode LDAP, un compte soumis au second facteur saisit son mot de
		// passe suivi du code (« motdepasse123456 ») : c'est le core qui coupe.
		p, err = s.LDAP.Authenticate(username, password+otp)
	default:
		return nil, ErrBadCredentials
	}
	if err != nil {
		return nil, err
	}
	s.Tokens.UpdateIdentity(p.Username, p.Groups, p.Rights)
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
		p.Rights = tk.Rights
		p.Role = s.role(tk.Groups, tk.Rights)
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
	// Pas de second facteur possible en Basic : docker, dnf et apt n'ont
	// aucun moyen de le saisir. Un compte qui en porte un utilise un jeton.
	p, err := s.Login(username, password, "", ip)
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

// RefreshLoop relit périodiquement l'identité des comptes Vaultaire ayant une
// session ouverte, et purge les sessions échues.
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
		if (s.LDAP == nil && s.Ducky == nil) || n%5 != 0 {
			continue
		}
		for u, src := range s.Sessions.DirectoryUsers() {
			s.refreshUser(u, src)
		}
		s.cacheMu.Lock()
		s.cache = map[string]cached{}
		s.cacheMu.Unlock()
	}
}

// refreshUser relit un compte à sa source et applique le résultat.
func (s *Service) refreshUser(u, src string) {
	var (
		id  Identity
		err error
	)
	switch {
	case src == SourceDucky && s.Ducky != nil:
		id, err = s.Ducky.v.RefreshUser(u)
		if endsRights(err) {
			s.log.Warn("auth: droits retirés par le core", "user", u, "raison", err.Error())
			s.Sessions.UpdateUser(u, nil, nil, "")
			s.Tokens.UpdateIdentity(u, nil, nil)
			return
		}
	case src == SourceLDAP && s.LDAP != nil:
		var ok bool
		id, ok, err = s.LDAP.Refresh(u)
		if err == nil && !ok {
			return // pas de compte de service : identité du login conservée
		}
	default:
		return
	}
	if err != nil {
		return // indisponible : on garde l'identité précédente
	}
	role := s.role(id.Groups, id.Rights)
	s.Sessions.UpdateUser(u, id.Groups, id.Rights, role)
	s.Tokens.UpdateIdentity(u, id.Groups, id.Rights)
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
