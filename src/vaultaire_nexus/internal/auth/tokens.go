package auth

import (
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"errors"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"vaultaire_nexus/internal/config"
	"vaultaire_nexus/internal/store"
)

// Jetons d'accès : pour ce qui ne tape pas de mot de passe (docker, dnf, CI).
//
// Un jeton s'écrit « nxs_<id>_<secret> ». Seule l'empreinte SHA-256 du secret
// est gardée : un jeton est un secret aléatoire de 192 bits, pas un mot de
// passe humain, un étirement type PBKDF2 n'y ajouterait rien sinon de la
// latence à chaque pull.
//
// Un jeton porte :
//   - un titulaire (le compte qui l'a créé) et ses groupes au moment de la
//     création, relus à chaque usage si le compte de service LDAP le permet ;
//   - un plafond de rôle (reader ou publisher) : il ne dépasse jamais les droits
//     de son titulaire, et un jeton de lecture ne publie jamais ;
//   - une échéance facultative.
const tokenPrefix = "nxs_"

// Token est un jeton enregistré.
type Token struct {
	ID        string    `json:"id"`
	Label     string    `json:"label"`
	Owner     string    `json:"owner"`
	Source    string    `json:"source"`
	Groups    []string  `json:"groups"`
	Rights    []string  `json:"rights,omitempty"`
	Scope     string    `json:"scope"`
	Hash      string    `json:"hash,omitempty"`
	CreatedAt time.Time `json:"created_at"`
	ExpiresAt time.Time `json:"expires_at,omitzero"`
	LastUsed  time.Time `json:"last_used,omitzero"`
	LastIP    string    `json:"last_ip,omitempty"`
}

// Expired dit si le jeton est échu.
func (t Token) Expired() bool { return !t.ExpiresAt.IsZero() && time.Now().After(t.ExpiresAt) }

// Tokens est le registre des jetons.
type Tokens struct {
	mu     sync.Mutex
	path   string
	tokens map[string]*Token
	dirty  bool
}

// OpenTokens charge le registre.
func OpenTokens(dataDir string) (*Tokens, error) {
	t := &Tokens{path: filepath.Join(dataDir, "auth", "tokens.json"), tokens: map[string]*Token{}}
	var list []*Token
	if _, err := store.LoadJSON(t.path, &list); err != nil {
		return nil, err
	}
	for _, tk := range list {
		t.tokens[tk.ID] = tk
	}
	return t, nil
}

func (t *Tokens) saveLocked() error {
	list := make([]*Token, 0, len(t.tokens))
	for _, tk := range t.tokens {
		list = append(list, tk)
	}
	sort.Slice(list, func(i, j int) bool { return list[i].CreatedAt.Before(list[j].CreatedAt) })
	t.dirty = false
	return store.SaveJSON(t.path, list)
}

func hashSecret(s string) string {
	h := sha256.Sum256([]byte(s))
	return hex.EncodeToString(h[:])
}

// Create émet un jeton ; le secret complet n'est rendu qu'ici.
func (t *Tokens) Create(owner *Principal, label, scope string, ttl time.Duration) (Token, string, error) {
	if owner.IsAnonymous() || owner.Source == SourceToken {
		return Token{}, "", errors.New("un jeton ne peut pas créer de jeton")
	}
	switch scope {
	case config.RoleReader, config.RolePublisher:
	default:
		return Token{}, "", errors.New("portée d'un jeton : reader ou publisher")
	}
	// Un lecteur global peut créer un jeton « publisher » : il reste publieur
	// des seuls dépôts qui l'y autorisent par ses groupes, CanPublish tranche.
	label = strings.TrimSpace(label)
	if label == "" || len(label) > 64 {
		return Token{}, "", errors.New("libellé obligatoire (64 caractères au plus)")
	}
	id := RandomSecret(6)
	id = strings.NewReplacer("-", "x", "_", "y").Replace(id)
	secret := RandomSecret(24)
	tk := Token{
		ID: id, Label: label, Owner: owner.Username, Source: owner.Source,
		Groups: owner.Groups, Rights: owner.Rights, Scope: scope, Hash: hashSecret(secret), CreatedAt: time.Now().UTC(),
	}
	if ttl > 0 {
		tk.ExpiresAt = tk.CreatedAt.Add(ttl)
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	t.tokens[id] = &tk
	if err := t.saveLocked(); err != nil {
		delete(t.tokens, id)
		return Token{}, "", err
	}
	return tk, tokenPrefix + id + "_" + secret, nil
}

// LooksLikeToken dit si une chaîne a la forme d'un jeton.
func LooksLikeToken(s string) bool { return strings.HasPrefix(s, tokenPrefix) }

// Verify retrouve le jeton désigné par la chaîne complète.
func (t *Tokens) Verify(raw, ip string) (Token, bool) {
	rest, ok := strings.CutPrefix(raw, tokenPrefix)
	if !ok {
		return Token{}, false
	}
	id, secret, ok := strings.Cut(rest, "_")
	if !ok {
		return Token{}, false
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	tk, found := t.tokens[id]
	if !found || tk.Expired() {
		return Token{}, false
	}
	if subtle.ConstantTimeCompare([]byte(hashSecret(secret)), []byte(tk.Hash)) != 1 {
		return Token{}, false
	}
	// La date d'usage est écrite au plus une fois par minute : un pull de
	// cinquante couches ne doit pas réécrire le fichier cinquante fois.
	if time.Since(tk.LastUsed) > time.Minute {
		tk.LastUsed = time.Now().UTC()
		tk.LastIP = ip
		_ = t.saveLocked()
	}
	return *tk, true
}

// UpdateIdentity met à jour les groupes et les clés connus d'un titulaire.
func (t *Tokens) UpdateIdentity(owner string, groups, rights []string) {
	t.mu.Lock()
	defer t.mu.Unlock()
	changed := false
	for _, tk := range t.tokens {
		if tk.Owner == owner && (strings.Join(tk.Groups, ",") != strings.Join(groups, ",") ||
			strings.Join(tk.Rights, ",") != strings.Join(rights, ",")) {
			tk.Groups, tk.Rights = groups, rights
			changed = true
		}
	}
	if changed {
		_ = t.saveLocked()
	}
}

// List rend les jetons d'un titulaire, ou tous si owner == "".
func (t *Tokens) List(owner string) []Token {
	t.mu.Lock()
	defer t.mu.Unlock()
	var out []Token
	for _, tk := range t.tokens {
		if owner == "" || tk.Owner == owner {
			cp := *tk
			cp.Hash = ""
			out = append(out, cp)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].CreatedAt.After(out[j].CreatedAt) })
	return out
}

// Revoke supprime un jeton. owner vide : n'importe lequel (administrateur).
func (t *Tokens) Revoke(id, owner string) error {
	t.mu.Lock()
	defer t.mu.Unlock()
	tk, ok := t.tokens[id]
	if !ok || (owner != "" && tk.Owner != owner) {
		return errors.New("jeton introuvable")
	}
	delete(t.tokens, id)
	return t.saveLocked()
}
