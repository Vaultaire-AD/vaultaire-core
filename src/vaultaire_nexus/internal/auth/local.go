package auth

import (
	"crypto/subtle"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"vaultaire_nexus/internal/config"
	"vaultaire_nexus/internal/store"
)

// Local est le compte administrateur local.
//
// # D'où vient son mot de passe
//
//  1. local_admin.password (ou NEXUS_ADMIN_PASSWORD) : pris tel quel, pour une
//     démonstration ou un déploiement piloté par l'environnement ;
//  2. sinon, l'empreinte déjà enregistrée dans <data_dir>/auth/local_admin.json
//     (changée depuis l'interface) ;
//  3. sinon — premier démarrage — un mot de passe aléatoire est tiré et écrit
//     UNE fois dans <data_dir>/admin.initial, lisible par le seul compte du
//     service. Pas de mot de passe par défaut connu : c'est précisément ce que
//     les robots essaient en premier.
type Local struct {
	mu       sync.RWMutex
	enabled  bool
	username string
	fixed    string // mot de passe de configuration, s'il y en a un
	hash     string
	path     string
}

type localFile struct {
	Hash      string    `json:"hash"`
	ChangedAt time.Time `json:"changed_at"`
}

// OpenLocal prépare le compte local.
func OpenLocal(cfg config.LocalAdmin, dataDir string) (*Local, string, error) {
	l := &Local{
		enabled:  cfg.Enable,
		username: cfg.Username,
		fixed:    cfg.Password,
		path:     filepath.Join(dataDir, "auth", "local_admin.json"),
	}
	if !l.enabled {
		return l, "", nil
	}
	if l.fixed != "" {
		return l, "", nil
	}
	var lf localFile
	found, err := store.LoadJSON(l.path, &lf)
	if err != nil {
		return nil, "", err
	}
	if found && lf.Hash != "" {
		l.hash = lf.Hash
		return l, "", nil
	}
	pw := RandomSecret(18)
	if err := l.SetPassword(pw); err != nil {
		return nil, "", err
	}
	initial := filepath.Join(dataDir, "admin.initial")
	msg := fmt.Sprintf("Compte : %s\nMot de passe : %s\n\nChangez-le depuis l'interface (Administration), puis supprimez ce fichier.\n", l.username, pw)
	if err := store.WriteFileAtomic(initial, []byte(msg), 0o600); err != nil {
		return nil, "", err
	}
	return l, initial, nil
}

// Enabled dit si le compte local est actif.
func (l *Local) Enabled() bool { return l != nil && l.enabled }

// Username rend le nom du compte.
func (l *Local) Username() string { return l.username }

// Fixed dit si le mot de passe vient de la configuration (non modifiable).
func (l *Local) Fixed() bool { return l.fixed != "" }

// Check vérifie le couple.
func (l *Local) Check(username, password string) bool {
	if !l.Enabled() || username != l.username || password == "" {
		return false
	}
	l.mu.RLock()
	fixed, hash := l.fixed, l.hash
	l.mu.RUnlock()
	if fixed != "" {
		return subtle.ConstantTimeCompare([]byte(fixed), []byte(password)) == 1
	}
	ok, err := VerifyPassword(hash, password)
	return err == nil && ok
}

// SetPassword change le mot de passe (refusé s'il vient de la configuration).
func (l *Local) SetPassword(pw string) error {
	if l.fixed != "" {
		return fmt.Errorf("le mot de passe du compte local est fixé par la configuration")
	}
	if len(pw) < 12 {
		return fmt.Errorf("12 caractères au minimum")
	}
	h, err := HashPassword(pw)
	if err != nil {
		return err
	}
	if err := store.SaveJSON(l.path, localFile{Hash: h, ChangedAt: time.Now().UTC()}); err != nil {
		return err
	}
	l.mu.Lock()
	l.hash = h
	l.mu.Unlock()
	// Le fichier initial n'a plus de raison d'exister : il porterait un mot de
	// passe qui n'ouvre plus rien, mais qu'on pourrait croire valable.
	_ = os.Remove(filepath.Join(filepath.Dir(filepath.Dir(l.path)), "admin.initial"))
	return nil
}

// Principal rend l'identité du compte local.
func (l *Local) Principal() *Principal {
	return &Principal{
		Username: l.username,
		Display:  l.username + " (local)",
		Source:   SourceLocal,
		Groups:   []string{"nexus-local-admin"},
		Role:     config.RoleAdmin,
		AuthAt:   time.Now(),
	}
}

// IsLocalName dit si un identifiant désigne le compte local. Utilisé pour
// qu'un compte LDAP homonyme ne soit jamais confondu avec lui.
func (l *Local) IsLocalName(u string) bool {
	return l.Enabled() && strings.EqualFold(u, l.username)
}
