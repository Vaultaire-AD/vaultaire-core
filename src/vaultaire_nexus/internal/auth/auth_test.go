package auth

import (
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"vaultaire_nexus/internal/config"
)

func TestPassword(t *testing.T) {
	h, err := HashPassword("secret-tres-long")
	if err != nil {
		t.Fatal(err)
	}
	if ok, _ := VerifyPassword(h, "secret-tres-long"); !ok {
		t.Error("bon mot de passe refusé")
	}
	if ok, _ := VerifyPassword(h, "autre"); ok {
		t.Error("mauvais mot de passe accepté")
	}
}

func TestRoles(t *testing.T) {
	m := config.RoleMapping{Admin: []string{"vaultaire"}, Publisher: []string{"Dev"}, Reader: []string{"*"}}
	if RoleFor(m, []string{"dev"}) != config.RolePublisher {
		t.Error("groupe insensible à la casse")
	}
	if RoleFor(m, nil) != config.RoleReader {
		t.Error("* doit couvrir tout compte")
	}
	m.Reader = nil
	if RoleFor(m, []string{"RH"}) != "" {
		t.Error("aucun rôle attendu")
	}

	reader := &Principal{Source: SourceLDAP, Role: config.RoleReader, Groups: []string{"Web"}}
	repo := RepoView{Publishers: []string{"Web"}}
	if !CanPublish(reader, repo) {
		t.Error("groupe publieur du dépôt ignoré")
	}
	tok := *reader
	tok.TokenScope = config.RoleReader
	if CanPublish(&tok, repo) {
		t.Error("un jeton de lecture a publié")
	}
	if CanRead(Anonymous, RepoView{}) || !CanRead(Anonymous, RepoView{Public: true}) {
		t.Error("lecture anonyme")
	}
	admin := &Principal{Source: SourceLocal, Role: config.RoleAdmin, TokenScope: config.RoleReader}
	if CanAdmin(admin) {
		t.Error("un jeton reader d'un admin ne doit pas administrer")
	}
}

func testService(t *testing.T, cfg config.LocalAdmin) (*Service, string) {
	t.Helper()
	dir := t.TempDir()
	c := config.Default().Auth
	c.LocalAdmin = cfg
	s, initial, err := NewService(c, dir, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatal(err)
	}
	return s, initial
}

func TestLocalAdminGenerated(t *testing.T) {
	s, initial := testService(t, config.LocalAdmin{Enable: true, Username: "admin"})
	if initial == "" {
		t.Fatal("aucun mot de passe initial écrit")
	}
	b, _ := os.ReadFile(initial)
	st, _ := os.Stat(initial)
	if st.Mode().Perm() != 0o600 {
		t.Errorf("mode %v", st.Mode().Perm())
	}
	var pw string
	for _, l := range strings.Split(string(b), "\n") {
		if v, ok := strings.CutPrefix(l, "Mot de passe : "); ok {
			pw = v
		}
	}
	if _, err := s.Login("admin", pw, "1.2.3.4"); err != nil {
		t.Fatalf("login avec le mot de passe initial : %v", err)
	}
	if _, err := s.Login("admin", "faux", "1.2.3.4"); err == nil {
		t.Fatal("mauvais mot de passe accepté")
	}
	if err := s.Local.SetPassword("nouveau-mot-de-passe"); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(initial); !os.IsNotExist(err) {
		t.Error("admin.initial doit disparaître après le changement")
	}
	// Rechargement : l'empreinte persiste, aucun nouveau fichier initial.
	s2, initial2, err := NewService(s.cfg, filepath.Dir(filepath.Dir(s.Local.path)), slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil || initial2 != "" {
		t.Fatalf("rechargement : %v %q", err, initial2)
	}
	if _, err := s2.Login("admin", "nouveau-mot-de-passe", "1.2.3.4"); err != nil {
		t.Fatal(err)
	}
}

func TestLockout(t *testing.T) {
	s, _ := testService(t, config.LocalAdmin{Enable: true, Username: "admin", Password: "fixe-pour-le-test"})
	for i := 0; i < 5; i++ {
		s.Login("admin", "faux", "9.9.9.9")
	}
	if _, err := s.Login("admin", "fixe-pour-le-test", "9.9.9.9"); err != ErrLocked {
		t.Fatalf("verrouillage attendu, obtenu %v", err)
	}
}

func TestTokens(t *testing.T) {
	s, _ := testService(t, config.LocalAdmin{Enable: true, Username: "admin", Password: "fixe-pour-le-test"})
	owner := s.Local.Principal()
	tk, raw, err := s.Tokens.Create(owner, "ci", config.RolePublisher, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	p, ok := s.FromToken(raw, "1.1.1.1")
	if !ok || p.Username != "admin" || p.EffectiveRole() != config.RolePublisher {
		t.Fatalf("jeton : %+v %v", p, ok)
	}
	if _, ok := s.FromToken(raw+"x", "1.1.1.1"); ok {
		t.Error("jeton altéré accepté")
	}
	if p2, err := s.Basic("peu-importe", raw, "1.1.1.1"); err != nil || p2.TokenID != tk.ID {
		t.Errorf("Basic avec jeton : %v", err)
	}
	if err := s.Tokens.Revoke(tk.ID, "quelquun"); err == nil {
		t.Error("révocation par un autre titulaire")
	}
	s.Tokens.Revoke(tk.ID, "admin")
	if _, ok := s.FromToken(raw, "1.1.1.1"); ok {
		t.Error("jeton révoqué accepté")
	}
}
