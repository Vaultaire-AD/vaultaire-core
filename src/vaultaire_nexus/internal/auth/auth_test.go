package auth

import (
	"errors"
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
	s, initial, err := NewService(c, dir, slog.New(slog.NewTextHandler(io.Discard, nil)), nil)
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
	if _, err := s.Login("admin", pw, "", "1.2.3.4"); err != nil {
		t.Fatalf("login avec le mot de passe initial : %v", err)
	}
	if _, err := s.Login("admin", "faux", "", "1.2.3.4"); err == nil {
		t.Fatal("mauvais mot de passe accepté")
	}
	if err := s.Local.SetPassword("nouveau-mot-de-passe"); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(initial); !os.IsNotExist(err) {
		t.Error("admin.initial doit disparaître après le changement")
	}
	// Rechargement : l'empreinte persiste, aucun nouveau fichier initial.
	s2, initial2, err := NewService(s.cfg, filepath.Dir(filepath.Dir(s.Local.path)), slog.New(slog.NewTextHandler(io.Discard, nil)), nil)
	if err != nil || initial2 != "" {
		t.Fatalf("rechargement : %v %q", err, initial2)
	}
	if _, err := s2.Login("admin", "nouveau-mot-de-passe", "", "1.2.3.4"); err != nil {
		t.Fatal(err)
	}
}

func TestLockout(t *testing.T) {
	s, _ := testService(t, config.LocalAdmin{Enable: true, Username: "admin", Password: "fixe-pour-le-test"})
	for i := 0; i < 5; i++ {
		s.Login("admin", "faux", "", "9.9.9.9")
	}
	if _, err := s.Login("admin", "fixe-pour-le-test", "", "9.9.9.9"); err != ErrLocked {
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

func TestRolesDepuisLesCles(t *testing.T) {
	m := config.RoleMapping{Admin: []string{"vaultaire"}, Publisher: []string{"Dev"}, Reader: []string{"*"}}
	cas := []struct {
		groups, rights []string
		only           bool
		want           string
	}{
		{nil, []string{"write:nexus_admin"}, false, config.RoleAdmin},
		{[]string{"Dev"}, []string{"read:nexus"}, false, config.RolePublisher}, // le plus élevé gagne
		{[]string{"Dev"}, []string{"read:nexus"}, true, config.RoleReader},     // seules les clés
		{[]string{"Dev"}, nil, true, ""},
		{nil, []string{"write:user", "READ:NEXUS"}, true, config.RoleReader},
		{[]string{"vaultaire@acme.lan"}, nil, false, config.RoleAdmin}, // nom nu = tout domaine
	}
	for _, c := range cas {
		if got := RoleFrom(m, c.groups, c.rights, c.only); got != c.want {
			t.Errorf("RoleFrom(%v, %v, %t) = %q, attendu %q", c.groups, c.rights, c.only, got, c.want)
		}
	}
	// Un groupe qualifié ne reconnaît que son domaine.
	q := config.RoleMapping{Admin: []string{"Infra@infra.acme.lan"}}
	if RoleFor(q, []string{"Infra@rh.acme.lan"}) != "" || RoleFor(q, []string{"Infra@INFRA.acme.lan"}) != config.RoleAdmin {
		t.Error("groupe qualifié mal comparé")
	}
}

// fauxVerifier simule le core derrière la trame 08.
type fauxVerifier struct {
	indispo bool
	rights  []string
	revoque bool
}

func (f *fauxVerifier) VerifyUser(user, password, otp, from string) (Identity, error) {
	if f.indispo {
		return Identity{}, ErrUnavailable
	}
	if password != "bon" {
		return Identity{}, ErrBadCredentials
	}
	if user == "alice" && otp == "" {
		return Identity{}, ErrMFARequired
	}
	if user == "alice" && otp != "123456" {
		return Identity{}, ErrMFAInvalid
	}
	return Identity{User: user, Name: "Nom " + user, Groups: []string{"Dev@dev.acme.lan"}, Rights: f.rights}, nil
}

func (f *fauxVerifier) RefreshUser(user string) (Identity, error) {
	if f.revoque {
		return Identity{}, ErrRevoked
	}
	if f.indispo {
		return Identity{}, ErrUnavailable
	}
	return Identity{User: user, Groups: []string{"Dev@dev.acme.lan"}, Rights: f.rights}, nil
}

func TestModeDucky(t *testing.T) {
	dir := t.TempDir()
	c := config.Default().Auth
	c.Mode = config.AuthDucky
	c.LocalAdmin.Password = "fixe-pour-le-test"
	c.Roles = config.RoleMapping{Publisher: []string{"Dev"}}
	c.Ducky.RequireRight = false
	v := &fauxVerifier{rights: []string{"write:nexus_admin"}}
	s, _, err := NewService(c, dir, slog.New(slog.NewTextHandler(io.Discard, nil)), v)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := NewService(c, t.TempDir(), slog.New(slog.NewTextHandler(io.Discard, nil)), nil); err == nil {
		t.Error("mode ducky sans raccordement accepté")
	}

	// Second facteur : demandé, puis code faux (compté), puis juste.
	if _, err := s.Login("alice", "bon", "", "1.1.1.1"); err != ErrMFARequired {
		t.Fatalf("attendu ErrMFARequired, obtenu %v", err)
	}
	if _, err := s.Login("alice", "bon", "000000", "1.1.1.1"); err != ErrMFAInvalid {
		t.Fatalf("attendu ErrMFAInvalid, obtenu %v", err)
	}
	p, err := s.Login("alice", "bon", "123456", "1.1.1.1")
	if err != nil || p.Source != SourceDucky || p.Role != config.RoleAdmin || p.Display != "Nom alice" {
		t.Fatalf("connexion ducky : %v %+v", err, p)
	}
	// Le compte local ne passe jamais par le core.
	v.indispo = true
	if _, err := s.Login("admin", "fixe-pour-le-test", "", "1.1.1.1"); err != nil {
		t.Errorf("compte local : %v", err)
	}
	// Core indisponible, pas de repli : erreur d'indisponibilité, pas un échec compté.
	if _, err := s.Login("bob", "bon", "", "1.1.1.1"); !errors.Is(err, ErrUnavailable) {
		t.Errorf("indisponible : %v", err)
	}
	v.indispo = false

	// Jeton : garde les clés du titulaire ; la relecture les met à jour.
	sess := s.Sessions.Create(p, "1.1.1.1")
	tk, raw, err := s.Tokens.Create(p, "ci", config.RolePublisher, 0)
	if err != nil || strings.Join(tk.Rights, ",") != "write:nexus_admin" {
		t.Fatalf("jeton : %v %+v", err, tk)
	}
	v.rights = []string{"read:nexus"}
	s.refreshUser("alice", SourceDucky)
	got, ok := s.Sessions.Get(sess.ID)
	if !ok || got.Principal.Role != config.RolePublisher { // groupe Dev > read:nexus
		t.Errorf("session après relecture : %v %+v", ok, got)
	}
	if tp, ok := s.FromToken(raw, "1.1.1.1"); !ok || tp.Role != config.RolePublisher {
		t.Errorf("jeton après relecture : %v %+v", ok, tp)
	}
	// Révocation : sessions fermées, jeton sans valeur.
	v.revoque = true
	s.refreshUser("alice", SourceDucky)
	if _, ok := s.Sessions.Get(sess.ID); ok {
		t.Error("session conservée après révocation")
	}
	s.cfg.Roles = config.RoleMapping{} // sans groupe utile, le jeton n'a plus de rôle
	if _, ok := s.FromToken(raw, "1.1.1.1"); ok {
		t.Error("jeton encore valable après révocation")
	}
}
