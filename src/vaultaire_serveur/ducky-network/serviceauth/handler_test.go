package serviceauth

import (
	"errors"
	"strings"
	"testing"
	"time"

	"vaultaire/core/clienttype"
	"vaultaire/core/storage"
)

// faux annuaire : alice (mot de passe « bon », MFA active, code « 123456 »),
// bob (sans MFA, membre de Dev), carl (MFA imposée non posée), dora (révoquée),
// eve (mot de passe expiré).
type faux struct {
	echecs, reussites []string
	consommes         map[int64]bool
	bloque            bool
	droits            map[string]bool
	auth              map[string]bool // permission « auth »
	grpErr            error
}

func nouveauFaux() *faux {
	return &faux{
		consommes: map[int64]bool{},
		droits:    map[string]bool{"read:nexus": true, "write:nexus": true, "write:user": true},
		auth:      map[string]bool{"alice": true, "bob": true, "carl": true, "dora": true, "eve": true, "vaultaire": true},
	}
}

var ids = map[string]int{"alice": 1, "bob": 2, "carl": 3, "dora": 4, "eve": 5, "vaultaire": 6}

func (f *faux) deps() Deps {
	return Deps{
		RateAllow: func(c, s string) (bool, time.Duration) { return !f.bloque, time.Minute },
		RateFail:  func(c, s string) { f.echecs = append(f.echecs, c+"|"+s) },
		RateOK:    func(c, s string) { f.reussites = append(f.reussites, c+"|"+s) },
		UserID: func(u string) (int, error) {
			if id, ok := ids[u]; ok {
				return id, nil
			}
			return 0, errors.New("inconnu")
		},
		CheckPassword: func(id int, p string) (bool, error) {
			if id == 99 {
				return false, errors.New("base")
			}
			return p == "bon", nil
		},
		IsRevoked:       func(u string) bool { return u == "dora" },
		PasswordExpired: func(u string) (bool, error) { return u == "eve", nil },
		MFAState: func(u string) (bool, string, bool, error) {
			switch u {
			case "alice":
				return true, "SECRET", true, nil
			case "carl":
				return false, "", true, nil
			}
			return false, "", false, nil
		},
		ValidateTOTP: func(secret, code string, _ time.Time) (int64, bool) {
			return 42, secret == "SECRET" && code == "123456"
		},
		ConsumeCounter: func(u string, c int64) (bool, error) {
			if f.consommes[c] {
				return false, nil
			}
			f.consommes[c] = true
			return true, nil
		},
		CanConnect: func(login string) (bool, string) {
			u, _, _ := strings.Cut(login, "@")
			return f.auth[u], "pas de permission auth"
		},
		GroupIDs:  func(string) ([]int, error) { return []int{7}, nil },
		HasAction: func(_ []int, k string) bool { return f.droits[k] },
		Groups: func(u string) ([]string, error) {
			if f.grpErr != nil {
				return nil, f.grpErr
			}
			return []string{"Dev@dev.acme.lan", "Infra@infra.acme.lan"}, nil
		},
		Name: func(u string) string { return "Nom\nde " + u },
		Now:  func() time.Time { return time.Unix(1_800_000_000, 0) },
	}
}

func session(typ string) *storage.DuckySession {
	return &storage.DuckySession{BoundClientType: typ, BoundClientSoftwareID: "nexus-01"}
}

func fausseTrame(sub, contenu string) storage.Trames_struct_client {
	return storage.Trames_struct_client{
		Message_Order: []string{"08", sub}, Destination_Server: "serveur_central",
		SessionIntegritykey: "CLE", Username: "vaultaire", ClientSoftwareID: "nexus-01", Content: contenu,
	}
}

// lire découpe une réponse serveur → client en code + champs.
func lire(t *testing.T, rep string) (string, map[string]string) {
	t.Helper()
	l := strings.Split(rep, "\n")
	if len(l) < 3 || l[1] != "serveur_central" || l[2] != "CLE" {
		t.Fatalf("en-tête invalide : %q", rep)
	}
	return l[0], champs(l[3:])
}

func auth(t *testing.T, m *Manager, contenu string) (string, map[string]string) {
	t.Helper()
	return lire(t, m.Traiter(fausseTrame("01", contenu), session(clienttype.Nexus)))
}

func TestSuccesSansMFA(t *testing.T) {
	f := nouveauFaux()
	m := NewManager(f.deps())
	code, c := auth(t, m, "bob@dev.acme.lan\nbon\nfrom:10.0.0.9\nref:r1")
	if code != TrameAuthOK {
		t.Fatalf("code %s %v", code, c)
	}
	if c["ref"] != "r1" || c["user"] != "bob" || c["ttl"] != "300" {
		t.Errorf("champs : %v", c)
	}
	if c["name"] != "Nom de bob" {
		t.Errorf("nom affiché non assaini : %q", c["name"])
	}
	if c["groups"] != "Dev@dev.acme.lan,Infra@infra.acme.lan" {
		t.Errorf("groups: %q", c["groups"])
	}
	// write:user est accordé au compte mais n'est pas une clé de Nexus : il ne
	// doit pas fuiter.
	if c["rights"] != "read:nexus,write:nexus" {
		t.Errorf("rights: %q", c["rights"])
	}
	if len(f.reussites) != 1 || f.reussites[0] != "bob|nexus-01" {
		t.Errorf("réussite non comptée par service : %v", f.reussites)
	}
}

func TestMauvaisMotDePasseEtCompteInconnuIndistinguables(t *testing.T) {
	f := nouveauFaux()
	m := NewManager(f.deps())
	c1, a := auth(t, m, "bob\nfaux")
	c2, b := auth(t, m, "personne\nbon")
	if c1 != TrameAuthFailed || c2 != TrameAuthFailed {
		t.Fatalf("%s %s", c1, c2)
	}
	if a["code"] != CodeBadCredentials || b["code"] != CodeBadCredentials || a["reason"] != b["reason"] {
		t.Errorf("réponses distinguables : %v / %v", a, b)
	}
	if len(f.echecs) != 2 {
		t.Errorf("échecs comptés : %v", f.echecs)
	}
}

func TestSecondFacteur(t *testing.T) {
	f := nouveauFaux()
	m := NewManager(f.deps())

	_, c := auth(t, m, "alice\nbon\nref:a")
	if c["code"] != CodeMFARequired || c["ref"] != "a" {
		t.Fatalf("sans code : %v", c)
	}
	if len(f.echecs) != 0 {
		t.Error("une demande de code n'est pas un échec")
	}
	// Mot de passe faux + code : le mot de passe est vérifié d'abord, et le
	// second facteur n'est même pas évoqué.
	_, c = auth(t, m, "alice\nfaux\notp:123456")
	if c["code"] != CodeBadCredentials {
		t.Fatalf("mot de passe faux avec code : %v", c)
	}
	_, c = auth(t, m, "alice\nbon\notp:000000")
	if c["code"] != CodeMFAInvalid {
		t.Fatalf("code faux : %v", c)
	}
	code, c := auth(t, m, "alice\nbon\notp:123456")
	if code != TrameAuthOK {
		t.Fatalf("code juste : %s %v", code, c)
	}
	// Rejeu du même code : refusé.
	_, c = auth(t, m, "alice\nbon\notp:123456")
	if c["code"] != CodeMFAInvalid {
		t.Fatalf("rejeu accepté : %v", c)
	}
}

func TestMFAImposeeNonPosee(t *testing.T) {
	m := NewManager(nouveauFaux().deps())
	_, c := auth(t, m, "carl\nbon\notp:123456")
	if c["code"] != CodeMFAEnrollRequired {
		t.Fatalf("%v", c)
	}
}

func TestRefusExplicitesApresLeMotDePasse(t *testing.T) {
	f := nouveauFaux()
	f.auth["bob"] = false
	m := NewManager(f.deps())
	cas := map[string]string{
		"dora\nbon":      CodeRevoked,
		"eve\nbon":       CodeExpired,
		"bob\nbon":       CodeDenied,
		"vaultaire\nbon": CodeDenied, // le compte d'amorçage ne se prête pas
	}
	for contenu, attendu := range cas {
		if _, c := auth(t, m, contenu); c["code"] != attendu {
			t.Errorf("%q : %v, attendu %s", contenu, c, attendu)
		}
	}
	// Et sans le mot de passe, aucun de ces états ne transparaît.
	for _, u := range []string{"dora", "eve"} {
		if _, c := auth(t, m, u+"\nfaux"); c["code"] != CodeBadCredentials {
			t.Errorf("%s : état révélé sans mot de passe : %v", u, c)
		}
	}
}

func TestLimitationAvantTout(t *testing.T) {
	f := nouveauFaux()
	f.bloque = true
	m := NewManager(f.deps())
	if _, c := auth(t, m, "personne\nbon"); c["code"] != CodeLocked {
		t.Fatalf("%v", c)
	}
}

func TestTramesMalformees(t *testing.T) {
	m := NewManager(nouveauFaux().deps())
	for _, contenu := range []string{
		"",
		"bob",
		"bob\n",
		"b*b\nbon",
		"bob\nbon\nref:pas d'espace",
		"bob\nbon\notp:" + strings.Repeat("1", 40),
	} {
		if _, c := auth(t, m, contenu); c["code"] != CodeInvalidRequest {
			t.Errorf("%q : %v", contenu, c)
		}
	}
}

func TestMotDePasseAvecDeuxPoints(t *testing.T) {
	f := nouveauFaux()
	d := f.deps()
	d.CheckPassword = func(_ int, p string) (bool, error) { return p == "ref:a b:c ", nil }
	m := NewManager(d)
	if code, c := auth(t, m, "bob\nref:a b:c \nref:z"); code != TrameAuthOK || c["ref"] != "z" {
		t.Fatalf("%s %v", code, c)
	}
}

func TestRelecture(t *testing.T) {
	f := nouveauFaux()
	m := NewManager(f.deps())
	relire := func(user string) (string, map[string]string) {
		return lire(t, m.Traiter(fausseTrame("04", "ref:x\nuser:"+user), session(clienttype.Nexus)))
	}
	// Jamais présenté par ce service : refusé.
	if code, c := relire("bob"); code != TrameRefreshDenied || c["code"] != CodeUnknown {
		t.Fatalf("compte jamais vérifié : %s %v", code, c)
	}
	auth(t, m, "bob\nbon")
	if code, c := relire("bob"); code != TrameRefreshOK || c["rights"] != "read:nexus,write:nexus" || c["ref"] != "x" {
		t.Fatalf("relecture : %s %v", code, c)
	}
	// Un autre service ne profite pas de la vérification faite par le premier.
	autre := &storage.DuckySession{BoundClientType: clienttype.Nexus, BoundClientSoftwareID: "nexus-02"}
	if code, _ := lire(t, m.Traiter(fausseTrame("04", "user:bob"), autre)); code != TrameRefreshDenied {
		t.Fatal("un second service relit un compte qu'il n'a pas vérifié")
	}
	// Droit retiré : la relecture le reflète.
	delete(f.droits, "write:nexus")
	if _, c := relire("bob"); c["rights"] != "read:nexus" {
		t.Errorf("droit retiré toujours transmis : %v", c)
	}
	// Permission de connexion retirée : refus.
	f.auth["bob"] = false
	if _, c := relire("bob"); c["code"] != CodeDenied {
		t.Errorf("%v", c)
	}
	f.auth["bob"] = true
	// Panne de lecture : indisponible, pas un refus définitif.
	f.grpErr = errors.New("base")
	if _, c := relire("bob"); c["code"] != CodeUnavailable {
		t.Errorf("%v", c)
	}
	f.grpErr = nil
	// Mémoire expirée.
	m.retention = 0
	if _, c := relire("bob"); c["code"] != CodeUnknown {
		t.Errorf("mémoire non expirée : %v", c)
	}
}

func TestSeulsLesServicesSontServis(t *testing.T) {
	m := NewManager(nouveauFaux().deps())
	for _, typ := range []string{clienttype.Client, "", "inconnu"} {
		if rep := m.Traiter(fausseTrame("01", "bob\nbon"), session(typ)); rep != "" {
			t.Errorf("type %q servi : %q", typ, rep)
		}
	}
	if rep := m.Traiter(fausseTrame("99", "x"), session(clienttype.Nexus)); rep != "" {
		t.Errorf("sous-trame inconnue servie : %q", rep)
	}
}

// Un service sans UserRights au catalogue vérifie des comptes sans rien
// apprendre de leurs droits.
func TestServiceSansDroitsNApprendRien(t *testing.T) {
	m := NewManager(nouveauFaux().deps())
	rep := m.Traiter(fausseTrame("01", "bob\nbon"), session(clienttype.Proxy))
	code, c := lire(t, rep)
	if code != TrameAuthOK || c["rights"] != "" {
		t.Fatalf("%s %v", code, c)
	}
}
