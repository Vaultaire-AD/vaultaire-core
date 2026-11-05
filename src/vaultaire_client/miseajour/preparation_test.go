package miseajour

import (
	"crypto/rand"
	"crypto/rsa"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const baseTest = "https://nexus.lan:8843"

func preparationDeTest(t *testing.T, c Chemins, p paquetDeTest, f *fauxSysteme) Preparation {
	t.Helper()
	return Preparation{
		Chemins: c, Systeme: f.Systeme,
		Telecharger: p.servir(baseTest, "rocky", "2.3.1"),
		Bases:       []Base{{URL: baseTest, Source: SourceCluster}},
		Cles:        func() ([]*rsa.PublicKey, error) { return []*rsa.PublicKey{&p.cle.PublicKey}, nil },
	}
}

func TestPreparerChemin(t *testing.T) {
	c := installationDeTest(t)
	p := fabriquerPaquet(t, "2.3.1", "rocky", "")
	f := &fauxSysteme{}
	plan, err := Preparer(preparationDeTest(t, c, p, f), Ordre{Version: "2.3.1"})
	if err != nil {
		t.Fatal(err)
	}
	if plan.Famille != "rocky" || plan.Repertoire != filepath.Join(c.Etat, "2.3.1") || len(plan.Fichiers) != 5 {
		t.Fatalf("%+v", plan)
	}
	dest := destinations(c)
	for _, fp := range plan.Fichiers {
		if fp.Destination != dest[fp.Nom] {
			t.Errorf("%s → %s, attendu %s", fp.Nom, fp.Destination, dest[fp.Nom])
		}
		// Les modules de la famille DE LA MACHINE, pas de l'autre.
		if got := lire(t, fp.Source); got != p.contenus[fp.Nom] {
			t.Errorf("%s : %q", fp.Nom, got)
		}
		info, _ := os.Stat(fp.Source)
		attendu := os.FileMode(0o755)
		if fp.Nom == "vaultaire_client" {
			attendu = 0o750
		}
		if info.Mode().Perm() != attendu || fp.Mode != attendu {
			t.Errorf("%s : mode %v / %v", fp.Nom, info.Mode().Perm(), fp.Mode)
		}
	}
	// ldd sur les quatre bibliothèques, --check sur le nouveau binaire.
	for _, so := range []string{"pam_login_custom_module.so", "pam_logout_custom_module.so",
		"pam_ssh_auth_module.so", "libnss_vaultaire.so.2"} {
		if !f.aAppele("ldd " + filepath.Join(plan.Repertoire, "nouveau", so)) {
			t.Errorf("ldd %s non joué : %v", so, f.appels)
		}
	}
	if !f.aAppele("vaultaire_client --check") || f.aAppele("ldd "+filepath.Join(plan.Repertoire, "nouveau", "vaultaire_client")) {
		t.Errorf("%v", f.appels)
	}
	// Le plan est relu tel quel par l'updater.
	relu, err := LirePlan(plan.Repertoire)
	if err != nil || relu.Version != "2.3.1" || len(relu.Fichiers) != 5 {
		t.Fatalf("plan relu : %+v %v", relu, err)
	}
}

func TestPreparerDebian(t *testing.T) {
	c := installationDeTest(t)
	ecrire(t, c.OSRelease, "ID=ubuntu\nID_LIKE=debian\n", 0o644)
	p := fabriquerPaquet(t, "2.3.1", "debian", "")
	prep := preparationDeTest(t, c, p, &fauxSysteme{})
	prep.Telecharger = p.servir(baseTest, "debian", "2.3.1")
	plan, err := Preparer(prep, Ordre{Version: "2.3.1"})
	if err != nil || plan.Famille != "debian" {
		t.Fatalf("%+v %v", plan, err)
	}
}

func TestPreparerRefus(t *testing.T) {
	type cas struct {
		nom       string
		modifier  func(c Chemins, p *paquetDeTest, prep *Preparation, f *fauxSysteme)
		alterer   string
		contient  string
		transitif bool
	}
	autreCle, _ := rsa.GenerateKey(rand.Reader, 2048)
	for _, k := range []cas{
		{nom: "dépôt muet", transitif: true, contient: "HTTP 404",
			modifier: func(_ Chemins, _ *paquetDeTest, prep *Preparation, _ *fauxSysteme) {
				prep.Bases = []Base{{URL: "https://ailleurs.lan:8843"}}
			}},
		{nom: "aucun dépôt", transitif: true, contient: "aucun dépôt",
			modifier: func(_ Chemins, _ *paquetDeTest, prep *Preparation, _ *fauxSysteme) { prep.Bases = nil }},
		{nom: "clé inconnue", contient: "clé inconnue",
			modifier: func(_ Chemins, _ *paquetDeTest, prep *Preparation, _ *fauxSysteme) {
				prep.Cles = func() ([]*rsa.PublicKey, error) { return []*rsa.PublicKey{&autreCle.PublicKey}, nil }
			}},
		{nom: "manifeste retouché", contient: "signature invalide",
			modifier: func(_ Chemins, p *paquetDeTest, prep *Preparation, _ *fauxSysteme) {
				// Un caractère d'une empreinte, toujours hexadécimal : le
				// manifeste reste lisible, seule la signature peut le refuser.
				b := []byte(p.manifeste)
				if b[len(b)-2] == '0' {
					b[len(b)-2] = '1'
				} else {
					b[len(b)-2] = '0'
				}
				p.manifeste = string(b)
				prep.Telecharger = p.servir(baseTest, "rocky", "2.3.1")
			}},
		{nom: "empreinte fausse", alterer: "pam_ssh_auth_module.so", contient: "pam_ssh_auth_module.so : empreinte"},
		{nom: "module qui ne se charge pas", contient: "ne se charge pas sur cette machine : libpam.so.0 => not found",
			modifier: func(_ Chemins, _ *paquetDeTest, _ *Preparation, f *fauxSysteme) {
				f.reponses = func(nom string, args []string) ([]byte, error) {
					if nom == "ldd" && strings.HasSuffix(args[0], "pam_login_custom_module.so") {
						return []byte("\tlibpam.so.0 => not found\n"), nil
					}
					return nil, nil
				}
			}},
		{nom: "binaire qui refuse", contient: "refuse de démarrer : config illisible",
			modifier: func(_ Chemins, _ *paquetDeTest, _ *Preparation, f *fauxSysteme) {
				f.reponses = func(nom string, args []string) ([]byte, error) {
					if len(args) == 1 && args[0] == "--check" {
						return []byte("config illisible\n"), errors.New("exit status 1")
					}
					return nil, nil
				}
			}},
		{nom: "distribution inconnue", contient: "almalinux",
			modifier: func(c Chemins, _ *paquetDeTest, _ *Preparation, _ *fauxSysteme) {
				ecrire(t, c.OSRelease, "ID=almalinux\nID_LIKE=rhel\n", 0o644)
			}},
		{nom: "modules absents", contient: "introuvables",
			modifier: func(c Chemins, _ *paquetDeTest, prep *Preparation, _ *fauxSysteme) {
				prep.Chemins.ReposPAM = []string{t.TempDir()}
			}},
	} {
		t.Run(k.nom, func(t *testing.T) {
			c := installationDeTest(t)
			p := fabriquerPaquet(t, "2.3.1", "rocky", k.alterer)
			f := &fauxSysteme{}
			prep := preparationDeTest(t, c, p, f)
			if k.modifier != nil {
				k.modifier(c, &p, &prep, f)
			}
			_, err := Preparer(prep, Ordre{Version: "2.3.1"})
			if err == nil || !strings.Contains(err.Error(), k.contient) {
				t.Fatalf("erreur %v, attendu %q", err, k.contient)
			}
			if errors.Is(err, ErrTransitoire) != k.transitif {
				t.Errorf("transitoire = %v", errors.Is(err, ErrTransitoire))
			}
			if _, err := os.Stat(filepath.Join(c.Etat, "2.3.1", NomPlan)); err == nil {
				t.Error("plan écrit malgré le refus")
			}
			// Rien n'a bougé dans l'installation.
			if lire(t, c.Binaire) != "ancien-vaultaire_client" {
				t.Error("binaire en place modifié")
			}
		})
	}
}

// Le manifeste d'une AUTRE version, même authentique, est refusé : c'est ce
// qui empêche de faire installer une ancienne version signée.
func TestPreparerManifesteDUneAutreVersion(t *testing.T) {
	c := installationDeTest(t)
	ancien := fabriquerPaquet(t, "2.2.0", "rocky", "")
	f := &fauxSysteme{}
	prep := preparationDeTest(t, c, ancien, f)
	prep.Telecharger = func(url string, max int64) ([]byte, error) {
		// Un intermédiaire qui sert 2.2.0 sous les noms de 2.3.1.
		return ancien.servir(baseTest, "rocky", "2.2.0")(strings.ReplaceAll(url, "2.3.1", "2.2.0"), max)
	}
	if _, err := Preparer(prep, Ordre{Version: "2.3.1"}); err == nil || !strings.Contains(err.Error(), "l'ordre demande 2.3.1") {
		t.Fatalf("%v", err)
	}
}

// Second dépôt : le premier muet, le second répond.
func TestPreparerDepotSuivant(t *testing.T) {
	c := installationDeTest(t)
	p := fabriquerPaquet(t, "2.3.1", "rocky", "")
	prep := preparationDeTest(t, c, p, &fauxSysteme{})
	prep.Bases = []Base{{URL: "https://muet.lan:8843"}, {URL: baseTest}}
	if _, err := Preparer(prep, Ordre{Version: "2.3.1"}); err != nil {
		t.Fatal(err)
	}
}

func TestTelechargerHTTPSSeulementEtBorne(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/absent" {
			http.NotFound(w, r)
			return
		}
		_, _ = w.Write([]byte("0123456789"))
	}))
	defer srv.Close()

	// L'AC du serveur de test n'est pas celle du système : refusé…
	sansAC, err := ClientHTTP("")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := TelechargerAvec(sansAC)(srv.URL+"/x", 100); err == nil {
		t.Fatal("certificat inconnu accepté")
	}
	// … et accepté par update_tls_ca.
	ac := filepath.Join(t.TempDir(), "ac.pem")
	ecrire(t, ac, pemCertificat(srv), 0o644)
	avecAC, err := ClientHTTP(ac)
	if err != nil {
		t.Fatal(err)
	}
	tel := TelechargerAvec(avecAC)
	if b, err := tel(srv.URL+"/x", 100); err != nil || string(b) != "0123456789" {
		t.Fatalf("%q %v", b, err)
	}
	if _, err := tel(srv.URL+"/x", 5); err == nil {
		t.Error("taille dépassée acceptée")
	}
	if _, err := tel(srv.URL+"/absent", 100); err == nil || !strings.Contains(err.Error(), "404") {
		t.Errorf("%v", err)
	}
	if _, err := tel(strings.Replace(srv.URL, "https://", "http://", 1)+"/x", 100); err == nil {
		t.Error("http:// accepté")
	}
	// Un fichier d'AC illisible est une erreur, pas un repli silencieux.
	if _, err := ClientHTTP(filepath.Join(t.TempDir(), "absent.pem")); err == nil {
		t.Error("AC absente acceptée")
	}
	vide := filepath.Join(t.TempDir(), "vide.pem")
	ecrire(t, vide, "pas un certificat", 0o644)
	if _, err := ClientHTTP(vide); err == nil {
		t.Error("AC vide acceptée")
	}
}
