package outil

import (
	"crypto/rsa"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"vaultaire/core/paquetagent"
)

const jetonTest = "nxs_jeton-de-test-secret"

// nexusFactice imite l'API de Vaultaire Nexus utile au versement : liste,
// versement (immuable), suppression, et téléchargement anonyme.
type nexusFactice struct {
	mu       sync.Mutex
	srv      *httptest.Server
	depot    string
	fichiers map[string][]byte
	prive    bool // téléchargement réservé aux porteurs de jeton
	versions []string
	// jetonVuAuTelechargement : un téléchargement a reçu l'en-tête.
	jetonVuAuTelechargement bool
	// jeton : celui que ce Nexus accepte (jetonTest par défaut).
	jeton string
}

func nouveauNexus(t *testing.T) *nexusFactice {
	t.Helper()
	n := &nexusFactice{depot: "releases", fichiers: map[string][]byte{}, jeton: jetonTest}
	mux := http.NewServeMux()
	auth := func(w http.ResponseWriter, r *http.Request) bool {
		if r.Header.Get("Authorization") != "Bearer "+n.jeton {
			w.WriteHeader(http.StatusUnauthorized)
			_, _ = w.Write([]byte(`{"error":"identifiants refusés"}`))
			return false
		}
		if r.PathValue("repo") != n.depot {
			w.WriteHeader(http.StatusNotFound)
			_, _ = w.Write([]byte(`{"error":"dépôt introuvable"}`))
			return false
		}
		return true
	}
	mux.HandleFunc("GET /api/v1/repos/{repo}/packages", func(w http.ResponseWriter, r *http.Request) {
		if !auth(w, r) {
			return
		}
		n.mu.Lock()
		defer n.mu.Unlock()
		out := []paquetNexus{}
		for nom, c := range n.fichiers {
			s := sha256.Sum256(c)
			out = append(out, paquetNexus{ID: "id-" + nom, Version: "2.3.0", Filename: nom,
				Digest: "sha256:" + hex.EncodeToString(s[:])})
		}
		_ = json.NewEncoder(w).Encode(out)
	})
	mux.HandleFunc("PUT /api/v1/repos/{repo}/upload/{filename}", func(w http.ResponseWriter, r *http.Request) {
		if !auth(w, r) {
			return
		}
		corps, _ := io.ReadAll(r.Body)
		n.mu.Lock()
		defer n.mu.Unlock()
		nom := r.PathValue("filename")
		if _, ok := n.fichiers[nom]; ok {
			w.WriteHeader(http.StatusConflict)
			_, _ = w.Write([]byte(`{"error":"cette version existe déjà — une version publiée est immuable, supprimez-la d'abord"}`))
			return
		}
		n.fichiers[nom] = corps
		w.WriteHeader(http.StatusCreated)
	})
	mux.HandleFunc("DELETE /api/v1/repos/{repo}/packages/{id}", func(w http.ResponseWriter, r *http.Request) {
		if !auth(w, r) {
			return
		}
		n.mu.Lock()
		defer n.mu.Unlock()
		nom := strings.TrimPrefix(r.PathValue("id"), "id-")
		if _, ok := n.fichiers[nom]; !ok {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		delete(n.fichiers, nom)
		w.WriteHeader(http.StatusNoContent)
	})
	mux.HandleFunc("GET /repo/vaultaire/{repo}/download/{version}/{file}", func(w http.ResponseWriter, r *http.Request) {
		n.mu.Lock()
		defer n.mu.Unlock()
		if r.Header.Get("Authorization") != "" {
			n.jetonVuAuTelechargement = true
		}
		if n.prive && r.Header.Get("Authorization") == "" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		n.versions = append(n.versions, r.PathValue("version"))
		c, ok := n.fichiers[r.PathValue("file")]
		if !ok || r.PathValue("repo") != n.depot {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		_, _ = w.Write(c)
	})
	n.srv = httptest.NewTLSServer(mux)
	t.Cleanup(n.srv.Close)
	return n
}

func (n *nexusFactice) contenu(nom string) ([]byte, bool) {
	n.mu.Lock()
	defer n.mu.Unlock()
	c, ok := n.fichiers[nom]
	return c, ok
}

func (n *nexusFactice) nombre() int {
	n.mu.Lock()
	defer n.mu.Unlock()
	return len(n.fichiers)
}

// ecrireCA écrit les certificats des Nexus factices, pour --ca.
func ecrireCA(t *testing.T, dir string, nexus ...*nexusFactice) string {
	t.Helper()
	var b strings.Builder
	for _, n := range nexus {
		b.Write(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: n.srv.Certificate().Raw}))
	}
	chemin := filepath.Join(dir, "ca.pem")
	if err := os.WriteFile(chemin, []byte(b.String()), 0o644); err != nil {
		t.Fatal(err)
	}
	return chemin
}

func ecrireCle(t *testing.T, dir, nom string) string {
	t.Helper()
	_, priv, _ := clePEM(t)
	chemin := filepath.Join(dir, nom)
	if err := os.WriteFile(chemin, []byte(priv), 0o600); err != nil {
		t.Fatal(err)
	}
	return chemin
}

// verifieAvec : la signature déposée vérifie-t-elle le manifeste avec cette clé ?
func verifieAvec(t *testing.T, n *nexusFactice, archive, famille string, cleFichier string) bool {
	t.Helper()
	sig, ok := n.contenu(filepath.Base(archive) + "." + famille + ".manifest.sig")
	if !ok {
		return false
	}
	manifeste, ok := n.contenu(filepath.Base(archive) + "." + famille + ".manifest")
	if !ok {
		return false
	}
	contenu, _ := os.ReadFile(cleFichier)
	privee, err := paquetagent.LireClePrivee(contenu)
	if err != nil {
		t.Fatal(err)
	}
	env, err := paquetagent.LireEnveloppe(string(sig))
	if err != nil {
		return false
	}
	_, err = paquetagent.Verifier(string(manifeste), env, []*rsa.PublicKey{&privee.PublicKey})
	return err == nil
}

func TestVersementDansDeuxNexus(t *testing.T) {
	t.Setenv(VariableJeton, jetonTest)
	dir := t.TempDir()
	a := ecrireArchive(t, dir)
	cle := ecrireCle(t, dir, "cle.pem")
	n1, n2 := nouveauNexus(t), nouveauNexus(t)
	ca := ecrireCA(t, dir, n1, n2)
	args := []string{"--publish-package", a, "--key", cle, "--repo", "releases",
		"--nexus", n1.srv.URL, "--nexus", n2.srv.URL, "--ca", ca}

	code, sortie, erreurs := executer(args, sansBase)
	if code != 0 {
		t.Fatalf("code %d : %s\n%s", code, erreurs, sortie)
	}
	for _, n := range []*nexusFactice{n1, n2} {
		if n.nombre() != 5 {
			t.Errorf("%d fichiers déposés, 5 attendus", n.nombre())
		}
		for _, f := range []string{"rocky", "debian"} {
			if !verifieAvec(t, n, a, f, cle) {
				t.Errorf("%s : signature déposée invalide", f)
			}
		}
		if n.jetonVuAuTelechargement {
			t.Error("la relecture doit se faire sans jeton, comme un agent")
		}
		for _, v := range n.versions {
			if v != "v2.3.0" {
				t.Errorf("URL de téléchargement en %q, v2.3.0 attendu", v)
			}
		}
	}
	if !strings.Contains(sortie, "Bilan : 2/2 Nexus à jour.") || strings.Contains(sortie+erreurs, jetonTest) {
		t.Errorf("sortie inattendue (ou jeton affiché) :\n%s", sortie)
	}

	// Rejouer : rien n'est resigné ni reversé.
	code, sortie, erreurs = executer(args, sansBase)
	if code != 0 {
		t.Fatalf("rejeu : code %d : %s\n%s", code, erreurs, sortie)
	}
	if strings.Contains(sortie, "versé  ") || strings.Count(sortie, "déjà en place") != 10 ||
		strings.Count(sortie, "déjà signé") != 2 {
		t.Errorf("rejeu : tout doit être déjà en place :\n%s", sortie)
	}
}

// Sans jeton, rien n'est signé ni contacté.
func TestVersementSansJeton(t *testing.T) {
	t.Setenv(VariableJeton, "")
	dir := t.TempDir()
	a := ecrireArchive(t, dir)
	cle := ecrireCle(t, dir, "cle.pem")
	n := nouveauNexus(t)
	code, _, erreurs := executer([]string{"--publish-package", a, "--key", cle, "--nexus", n.srv.URL,
		"--repo", "releases"}, sansBase)
	if code != 1 || !strings.Contains(erreurs, VariableJeton) {
		t.Fatalf("code %d : %s", code, erreurs)
	}
	if _, err := os.Stat(a + ".rocky.manifest.sig"); !os.IsNotExist(err) {
		t.Error("aucune signature ne doit être écrite sans jeton")
	}
}

func TestJetonParFichier(t *testing.T) {
	t.Setenv(VariableJeton, "nxs_mauvais")
	dir := t.TempDir()
	a := ecrireArchive(t, dir)
	cle := ecrireCle(t, dir, "cle.pem")
	n := nouveauNexus(t)
	fj := filepath.Join(dir, "jeton")
	_ = os.WriteFile(fj, []byte(jetonTest+"\n"), 0o600)
	code, sortie, erreurs := executer([]string{"--publish-package", a, "--key", cle, "--nexus", n.srv.URL,
		"--repo", "releases", "--ca", ecrireCA(t, dir, n), "--token-file", fj}, sansBase)
	if code != 0 {
		t.Fatalf("le fichier doit l'emporter sur la variable : code %d : %s\n%s", code, erreurs, sortie)
	}
}

func TestJetonRefuse(t *testing.T) {
	t.Setenv(VariableJeton, "nxs_mauvais")
	dir := t.TempDir()
	a := ecrireArchive(t, dir)
	cle := ecrireCle(t, dir, "cle.pem")
	n := nouveauNexus(t)
	code, sortie, _ := executer([]string{"--publish-package", a, "--key", cle, "--nexus", n.srv.URL,
		"--repo", "releases", "--ca", ecrireCA(t, dir, n)}, sansBase)
	if code != 1 || !strings.Contains(sortie, "jeton refusé") || strings.Contains(sortie, "nxs_mauvais") {
		t.Fatalf("code %d :\n%s", code, sortie)
	}
}

func TestJetonSurLaLigneRefuse(t *testing.T) {
	code, _, erreurs := executer([]string{"--publish-package", "a.tar.gz", "--token", jetonTest}, sansBase)
	if code != 2 || !strings.Contains(erreurs, VariableJeton) {
		t.Fatalf("code %d : %s", code, erreurs)
	}
}

// Sans --ca, le certificat du Nexus factice n'est pas reconnu : TLS vérifié.
func TestTLSVerifie(t *testing.T) {
	t.Setenv(VariableJeton, jetonTest)
	dir := t.TempDir()
	a := ecrireArchive(t, dir)
	cle := ecrireCle(t, dir, "cle.pem")
	n := nouveauNexus(t)
	code, sortie, _ := executer([]string{"--publish-package", a, "--key", cle, "--nexus", n.srv.URL,
		"--repo", "releases"}, sansBase)
	if code != 1 || !strings.Contains(sortie, "certificate") || n.nombre() != 0 {
		t.Fatalf("code %d :\n%s", code, sortie)
	}
}

// Une archive différente sous le même nom : rien n'est versé.
func TestArchiveDejaPublieeDifferente(t *testing.T) {
	t.Setenv(VariableJeton, jetonTest)
	dir := t.TempDir()
	a := ecrireArchive(t, dir)
	cle := ecrireCle(t, dir, "cle.pem")
	n := nouveauNexus(t)
	n.fichiers[filepath.Base(a)] = []byte("une autre release")
	code, sortie, _ := executer([]string{"--publish-package", a, "--key", cle, "--nexus", n.srv.URL,
		"--repo", "releases", "--ca", ecrireCA(t, dir, n)}, sansBase)
	if code != 1 || !strings.Contains(sortie, "immuable") || n.nombre() != 1 {
		t.Fatalf("code %d, %d fichiers :\n%s", code, n.nombre(), sortie)
	}
}

// Une autre signature valide de la même clé est gardée.
func TestSignatureValideGardee(t *testing.T) {
	t.Setenv(VariableJeton, jetonTest)
	dir := t.TempDir()
	a := ecrireArchive(t, dir)
	cle := ecrireCle(t, dir, "cle.pem")
	n := nouveauNexus(t)
	args := []string{"--publish-package", a, "--key", cle, "--nexus", n.srv.URL,
		"--repo", "releases", "--ca", ecrireCA(t, dir, n)}
	if code, sortie, erreurs := executer(args, sansBase); code != 0 {
		t.Fatalf("code %d : %s\n%s", code, erreurs, sortie)
	}
	avant, _ := n.contenu(filepath.Base(a) + ".rocky.manifest.sig")
	// Un autre poste, une autre signature PSS de la même clé.
	_ = os.Remove(a + ".rocky.manifest.sig")
	_ = os.Remove(a + ".debian.manifest.sig")
	code, sortie, erreurs := executer(args, sansBase)
	if code != 0 || strings.Count(sortie, "signature gardée") != 2 {
		t.Fatalf("code %d : %s\n%s", code, erreurs, sortie)
	}
	apres, _ := n.contenu(filepath.Base(a) + ".rocky.manifest.sig")
	if string(avant) != string(apres) {
		t.Error("la signature déjà publiée ne doit pas être remplacée")
	}
}

// Après une bascule (207) : les signatures de l'ancienne clé ne sont
// remplacées que sur demande.
func TestSignaturesDeLAncienneCle(t *testing.T) {
	t.Setenv(VariableJeton, jetonTest)
	dir := t.TempDir()
	a := ecrireArchive(t, dir)
	ancienne := ecrireCle(t, dir, "ancienne.pem")
	nouvelle := ecrireCle(t, dir, "nouvelle.pem")
	n := nouveauNexus(t)
	ca := ecrireCA(t, dir, n)
	base := []string{"--publish-package", a, "--nexus", n.srv.URL, "--repo", "releases", "--ca", ca}
	if code, sortie, erreurs := executer(append(base, "--key", ancienne), sansBase); code != 0 {
		t.Fatalf("code %d : %s\n%s", code, erreurs, sortie)
	}

	code, sortie, _ := executer(append(base, "--key", nouvelle), sansBase)
	if code != 1 || !strings.Contains(sortie, "--replace-signatures") || !verifieAvec(t, n, a, "rocky", ancienne) {
		t.Fatalf("sans --replace-signatures : code %d :\n%s", code, sortie)
	}

	code, sortie, erreurs := executer(append(base, "--key", nouvelle, "--replace-signatures"), sansBase)
	if code != 0 || strings.Count(sortie, "remplacée") != 2 {
		t.Fatalf("code %d : %s\n%s", code, erreurs, sortie)
	}
	for _, f := range []string{"rocky", "debian"} {
		if !verifieAvec(t, n, a, f, nouvelle) {
			t.Errorf("%s : la signature déposée doit être celle de la nouvelle clé", f)
		}
	}
}

// Un dépôt que les agents ne peuvent pas lire sans jeton : échec.
func TestDepotPrive(t *testing.T) {
	t.Setenv(VariableJeton, jetonTest)
	dir := t.TempDir()
	a := ecrireArchive(t, dir)
	cle := ecrireCle(t, dir, "cle.pem")
	n := nouveauNexus(t)
	n.prive = true
	code, sortie, _ := executer([]string{"--publish-package", a, "--key", cle, "--nexus", n.srv.URL,
		"--repo", "releases", "--ca", ecrireCA(t, dir, n)}, sansBase)
	if code != 1 || !strings.Contains(sortie, "pas public") {
		t.Fatalf("code %d :\n%s", code, sortie)
	}
}

// Les Nexus du cluster et le dépôt réglé, lus en base.
func TestNexusDuCluster(t *testing.T) {
	t.Setenv(VariableJeton, jetonTest)
	dir := t.TempDir()
	a := ecrireArchive(t, dir)
	cle := ecrireCle(t, dir, "cle.pem")
	n := nouveauNexus(t)
	n.depot = "parc"
	ouvertures := 0
	ouvrir := func() (Cles, error) {
		ouvertures++
		return Cles{
			Depot: func() (string, error) { return "parc", nil },
			Nexus: func() ([]NexusCible, error) {
				return []NexusCible{
					{Nom: "nexus-a", URL: n.srv.URL, EnLigne: true, ExposeAgents: true},
					{Nom: "nexus-b", URL: "https://nexus-b.invalid:8843", EnLigne: false},
					{Nom: "nexus-c", Probleme: "point d'accès \"\" inutilisable"},
				}, nil
			},
		}, nil
	}
	code, sortie, erreurs := executer([]string{"--publish-package", a, "--key", cle,
		"--ca", ecrireCA(t, dir, n)}, ouvrir)
	if code != 1 || !strings.Contains(sortie, "Bilan : 1/3 Nexus à jour.") || n.nombre() != 5 {
		t.Fatalf("code %d : %s\n%s", code, erreurs, sortie)
	}
	if !strings.Contains(sortie, "hors ligne") || !strings.Contains(sortie, "inutilisable") ||
		!strings.Contains(sortie, "non annoncé aux agents") || !strings.Contains(sortie, "« parc »") {
		t.Errorf("compte rendu incomplet :\n%s", sortie)
	}
	if ouvertures != 1 {
		t.Errorf("base ouverte %d fois, une attendue", ouvertures)
	}
}

func TestNormaliserURLNexus(t *testing.T) {
	for saisie, attendu := range map[string]string{
		"https://nexus.acme.lan:8843":  "https://nexus.acme.lan:8843",
		"https://nexus.acme.lan:8843/": "https://nexus.acme.lan:8843",
		" https://nexus.acme.lan ":     "https://nexus.acme.lan",
	} {
		if u, err := NormaliserURLNexus(saisie); err != nil || u != attendu {
			t.Errorf("%q : %q, %v", saisie, u, err)
		}
	}
	for _, refus := range []string{"http://nexus.acme.lan", "https://u:p@nexus.acme.lan",
		"https://nexus.acme.lan/api", "nexus.acme.lan:8843", "https://"} {
		if _, err := NormaliserURLNexus(refus); err == nil {
			t.Errorf("%q devrait être refusée", refus)
		}
	}
}

func TestVersementSyntaxe(t *testing.T) {
	for _, args := range [][]string{
		{"--publish-package", "--key"},
		{"--publish-package", "a.tar.gz", "--nexus"},
		{"--publish-package", "a.tar.gz", "b.tar.gz"},
		{"--publish-package", "a.tar.gz", "--force"},
	} {
		if code, _, _ := executer(args, sansBase); code != 2 {
			t.Errorf("%v : code %d, 2 attendu", args, code)
		}
	}
}

// TO-DO 232 : chaque Nexus a son jeton. Le jeton par défaut ne vaut que pour
// les Nexus qui n'en ont pas de nommé ; un Nexus sans jeton est refusé avant
// toute signature ; un jeton nommé pour un Nexus non visé aussi.
func TestUnJetonParNexus(t *testing.T) {
	t.Setenv(VariableJeton, "")
	dir := t.TempDir()
	a := ecrireArchive(t, dir)
	cle := ecrireCle(t, dir, "cle.pem")
	n1, n2 := nouveauNexus(t), nouveauNexus(t)
	n2.jeton = "nxs_jeton-du-second"
	ca := ecrireCA(t, dir, n1, n2)
	j1, j2 := filepath.Join(dir, "j1"), filepath.Join(dir, "j2")
	_ = os.WriteFile(j1, []byte(jetonTest+"\n"), 0o600)
	_ = os.WriteFile(j2, []byte(n2.jeton+"\n"), 0o600)
	base := []string{"--publish-package", a, "--key", cle, "--repo", "releases",
		"--nexus", n1.srv.URL, "--nexus", n2.srv.URL, "--ca", ca}

	// Un seul jeton nommé : le second Nexus n'en a pas.
	code, _, erreurs := executer(append(append([]string{}, base...), "--token-file", n1.srv.URL+"="+j1), sansBase)
	if code != 1 || !strings.Contains(erreurs, n2.srv.URL) {
		t.Fatalf("Nexus sans jeton non nommé : code %d : %s", code, erreurs)
	}
	if _, err := os.Stat(a + ".rocky.manifest.sig"); !os.IsNotExist(err) {
		t.Error("rien ne doit être signé quand un jeton manque")
	}

	// Un jeton pour un Nexus qui n'est pas visé : refusé.
	code, _, erreurs = executer(append(append([]string{}, base...), "--token-file", j1,
		"--token-file", "https://ailleurs:8843="+j2), sansBase)
	if code != 1 || !strings.Contains(erreurs, "https://ailleurs:8843") {
		t.Fatalf("jeton d'un Nexus non visé : code %d : %s", code, erreurs)
	}

	// Le défaut pour le premier, le nommé pour le second : 2/2.
	t.Setenv(VariableJeton, jetonTest)
	code, sortie, erreurs := executer(append(append([]string{}, base...), "--token-file", n2.srv.URL+"="+j2), sansBase)
	if code != 0 || !strings.Contains(sortie, "Bilan : 2/2") {
		t.Fatalf("code %d : %s\n%s", code, erreurs, sortie)
	}
	if n1.nombre() != 5 || n2.nombre() != 5 {
		t.Errorf("fichiers : %d et %d, 5 attendus", n1.nombre(), n2.nombre())
	}
	if strings.Contains(sortie+erreurs, n2.jeton) || strings.Contains(sortie+erreurs, jetonTest) {
		t.Error("un jeton est affiché")
	}
}

func TestTokenFileSyntaxe(t *testing.T) {
	var o optionsVersement
	if err := o.ajouterFichierJeton("http://n:8843=/j"); err == nil {
		t.Error("http:// accepté")
	}
	if err := o.ajouterFichierJeton("https://n:8843"); err == nil {
		t.Error("URL sans fichier acceptée")
	}
	if err := o.ajouterFichierJeton("https://n:8843/=/j"); err != nil || o.jetonsNommes["https://n:8843"] != "/j" {
		t.Errorf("%v %v", err, o.jetonsNommes)
	}
	if err := o.ajouterFichierJeton("https://n:8843=/k"); err == nil {
		t.Error("deux jetons pour un Nexus acceptés")
	}
	if err := o.ajouterFichierJeton("/a"); err != nil {
		t.Fatal(err)
	}
	if err := o.ajouterFichierJeton("/b"); err == nil {
		t.Error("deux jetons par défaut acceptés")
	}
}

// TO-DO 234 : dépôt rendu privé APRÈS un premier versement. La signature en
// place, relue sans jeton, rend 401 : le message dit « pas public », et non
// « ancienne clé » — --replace-signatures n'y changerait rien.
func TestDepotDevenuPriveNEstPasUneAncienneCle(t *testing.T) {
	t.Setenv(VariableJeton, jetonTest)
	dir := t.TempDir()
	a := ecrireArchive(t, dir)
	cle := ecrireCle(t, dir, "cle.pem")
	n := nouveauNexus(t)
	args := []string{"--publish-package", a, "--key", cle, "--nexus", n.srv.URL, "--repo", "releases",
		"--ca", ecrireCA(t, dir, n)}
	if code, sortie, erreurs := executer(args, sansBase); code != 0 {
		t.Fatalf("premier versement : %d %s\n%s", code, erreurs, sortie)
	}
	// Signatures locales effacées : les nouvelles diffèrent, la relecture de
	// celles du Nexus est nécessaire.
	for _, f := range []string{"rocky", "debian"} {
		_ = os.Remove(a + "." + f + ".manifest.sig")
	}
	n.mu.Lock()
	n.prive = true
	n.mu.Unlock()
	code, sortie, _ := executer(args, sansBase)
	if code != 1 || !strings.Contains(sortie, "pas public") || strings.Contains(sortie, "ancienne clé") {
		t.Fatalf("code %d :\n%s", code, sortie)
	}
}
