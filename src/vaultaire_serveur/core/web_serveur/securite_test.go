package webserveur

import (
	"html/template"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// Jeton CSRF et en-têtes de sécurité du portail (TO-DO 103).
//
// # Ce que ces tests gardent
//
//   - un POST porteur d'un cookie de session n'atteint aucun gestionnaire sans
//     le jeton qui correspond à ce cookie ;
//   - chaque formulaire POST rendu reçoit ce jeton, sans que le gabarit ait à
//     l'écrire ;
//   - aucun gabarit ne contient de script en ligne ni d'attribut on* : la
//     Content-Security-Policy les refuserait, et la page cesserait de
//     fonctionner en silence.

const cookieDeTest = "jeton-de-session-de-test"

func requete(methode, cible string, corps url.Values, avecCookie bool) *http.Request {
	var r *http.Request
	if corps != nil {
		r = httptest.NewRequest(methode, cible, strings.NewReader(corps.Encode()))
		r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	} else {
		r = httptest.NewRequest(methode, cible, nil)
	}
	if avecCookie {
		r.AddCookie(&http.Cookie{Name: "session_token", Value: cookieDeTest})
	}
	return r
}

// servir passe une requête par Proteger et dit si le gestionnaire l'a reçue.
func servir(r *http.Request) (*httptest.ResponseRecorder, bool) {
	atteint := false
	h := Proteger(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atteint = true
		w.WriteHeader(http.StatusOK)
	}))
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	return w, atteint
}

func TestUnPostSansJetonNAtteintAucunGestionnaire(t *testing.T) {
	bon := jetonCSRF(cookieDeTest)
	cas := []struct {
		nom     string
		req     *http.Request
		atteint bool
	}{
		{"GET avec session", requete(http.MethodGet, "/admin/users", nil, true), true},
		{"POST sans session (connexion)", requete(http.MethodPost, "/login", url.Values{"username": {"a"}}, false), true},
		{"POST avec session, sans jeton", requete(http.MethodPost, "/admin/users", url.Values{"action": {"delete"}}, true), false},
		{"POST avec session, jeton faux", requete(http.MethodPost, "/admin/users",
			url.Values{"action": {"delete"}, "csrf": {jetonCSRF("autre-session")}}, true), false},
		{"POST avec session, bon jeton", requete(http.MethodPost, "/admin/users",
			url.Values{"action": {"delete"}, "csrf": {bon}}, true), true},
	}
	for _, c := range cas {
		w, atteint := servir(c.req)
		if atteint != c.atteint {
			t.Errorf("%s : gestionnaire atteint = %v, attendu %v (statut %d)", c.nom, atteint, c.atteint, w.Code)
		}
		if !c.atteint && w.Code != http.StatusForbidden {
			t.Errorf("%s : statut %d, attendu 403", c.nom, w.Code)
		}
	}

	// L'en-tête vaut le champ, pour un appel JavaScript.
	r := requete(http.MethodPost, "/admin/api/x", nil, true)
	r.Header.Set("X-CSRF-Token", bon)
	if _, atteint := servir(r); !atteint {
		t.Error("jeton passé par l'en-tête X-CSRF-Token refusé")
	}
}

func TestLesEntetesDeSecuriteSontSurToutesLesReponses(t *testing.T) {
	for _, r := range []*http.Request{
		requete(http.MethodGet, "/", nil, false),
		requete(http.MethodGet, "/static/app.css", nil, true),
		requete(http.MethodPost, "/admin/users", url.Values{}, true), // refusé : en-têtes quand même
	} {
		w, _ := servir(r)
		for _, h := range []string{"Content-Security-Policy", "X-Frame-Options", "X-Content-Type-Options",
			"Referrer-Policy", "Strict-Transport-Security"} {
			if w.Header().Get(h) == "" {
				t.Errorf("%s %s : en-tête %s absent", r.Method, r.URL.Path, h)
			}
		}
		if csp := w.Header().Get("Content-Security-Policy"); !strings.Contains(csp, "script-src 'self';") {
			t.Errorf("CSP %q : script-src doit être 'self' seul — c'est ce qui en fait une défense", csp)
		}
	}
}

func TestLeJetonEntreDansChaqueFormulairePost(t *testing.T) {
	page := []byte(`<form method="post" action="/a"><button></button></form>
<FORM class="x" METHOD='POST'>
<form
   method="post"
   class="multi">
<form method="get" action="/recherche">
<form action="/b">`)
	out := string(injecterJetonCSRF(page, "abc"))
	if n := strings.Count(out, `name="csrf" value="abc"`); n != 3 {
		t.Errorf("%d jeton(s) inséré(s), attendu 3 (les trois POST, pas le GET ni le formulaire sans méthode) :\n%s", n, out)
	}
	if strings.Contains(out, `/recherche"><input type="hidden" name="csrf"`) {
		t.Error("le jeton entre dans un formulaire GET : il fuirait dans l'adresse")
	}
	if got := injecterJetonCSRF(page, ""); string(got) != string(page) {
		t.Error("sans session, la page doit rester intacte")
	}
}

// TestDeLaRequeteALaPage : le jeton rendu par une vraie page est celui que le
// middleware attend au retour.
func TestDeLaRequeteALaPage(t *testing.T) {
	tmpl := template.Must(template.New("p").Parse(`<form method="post"><input name="x"></form>`))
	h := Proteger(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if err := rendreGabarit(w, tmpl, nil); err != nil {
			t.Fatal(err)
		}
	}))
	w := httptest.NewRecorder()
	h.ServeHTTP(w, requete(http.MethodGet, "/profil", nil, true))
	m := regexp.MustCompile(`name="csrf" value="([0-9a-f]+)"`).FindStringSubmatch(w.Body.String())
	if m == nil {
		t.Fatalf("aucun jeton dans la page rendue : %s", w.Body.String())
	}
	if _, atteint := servir(requete(http.MethodPost, "/profil", url.Values{"x": {"1"}, "csrf": {m[1]}}, true)); !atteint {
		t.Error("le jeton rendu dans la page est refusé au retour")
	}
}

// TestUnNouveauCookieDonneUnNouveauJeton : après un changement de mot de passe,
// la page rendue dans la même réponse porte le jeton du NOUVEAU cookie.
func TestUnNouveauCookieDonneUnNouveauJeton(t *testing.T) {
	w := &reponseProtegee{ResponseWriter: httptest.NewRecorder(), jeton: jetonCSRF("ancien")}
	setSessionCookie(w, "nouveau")
	if jetonDeLaReponse(w) != jetonCSRF("nouveau") {
		t.Error("le jeton n'a pas suivi le nouveau cookie : le prochain envoi serait refusé")
	}
}

// TestAucunScriptEnLigneDansLesGabarits : la CSP refuse les scripts en ligne.
// Un gabarit qui en réintroduirait un fonctionnerait au poste du développeur
// sans CSP… et plus du tout en production, sans message.
func TestAucunScriptEnLigneDansLesGabarits(t *testing.T) {
	fichiers, err := filepath.Glob(filepath.Join(RepertoireGabarits(), "*.html"))
	if err != nil || len(fichiers) < 20 {
		t.Fatalf("gabarits introuvables (%d, %v) : ce test ne vérifierait rien", len(fichiers), err)
	}
	attributOn := regexp.MustCompile(`(?i)<[a-z][^>]*\son[a-z]+\s*=`)
	lienJS := regexp.MustCompile(`(?i)javascript:`)
	for _, f := range fichiers {
		b, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		s := string(b)
		nom := filepath.Base(f)
		for _, m := range regexp.MustCompile(`(?is)<script\b[^>]*>(.*?)</script>`).FindAllStringSubmatch(s, -1) {
			if !strings.Contains(m[0], "src=") || strings.TrimSpace(m[1]) != "" {
				t.Errorf("%s : script en ligne — la CSP le bloquerait. À déplacer dans /static.", nom)
			}
		}
		if m := attributOn.FindString(s); m != "" {
			t.Errorf("%s : attribut de gestionnaire en ligne %q — la CSP le bloquerait "+
				"(confirmations : data-confirm)", nom, m)
		}
		if lienJS.MatchString(s) {
			t.Errorf("%s : lien javascript: — la CSP le bloquerait", nom)
		}
	}
}
