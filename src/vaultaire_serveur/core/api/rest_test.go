package api

import (
	"bytes"
	"crypto/rand"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"

	"vaultaire/core/action"

	"golang.org/x/crypto/ssh"
)

// L'API REST — TO-DO 270.
//
// Ce que ces tests gardent :
//   - une requête signée selon ChaineCanoniqueREST est acceptée ; un octet changé
//     dans le chemin, la requête ou le corps la fait refuser ; un nonce rejoué aussi ;
//   - une route ressource appelle L'ACTION de sa table, avec les paramètres du
//     chemin, du corps et de la requête, et l'appelant authentifié ;
//   - le corps ne peut pas changer la cible désignée par le chemin ;
//   - les erreurs du registre deviennent un statut et un code stables ;
//   - la route générique refuse une écriture en GET ;
//   - chaque route nomme une action qui existe.

var sourceREST int

type appelREST struct {
	nom      string
	appelant action.Appelant
	params   action.Params
}

// bancREST : un banc d'authentification (api_test.go) et un registre simulé.
type bancREST struct {
	*banc
	mux     *http.ServeMux
	appels  []appelREST
	reponse action.Resultat
	erreur  error
}

func nouveauBancREST(t *testing.T) *bancREST {
	t.Helper()
	b := &bancREST{banc: nouveauBanc(t), mux: http.NewServeMux()}
	EnregistrerREST(b.mux)

	ancExec, ancGroupes, ancCmd, ancCat := executerActionREST, groupesDeREST, executerCommandeREST, catalogueREST
	executerActionREST = func(nom string, a action.Appelant, p action.Params) (action.Resultat, error) {
		b.appels = append(b.appels, appelREST{nom, a, p})
		return b.reponse, b.erreur
	}
	groupesDeREST = func(string) ([]int, error) { return []int{3}, nil }
	executerCommandeREST = func(cmd, user string) string { return "sortie de « " + cmd + " » pour " + user }
	catalogueREST = func() []action.Definition {
		var defs []action.Definition
		for _, nom := range RoutesActionsREST() {
			cle := "write:x:y"
			if strings.HasSuffix(nom, ".list") || strings.HasSuffix(nom, ".get") {
				cle = "read:get:user"
			}
			defs = append(defs, action.Definition{Nom: nom, CleRBAC: cle, Resume: nom})
		}
		return defs
	}
	t.Cleanup(func() {
		executerActionREST, groupesDeREST, executerCommandeREST, catalogueREST = ancExec, ancGroupes, ancCmd, ancCat
	})
	return b
}

// requete fabrique une requête REST signée comme le fera `vlt api`.
func (b *bancREST) requete(signer ssh.Signer, compte, methode, cible string, corps []byte) *http.Request {
	b.t.Helper()
	r := httptest.NewRequest(methode, cible, bytes.NewReader(corps))
	// Une source par requête : les échecs voulus des tests ne doivent pas
	// déclencher le frein des échecs répétés d'une source.
	sourceREST++
	r.RemoteAddr = fmt.Sprintf("10.9.%d.%d:40000", sourceREST/250, sourceREST%250+1)
	horodatage := time.Now().Unix()
	nonce := fmt.Sprintf("n-%d", time.Now().UnixNano())
	canon := ChaineCanoniqueREST(methode, r.URL.EscapedPath(), r.URL.RawQuery, compte, horodatage, nonce, corps)
	sig, err := signer.Sign(rand.Reader, canon)
	if err != nil {
		b.t.Fatal(err)
	}
	r.Header.Set("Authorization", "Vaultaire-SSH "+base64.StdEncoding.EncodeToString(ssh.Marshal(sig)))
	r.Header.Set(enteteUtilisateur, compte)
	r.Header.Set(enteteHorodatage, strconv.FormatInt(horodatage, 10))
	r.Header.Set(enteteNonce, nonce)
	return r
}

func (b *bancREST) servir(r *http.Request) (*httptest.ResponseRecorder, reponseREST) {
	b.t.Helper()
	w := httptest.NewRecorder()
	b.mux.ServeHTTP(w, r)
	var rep reponseREST
	if err := json.Unmarshal(w.Body.Bytes(), &rep); err != nil {
		b.t.Fatalf("réponse non JSON (%d) : %s", w.Code, w.Body.String())
	}
	return w, rep
}

func TestRESTUneRouteAppelleSonAction(t *testing.T) {
	b := nouveauBancREST(t)
	b.reponse = action.Resultat{Message: "Utilisateur bob@acme.lan créé."}

	corps := []byte(`{"username":"bob","domain":"acme.lan","password":"x","group":"admin-users","temporary":false}`)
	w, rep := b.servir(b.requete(b.alice, "alice", "POST", "/api/v1/users", corps))
	if w.Code != http.StatusCreated || !rep.OK {
		t.Fatalf("statut %d, réponse %+v", w.Code, rep)
	}
	if len(b.appels) != 1 || b.appels[0].nom != "user.create" {
		t.Fatalf("appels %+v", b.appels)
	}
	a := b.appels[0]
	if a.appelant.Username != "alice" || len(a.appelant.GroupIDs) != 1 {
		t.Errorf("appelant %+v : doit être le compte AUTHENTIFIÉ, avec ses groupes", a.appelant)
	}
	if a.params["group"] != "admin-users" || a.params["temporary"] != "false" || a.params["username"] != "bob" {
		t.Errorf("paramètres %v", a.params)
	}
}

func TestRESTParametresDuChemin(t *testing.T) {
	b := nouveauBancREST(t)
	w, _ := b.servir(b.requete(b.alice, "alice", "PUT", "/api/v1/groups/infra/users/bob", nil))
	if w.Code != http.StatusOK || len(b.appels) != 1 {
		t.Fatalf("statut %d, appels %+v", w.Code, b.appels)
	}
	p := b.appels[0].params
	if b.appels[0].nom != "group.add_user" || p["group"] != "infra" || p["username"] != "bob" {
		t.Fatalf("appel %+v", b.appels[0])
	}

	// Le corps ne change pas la cible.
	w, rep := b.servir(b.requete(b.alice, "alice", "DELETE", "/api/v1/users/alice", []byte(`{"username":"bob"}`)))
	if w.Code != http.StatusBadRequest || rep.Error == nil || rep.Error.Code != codeRequeteInvalide {
		t.Fatalf("cible changée par le corps : %d %+v", w.Code, rep)
	}
	if len(b.appels) != 1 {
		t.Fatal("l'action a été appelée malgré le conflit")
	}
}

func TestRESTSignatureCouvreToutLaRequete(t *testing.T) {
	b := nouveauBancREST(t)
	cas := map[string]func(r *http.Request){
		"chemin changé":   func(r *http.Request) { r.URL.Path = "/api/v1/users/root"; r.URL.RawPath = "" },
		"requête changée": func(r *http.Request) { r.URL.RawQuery = "x=1" },
		"compte changé":   func(r *http.Request) { r.Header.Set(enteteUtilisateur, "bob") },
		"signature d'un autre": func(r *http.Request) {
			r2 := b.requete(b.autre, "alice", "GET", "/api/v1/users/alice", nil)
			r.Header.Set("Authorization", r2.Header.Get("Authorization"))
		},
		"sans signature": func(r *http.Request) { r.Header.Del("Authorization") },
	}
	for nom, alterer := range cas {
		t.Run(nom, func(t *testing.T) {
			r := b.requete(b.alice, "alice", "GET", "/api/v1/users/alice", nil)
			alterer(r)
			w, rep := b.servir(r)
			if w.Code != http.StatusUnauthorized || rep.Error == nil || rep.Error.Code != codeNonAuthentifie {
				t.Fatalf("statut %d, %+v", w.Code, rep)
			}
		})
	}
	// Corps changé après signature.
	r := b.requete(b.alice, "alice", "POST", "/api/v1/groups", []byte(`{"group":"a","domain":"d"}`))
	r.Body = httpBody(`{"group":"b","domain":"d"}`)
	if w, _ := b.servir(r); w.Code != http.StatusUnauthorized {
		t.Fatalf("corps changé accepté : %d", w.Code)
	}
	if len(b.appels) != 0 {
		t.Fatalf("une requête refusée a appelé %+v", b.appels)
	}
}

func TestRESTNonceRejoue(t *testing.T) {
	b := nouveauBancREST(t)
	r := b.requete(b.alice, "alice", "GET", "/api/v1/users", nil)
	r2 := r.Clone(r.Context())
	if w, _ := b.servir(r); w.Code != http.StatusOK {
		t.Fatalf("premier envoi : %d", w.Code)
	}
	if w, _ := b.servir(r2); w.Code != http.StatusUnauthorized {
		t.Fatalf("rejeu accepté : %d", w.Code)
	}
}

func TestRESTErreursDuRegistre(t *testing.T) {
	cas := []struct {
		nom    string
		err    error
		statut int
		code   string
	}{
		{"refus", &action.ErrRefusee{Action: "user.create", Cle: "write:create:user", Motif: "droit manquant sur *"}, 403, codeRefuse},
		{"inconnue", &action.ErrInconnue{Nom: "x.y"}, 404, codeActionInconnue},
		{"confirmation", &action.ErrConfirmationRequise{Motif: "parc en retard", Rejouer: action.Params{"confirm": "oui"}}, 409, codeConfirmationRequise},
		{"introuvable", fmt.Errorf("groupe fantome introuvable : aucun compte créé"), 404, codeIntrouvable},
		{"échec", fmt.Errorf("mot de passe requis"), 422, codeActionEchouee},
	}
	for _, c := range cas {
		t.Run(c.nom, func(t *testing.T) {
			b := nouveauBancREST(t)
			b.erreur = c.err
			w, rep := b.servir(b.requete(b.alice, "alice", "POST", "/api/v1/actions/user.create", []byte(`{}`)))
			if w.Code != c.statut || rep.OK || rep.Error == nil || rep.Error.Code != c.code {
				t.Fatalf("statut %d, %+v", w.Code, rep)
			}
			if c.code == codeRefuse && rep.Error.Key != "write:create:user" {
				t.Errorf("droit refusé non nommé : %+v", rep.Error)
			}
			if c.code == codeConfirmationRequise && rep.Error.Replay["confirm"] != "oui" {
				t.Errorf("paramètres à renvoyer absents : %+v", rep.Error)
			}
		})
	}
}

func TestRESTGeneriqueRefuseUneEcritureEnGET(t *testing.T) {
	b := nouveauBancREST(t)
	w, rep := b.servir(b.requete(b.alice, "alice", "GET", "/api/v1/actions/user.create?username=x", nil))
	if w.Code != http.StatusMethodNotAllowed || rep.Error.Code != codeMethodeRefusee || len(b.appels) != 0 {
		t.Fatalf("écriture en GET : %d %+v, appels %v", w.Code, rep, b.appels)
	}
	w, _ = b.servir(b.requete(b.alice, "alice", "GET", "/api/v1/actions/user.list", nil))
	if w.Code != http.StatusOK || len(b.appels) != 1 || b.appels[0].nom != "user.list" {
		t.Fatalf("lecture en GET : %d %v", w.Code, b.appels)
	}
}

func TestRESTCommandeEtCatalogue(t *testing.T) {
	b := nouveauBancREST(t)
	w, rep := b.servir(b.requete(b.alice, "alice", "POST", "/api/v1/command", []byte(`{"command":"status -c"}`)))
	data, _ := rep.Data.(map[string]any)
	if w.Code != 200 || !strings.Contains(fmt.Sprint(data["output"]), "status -c") {
		t.Fatalf("commande : %d %+v", w.Code, rep)
	}
	w, rep = b.servir(b.requete(b.alice, "alice", "GET", "/api/v1/actions", nil))
	liste, _ := rep.Data.([]any)
	if w.Code != 200 || len(liste) != len(RoutesActionsREST()) {
		t.Fatalf("catalogue : %d, %d entrée(s)", w.Code, len(liste))
	}
	w, rep = b.servir(b.requete(b.alice, "alice", "GET", "/api/v1/nimporte/quoi", nil))
	if w.Code != 404 || rep.Error == nil {
		t.Fatalf("route inconnue : %d %+v", w.Code, rep)
	}
}

func TestRESTOpenAPISansAuthentification(t *testing.T) {
	b := nouveauBancREST(t)
	r := httptest.NewRequest("GET", "/api/v1/openapi.json", nil)
	w := httptest.NewRecorder()
	b.mux.ServeHTTP(w, r)
	var doc map[string]any
	if w.Code != 200 || json.Unmarshal(w.Body.Bytes(), &doc) != nil {
		t.Fatalf("openapi : %d", w.Code)
	}
	paths, _ := doc["paths"].(map[string]any)
	if _, ok := paths["/api/v1/users/{username}"]; !ok {
		t.Fatal("route /users/{username} absente de la description")
	}
}

// Les routes ressources nomment des actions du VRAI registre.
func TestRESTChaqueRouteNommeUneActionExistante(t *testing.T) {
	r := action.NouveauRegistre()
	action.EnregistrerToutDans(r)
	for _, nom := range RoutesActionsREST() {
		if _, ok := r.Definition(nom); !ok {
			t.Errorf("route REST vers %q : absente du registre", nom)
		}
	}
}

func TestSnakeCase(t *testing.T) {
	for entree, attendu := range map[string]string{
		"GroupName": "group_name", "ID": "id", "UserID": "user_id", "DNSName": "dns_name",
		"Database_portDatabase": "database_port_database", "CreatedAt": "created_at",
		"computeur_id": "computeur_id", "GPOs": "gpos", "UserIDs": "user_ids", "IDsList": "ids_list",
	} {
		if got := SnakeCase(entree); got != attendu {
			t.Errorf("SnakeCase(%q) = %q, attendu %q", entree, got, attendu)
		}
	}
}

func TestVersJSON(t *testing.T) {
	type interne struct {
		GroupName string
		Tagged    string `json:"etiquette"`
		Cache     string `json:"-"`
		Vide      string `json:",omitempty"`
		Quand     time.Time
		Nul       sql.NullString
		Membres   []string
		Index     map[string]int
		secret    string
	}
	v := versJSON([]interne{{GroupName: "Infra", Tagged: "t", Cache: "c",
		Quand: time.Date(2026, 11, 16, 10, 0, 0, 0, time.UTC), Index: map[string]int{"Alice": 1}, secret: "s"}})
	b, _ := json.Marshal(v)
	got := string(b)
	for _, attendu := range []string{`"group_name":"Infra"`, `"etiquette":"t"`, `"quand":"2026-11-16T10:00:00Z"`,
		`"nul":null`, `"membres":[]`, `"Alice":1`} {
		if !strings.Contains(got, attendu) {
			t.Errorf("%s ne contient pas %s", got, attendu)
		}
	}
	for _, absent := range []string{"Cache", `"c"`, "vide", "secret"} {
		if strings.Contains(got, absent) {
			t.Errorf("%s contient %s", got, absent)
		}
	}
}

func httpBody(s string) *bodyLecteur { return &bodyLecteur{strings.NewReader(s)} }

type bodyLecteur struct{ *strings.Reader }

func (bodyLecteur) Close() error { return nil }

// Le même cas que vaultaire_ctl (TestChaineCanoniqueFigee) : client et serveur
// doivent composer la même chaîne, octet pour octet.
func TestChaineCanoniqueFigee(t *testing.T) {
	got := string(ChaineCanoniqueREST("post", "/api/v1/users", "a=1", "alice", 1763300000, "n-1", []byte(`{"x":1}`)))
	attendu := "VAULTAIRE-REST-1\nPOST\n/api/v1/users\na=1\nalice\n1763300000\nn-1\n" +
		"5041bf1f713df204784353e82f6a4a535931cb64f1f4b4a5aeaffcb720918b22"
	if got != attendu {
		t.Fatalf("chaîne\n%q\nattendu\n%q", got, attendu)
	}
}
