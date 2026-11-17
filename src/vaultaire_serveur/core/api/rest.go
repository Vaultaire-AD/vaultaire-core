package api

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"regexp"
	"sort"
	"strconv"
	"strings"

	"vaultaire/core/action"
	"vaultaire/core/auth/ratelimit"
	"vaultaire/core/command"
	"vaultaire/core/logs"
	"vaultaire/core/permission"
)

// API REST — TO-DO 270.
//
// # Ce que c'est, et ce que ce n'est pas
//
// Une INTERFACE, pas une gestion de plus. Chaque route appelle une action du
// registre — exactement celle qu'appelle la commande `vlt` du même geste — par
// le même exécuteur : mêmes droits, même portée par domaine, même filtrage des
// listes, même journal d'audit, mêmes messages d'erreur. Ce fichier ne contient
// aucune règle métier et ne lit pas la base ; il traduit HTTP ↔ registre :
//
//   - méthode + chemin  → nom de l'action (table routesREST, ou route générique) ;
//   - chemin, requête, corps JSON → paramètres de l'action ;
//   - Resultat.Donnees → `data`, en JSON propre (rest_json.go) ;
//   - les erreurs typées du registre → un statut HTTP et un code stable.
//
// Trois portes :
//
//	/api/v1/<ressource>…        routes lisibles (users, groups, clients, permissions, gpos, domains)
//	/api/v1/actions/{action}    TOUTE action du registre, par son nom
//	/api/v1/command             une ligne de commande `vlt`, pour ce qui n'est pas encore au registre
//
// et deux lectures : GET /api/v1/actions (le catalogue), GET /api/v1/openapi.json
// (la description, sans authentification).
//
// L'authentification est celle de /api/command — la clé SSH du compte — voir
// rest_auth.go.

const prefixeREST = "/api/v1"

// Accès remplaçables par les tests : le routeur s'éprouve sans base.
var (
	executerActionREST   = action.Executer
	groupesDeREST        = permission.GetGroupIDsForUser
	executerCommandeREST = command.ExecuteCommand
	catalogueREST        = func() []action.Definition { return action.Catalogue.Definitions() }
)

// reponseREST est l'enveloppe de TOUTES les réponses JSON de l'API.
//
// `ok` dit le succès sans avoir à lire le statut ; `data` est toujours présent
// sur un succès (nul quand l'action ne rend pas de données) ; `error` seulement
// sur un échec.
type reponseREST struct {
	OK        bool        `json:"ok"`
	Action    string      `json:"action,omitempty"`
	Message   string      `json:"message,omitempty"`
	Data      any         `json:"data"`
	Error     *erreurREST `json:"error,omitempty"`
	RequestID string      `json:"request_id,omitempty"`
}

// erreurREST : `code` est STABLE (un client l'aiguille), `message` est pour un humain.
type erreurREST struct {
	Code    string            `json:"code"`
	Message string            `json:"message"`
	Key     string            `json:"key,omitempty"`    // droit refusé (forbidden)
	Replay  map[string]string `json:"replay,omitempty"` // paramètres à renvoyer (confirmation_required)
}

// Codes d'erreur. Documentés dans docs/Utilisation/API_REST.md.
const (
	codeNonAuthentifie      = "unauthenticated"
	codeRefuse              = "forbidden"
	codeRequeteInvalide     = "bad_request"
	codeIntrouvable         = "not_found"
	codeActionInconnue      = "unknown_action"
	codeConfirmationRequise = "confirmation_required"
	codeActionEchouee       = "action_failed"
	codeTropDeRequetes      = "too_many_requests"
	codeTropVolumineux      = "payload_too_large"
	codeMethodeRefusee      = "method_not_allowed"
)

// EnregistrerREST pose les routes de l'API REST sur le multiplexeur de l'API.
func EnregistrerREST(mux *http.ServeMux) {
	for _, rt := range routesREST {
		rt := rt
		mux.HandleFunc(rt.Methode+" "+prefixeREST+rt.Chemin, func(w http.ResponseWriter, r *http.Request) {
			servirAction(w, r, rt.Action, rt.Statut, false)
		})
	}
	mux.HandleFunc("GET "+prefixeREST+"/actions", servirCatalogue)
	mux.HandleFunc("GET "+prefixeREST+"/actions/{action}", func(w http.ResponseWriter, r *http.Request) {
		servirAction(w, r, r.PathValue("action"), 0, true)
	})
	mux.HandleFunc("POST "+prefixeREST+"/actions/{action}", func(w http.ResponseWriter, r *http.Request) {
		servirAction(w, r, r.PathValue("action"), 0, false)
	})
	mux.HandleFunc("POST "+prefixeREST+"/command", servirCommande)
	mux.HandleFunc("GET "+prefixeREST+"/openapi.json", servirOpenAPI)
	// Tout le reste sous /api/v1 : une réponse JSON, et non la page texte de
	// net/http — un client de l'API ne doit lire qu'un seul format.
	mux.HandleFunc(prefixeREST+"/", func(w http.ResponseWriter, r *http.Request) {
		ecrireErreur(w, r, http.StatusNotFound, "", &erreurREST{Code: codeIntrouvable,
			Message: fmt.Sprintf("aucune route %s %s — voir GET %s/openapi.json", r.Method, r.URL.Path, prefixeREST)})
	})
}

// RoutesActionsREST rend les actions nommées par les routes ressources, pour
// le contrôle de démarrage (une route qui nommerait une action absente
// échouerait au premier appel, pas à la compilation).
func RoutesActionsREST() []string {
	vus := map[string]bool{}
	var noms []string
	for _, rt := range routesREST {
		if !vus[rt.Action] {
			vus[rt.Action] = true
			noms = append(noms, rt.Action)
		}
	}
	return noms
}

// --- le tronc commun ---------------------------------------------------------

// preparer applique, dans l'ordre de /api/command, le débit, les échecs de la
// source, la borne du corps, la signature et la fraîcheur. Rend faux quand la
// réponse est déjà écrite.
func preparer(w http.ResponseWriter, r *http.Request) (identiteREST, []byte, bool) {
	source := ratelimit.SourceHTTP(r)

	if ok, reste := debitAPI.Prendre(source); !ok {
		refuserTropTotREST(w, r, reste)
		return identiteREST{}, nil, false
	}
	if ok, reste := ratelimit.Autorise("", source); !ok {
		refuserTropTotREST(w, r, reste)
		return identiteREST{}, nil, false
	}

	corps, err := io.ReadAll(http.MaxBytesReader(w, r.Body, tailleMaxCorps))
	if err != nil {
		var tropGros *http.MaxBytesError
		if errors.As(err, &tropGros) {
			ecrireErreur(w, r, http.StatusRequestEntityTooLarge, "", &erreurREST{Code: codeTropVolumineux,
				Message: fmt.Sprintf("requête trop volumineuse : %d octets au plus", tailleMaxCorps)})
			return identiteREST{}, nil, false
		}
		ecrireErreur(w, r, http.StatusBadRequest, "", &erreurREST{Code: codeRequeteInvalide, Message: "corps illisible"})
		return identiteREST{}, nil, false
	}

	id, nonce, horodatage, err := authentifierREST(r, corps)
	if err != nil {
		ratelimit.Echec("", source)
		journaliserREST(r, id, "", http.StatusUnauthorized, err)
		ecrireErreur(w, r, http.StatusUnauthorized, "", &erreurREST{Code: codeNonAuthentifie, Message: messageRefus})
		return identiteREST{}, nil, false
	}
	ratelimit.Reussite("", source)

	if err := verifierFraicheur(id.Username, nonce, horodatage); err != nil {
		journaliserREST(r, id, "", http.StatusUnauthorized, err)
		ecrireErreur(w, r, http.StatusUnauthorized, "", &erreurREST{Code: codeNonAuthentifie,
			Message: "requête rejetée : " + err.Error()})
		return identiteREST{}, nil, false
	}
	return id, corps, true
}

// servirAction exécute une action du registre.
//
// lectureSeule : la route générique en GET n'accepte que les LECTURES. Une
// écriture déclenchée par un GET serait rejouée par le premier robot, cache ou
// prélecteur venu ; elle se fait en POST.
func servirAction(w http.ResponseWriter, r *http.Request, nom string, statut int, lectureSeule bool) {
	id, corps, ok := preparer(w, r)
	if !ok {
		return
	}

	if lectureSeule {
		if d, connue := definitionREST(nom); connue && !estLecture(d) {
			ecrireErreur(w, r, http.StatusMethodNotAllowed, nom, &erreurREST{Code: codeMethodeRefusee,
				Message: fmt.Sprintf("%s modifie l'état : POST %s/actions/%s", nom, prefixeREST, nom)})
			return
		}
	}

	params, err := parametresREST(r, corps)
	if err != nil {
		journaliserREST(r, id, nom, http.StatusBadRequest, err)
		ecrireErreur(w, r, http.StatusBadRequest, nom, &erreurREST{Code: codeRequeteInvalide, Message: err.Error()})
		return
	}

	groupIDs, err := groupesDeREST(id.Username)
	if err != nil {
		journaliserREST(r, id, nom, http.StatusForbidden, err)
		ecrireErreur(w, r, http.StatusForbidden, nom, &erreurREST{Code: codeRefuse, Message: "groupes de l'appelant illisibles : " + err.Error()})
		return
	}

	res, err := executerActionREST(nom, action.Appelant{Username: id.Username, GroupIDs: groupIDs}, params)
	if err != nil {
		code, e := classerErreur(err)
		journaliserREST(r, id, nom, code, err)
		ecrireErreur(w, r, code, nom, e)
		return
	}

	if statut == 0 {
		statut = http.StatusOK
	}
	journaliserREST(r, id, nom, statut, nil)
	ecrireJSON(w, statut, reponseREST{
		OK: true, Action: nom, Message: res.Message, Data: versJSON(res.Donnees),
		RequestID: r.Header.Get("X-Request-ID"),
	})
}

// classerErreur traduit une erreur du registre en statut et code stables.
func classerErreur(err error) (int, *erreurREST) {
	var refus *action.ErrRefusee
	if errors.As(err, &refus) {
		return http.StatusForbidden, &erreurREST{Code: codeRefuse, Message: "permission refusée : " + refus.Motif, Key: refus.Cle}
	}
	var inconnue *action.ErrInconnue
	if errors.As(err, &inconnue) {
		return http.StatusNotFound, &erreurREST{Code: codeActionInconnue,
			Message: fmt.Sprintf("action %q inconnue — voir GET %s/actions", inconnue.Nom, prefixeREST)}
	}
	var attente *action.ErrConfirmationRequise
	if errors.As(err, &attente) {
		return http.StatusConflict, &erreurREST{Code: codeConfirmationRequise, Message: attente.Motif,
			Replay: map[string]string(attente.Rejouer)}
	}
	// Les actions rendent des erreurs en texte. « introuvable » est la forme
	// constante de leurs absences (compte, groupe, machine…) : c'est le seul
	// cas qui mérite un statut à part, parce qu'un client le traite à part.
	msg := err.Error()
	if strings.Contains(strings.ToLower(msg), "introuvable") {
		return http.StatusNotFound, &erreurREST{Code: codeIntrouvable, Message: msg}
	}
	return http.StatusUnprocessableEntity, &erreurREST{Code: codeActionEchouee, Message: msg}
}

// --- paramètres --------------------------------------------------------------

var motifParametre = regexp.MustCompile(`\{([a-zA-Z_][a-zA-Z0-9_]*)\}`)

// parametresREST assemble les paramètres de l'action : requête, puis corps
// JSON, puis chemin.
//
// Le CHEMIN désigne la cible : un corps qui donnerait une autre valeur au même
// paramètre est refusé, et non écrasé en silence — sans quoi
// `DELETE /users/alice` avec `{"username": "bob"}` dépendrait d'une règle
// d'ordre que personne ne lit.
func parametresREST(r *http.Request, corps []byte) (action.Params, error) {
	p := action.Params{}
	for nom, valeurs := range r.URL.Query() {
		if len(valeurs) > 0 {
			p[nom] = valeurs[0]
		}
	}

	if len(bytes.TrimSpace(corps)) > 0 {
		dec := json.NewDecoder(bytes.NewReader(corps))
		dec.UseNumber()
		var brut map[string]any
		if err := dec.Decode(&brut); err != nil {
			return nil, fmt.Errorf("corps JSON attendu : un objet {\"paramètre\": valeur} (%v)", err)
		}
		for nom, v := range brut {
			s, present, err := enChaine(v)
			if err != nil {
				return nil, fmt.Errorf("paramètre %q : %v", nom, err)
			}
			if present {
				p[nom] = s
			}
		}
	}

	for _, m := range motifParametre.FindAllStringSubmatch(r.Pattern, -1) {
		nom := m[1]
		if nom == "action" && strings.Contains(r.Pattern, "/actions/{action}") {
			continue // le nom de l'action, pas un de ses paramètres
		}
		v := r.PathValue(nom)
		if deja, existe := p[nom]; existe && deja != v {
			return nil, fmt.Errorf("paramètre %q : %q dans le chemin, %q dans le corps — le chemin désigne la cible, retirez-le du corps", nom, v, deja)
		}
		p[nom] = v
	}
	return p, nil
}

// enChaine ramène une valeur JSON à la chaîne qu'attend le registre — celle
// qu'aurait tapée la ligne de commande. Les booléens deviennent « true » /
// « false », que les actions acceptent comme « oui » / « non ». Une liste ou un
// objet est passé en JSON compact (les modules de GPO en reçoivent).
func enChaine(v any) (string, bool, error) {
	switch x := v.(type) {
	case nil:
		return "", false, nil
	case string:
		return x, true, nil
	case json.Number:
		return x.String(), true, nil
	case bool:
		return strconv.FormatBool(x), true, nil
	default:
		b, err := json.Marshal(x)
		if err != nil {
			return "", false, err
		}
		return string(b), true, nil
	}
}

// --- catalogue, commande ----------------------------------------------------

type entreeCatalogue struct {
	Name       string `json:"name"`
	Summary    string `json:"summary"`
	Key        string `json:"key,omitempty"`
	Read       bool   `json:"read"`
	Global     bool   `json:"global"`
	Superadmin bool   `json:"superadmin"`
	Method     string `json:"method"`
	Path       string `json:"path"`
}

// servirCatalogue liste les actions du registre et la façon de les appeler.
//
// Authentifié comme le reste : le catalogue ne porte aucun secret, mais il
// décrit la surface d'administration, et rien ne justifie de la montrer à qui
// n'a pas de compte.
func servirCatalogue(w http.ResponseWriter, r *http.Request) {
	id, _, ok := preparer(w, r)
	if !ok {
		return
	}
	var liste []entreeCatalogue
	for _, d := range catalogueREST() {
		methode := http.MethodPost
		if estLecture(d) {
			methode = http.MethodGet
		}
		liste = append(liste, entreeCatalogue{
			Name: d.Nom, Summary: d.Resume, Key: d.CleRBAC, Read: estLecture(d),
			Global: d.PorteeEstGlobale(), Superadmin: d.ExigeSuperadmin,
			Method: methode, Path: prefixeREST + "/actions/" + d.Nom,
		})
	}
	sort.Slice(liste, func(i, j int) bool { return liste[i].Name < liste[j].Name })
	journaliserREST(r, id, "", http.StatusOK, nil)
	ecrireJSON(w, http.StatusOK, reponseREST{OK: true, Message: fmt.Sprintf("%d action(s).", len(liste)),
		Data: liste, RequestID: r.Header.Get("X-Request-ID")})
}

// servirCommande exécute une ligne de commande `vlt` — la porte de ce qui
// n'est pas encore au registre (status, eyes, logs, cluster…).
//
// La sortie est le TEXTE de la commande, dans `data.output` : rien n'est
// inventé pour lui donner une structure qu'elle n'a pas. Une action qui gagne
// une route ressource ou générique gagne du même coup un JSON structuré.
func servirCommande(w http.ResponseWriter, r *http.Request) {
	id, corps, ok := preparer(w, r)
	if !ok {
		return
	}
	var req struct {
		Command string `json:"command"`
	}
	if err := json.Unmarshal(corps, &req); err != nil || strings.TrimSpace(req.Command) == "" {
		ecrireErreur(w, r, http.StatusBadRequest, "", &erreurREST{Code: codeRequeteInvalide,
			Message: `corps attendu : {"command": "get -u"}`})
		return
	}
	sortie := executerCommandeREST(req.Command, id.Username)
	journaliserREST(r, id, "command", http.StatusOK, nil)
	ecrireJSON(w, http.StatusOK, reponseREST{OK: true, Action: "command",
		Data: map[string]string{"command": req.Command, "output": sortie}, RequestID: r.Header.Get("X-Request-ID")})
}

// --- utilitaires -------------------------------------------------------------

func definitionREST(nom string) (action.Definition, bool) {
	for _, d := range catalogueREST() {
		if d.Nom == nom {
			return d, true
		}
	}
	return action.Definition{}, false
}

// estLecture : la clé dit la nature, comme pour le journal d'audit du registre.
func estLecture(d action.Definition) bool {
	return strings.HasPrefix(d.CleRBAC, "read:")
}

func ecrireJSON(w http.ResponseWriter, statut int, rep reponseREST) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(statut)
	enc := json.NewEncoder(w)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(rep); err != nil {
		logs.Write_LogCode("ERROR", logs.CodeAPIDecode, "api rest: écriture JSON échouée : "+err.Error())
	}
}

func ecrireErreur(w http.ResponseWriter, r *http.Request, statut int, nom string, e *erreurREST) {
	ecrireJSON(w, statut, reponseREST{OK: false, Action: nom, Error: e, RequestID: r.Header.Get("X-Request-ID")})
}

func refuserTropTotREST(w http.ResponseWriter, r *http.Request, reste interface{ Seconds() float64 }) {
	secondes := int(reste.Seconds() + 0.999)
	if secondes < 1 {
		secondes = 1
	}
	w.Header().Set("Retry-After", strconv.Itoa(secondes))
	ecrireErreur(w, r, http.StatusTooManyRequests, "", &erreurREST{Code: codeTropDeRequetes,
		Message: fmt.Sprintf("trop de requêtes : réessayer dans %d s", secondes)})
}

// journaliserREST : une ligne par appel, jamais le corps (il porte des mots de
// passe). Les ÉCRITURES ont en plus leur ligne d'audit, posée par le registre.
func journaliserREST(r *http.Request, id identiteREST, nom string, statut int, err error) {
	compte := id.Username
	if compte == "" {
		compte = "<inconnu>"
	}
	niveau := "INFO"
	msg := fmt.Sprintf("api rest: %s %s user=%s action=%s status=%d", r.Method, r.URL.Path, compte, nom, statut)
	if err != nil {
		niveau = "WARNING"
		msg += " erreur=" + err.Error()
	}
	meta := logs.WithMeta(r.Header.Get("X-Request-ID"), strconv.Itoa(id.UserID))
	if meta == nil && id.UserID > 0 {
		meta = logs.UserMeta(id.UserID)
	}
	logs.Write_LogCodeMeta(niveau, logs.CodeNone, msg, meta)
}
