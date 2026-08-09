package webserveur

import (
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"vaultaire/core/action"
)

// Tests de l'exécution groupée.
//
// Ce qui est éprouvé ici n'est pas « la boucle boucle » mais les cinq manières
// dont elle pourrait mentir sans que rien ne le montre :
//
//   - traiter douze fois la même cible en annonçant douze réussites ;
//   - accepter une cible venue de l'URL et non du formulaire ;
//   - taire un échec au milieu d'un lot ;
//   - écrire une partie du lot avant de refuser le reste ;
//   - faire basculer sur le chemin groupé un formulaire qui n'a rien demandé.
//
// Chacune produirait une interface qui a l'air de fonctionner.

// requetePost fabrique une requête POST prête à être lue par le pont.
//
// `chaineURL` sert à éprouver la séparation corps / URL : c'est le point où
// une confusion entre r.Form et r.PostForm se verrait.
func requetePost(t *testing.T, chaineURL string, corps url.Values) *http.Request {
	t.Helper()
	cible := "/admin/groups"
	if chaineURL != "" {
		cible += "?" + chaineURL
	}
	r := httptest.NewRequest(http.MethodPost, cible, strings.NewReader(corps.Encode()))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	if err := r.ParseForm(); err != nil {
		t.Fatalf("ParseForm : %v", err)
	}
	return r
}

// corpsGroupe monte un corps de formulaire déclarant `champ` comme porteur de
// cibles.
func corpsGroupe(nomAction, champ string, cibles ...string) url.Values {
	v := url.Values{}
	v.Set("action", nomAction)
	v.Set(ChampCibles, champ)
	for _, c := range cibles {
		v.Add(champ, c)
	}
	return v
}

// espion remplace l'exécuteur le temps d'un test et enregistre chaque appel.
//
// Rend la fonction de restauration : sans elle, un test laisserait l'exécuteur
// détourné pour tous les suivants, et les échecs apparaîtraient ailleurs que
// là où ils sont causés.
func espion(reponses map[string]error) (*[]action.Params, func()) {
	var vus []action.Params
	precedent := executerAction
	executerAction = func(nom string, a action.Appelant, p action.Params) (action.Resultat, error) {
		copie := action.Params{}
		for k, v := range p {
			copie[k] = v
		}
		vus = append(vus, copie)
		if reponses != nil {
			if err, ok := reponses[p.Get("username")]; ok {
				return action.Resultat{}, err
			}
		}
		return action.Resultat{Message: "fait"}, nil
	}
	return &vus, func() { executerAction = precedent }
}

// --- Le chemin d'origine reste intact ---------------------------------------

// TestSansDeclarationRienNeChange : un formulaire qui ne déclare pas de champ
// groupé doit suivre exactement le chemin d'avant.
//
// C'est la garantie de non-régression pour les formulaires existants, qui
// n'ont pas été touchés.
func TestSansDeclarationRienNeChange(t *testing.T) {
	corps := url.Values{}
	corps.Set("action", "add_user")
	corps.Set("username", "alice")

	r := requetePost(t, "group=paris", corps)
	if champ := ciblesDeclarees(r); champ != "" {
		t.Fatalf("champ groupé détecté (%q) sur un formulaire qui n'en déclare pas : "+
			"tous les formulaires existants basculeraient sur le chemin groupé", champ)
	}
}

// --- La cible ne peut venir que du corps -------------------------------------

// TestLesCiblesNeViennentQueDuCorps est le test de sécurité de ce fichier.
//
// `r.Form` fusionne le corps et la chaîne de requête. Lire les cibles dedans
// laisserait ajouter une cible en modifiant l'URL — donc agir sur une entité
// que le formulaire n'a jamais proposée, et que l'écran n'affichait pas.
func TestLesCiblesNeViennentQueDuCorps(t *testing.T) {
	corps := corpsGroupe("add_user", "username", "alice", "bob")
	r := requetePost(t, "group=paris&username=victime", corps)

	// La fusion a bien lieu : sans elle le test ne prouverait rien.
	if len(r.Form["username"]) != 3 {
		t.Fatalf("r.Form contient %d valeurs pour username, attendu 3 : "+
			"la fusion corps/URL n'a pas eu lieu, le test ne démontre plus rien",
			len(r.Form["username"]))
	}

	cibles := valeursDeCible(r, "username")
	for _, c := range cibles {
		if c == "victime" {
			t.Fatalf("une cible venue de l'URL a été retenue : %v", cibles)
		}
	}
	if len(cibles) != 2 || cibles[0] != "alice" || cibles[1] != "bob" {
		t.Fatalf("cibles = %v, attendu [alice bob]", cibles)
	}
}

// --- Nettoyage des cibles ----------------------------------------------------

func TestCiblesNettoyeesEtDedupliquees(t *testing.T) {
	corps := corpsGroupe("add_user", "username",
		" alice ", "bob", "", "alice", "   ", "bob")
	r := requetePost(t, "", corps)

	cibles := valeursDeCible(r, "username")
	attendu := []string{"alice", "bob"}
	if len(cibles) != len(attendu) {
		t.Fatalf("cibles = %v, attendu %v", cibles, attendu)
	}
	for i := range attendu {
		if cibles[i] != attendu[i] {
			t.Fatalf("cibles = %v, attendu %v (l'ordre d'envoi doit être conservé)",
				cibles, attendu)
		}
	}
}

// --- Le piège des alias ------------------------------------------------------

// TestLEcrasementPrecedeLesAlias.
//
// Si le champ groupé est une SOURCE d'alias — « target_user » → « username » —
// et que l'écrasement a lieu APRÈS la résolution, le nom canonique reste figé
// sur la première valeur du lot. Les douze exécutions visent alors le même
// compte, et le compte rendu annonce douze réussites.
//
// C'est la faute la plus facile à commettre ici, et la seule qui produise un
// mensonge complet plutôt qu'une erreur.
func TestLEcrasementPrecedeLesAlias(t *testing.T) {
	corps := corpsGroupe("delete_user", "target_user", "alice", "bob")
	r := requetePost(t, "", corps)

	p := parametresPourCible(r, nil, "target_user", "bob")
	if p.Get("username") != "bob" {
		t.Fatalf("username = %q, attendu bob : l'alias a été résolu avant "+
			"l'écrasement, toutes les cibles du lot viseraient la première",
			p.Get("username"))
	}
	if p.Get("target_user") != "bob" {
		t.Fatalf("target_user = %q, attendu bob", p.Get("target_user"))
	}
}

// TestLeChampDeTransportNeDevientPasUnParametre.
func TestLeChampDeTransportNeDevientPasUnParametre(t *testing.T) {
	corps := corpsGroupe("add_user", "username", "alice")
	r := requetePost(t, "", corps)

	p := parametresPourCible(r, nil, "username", "alice")
	if p.Presente(ChampCibles) {
		t.Fatalf("%s a été transmis à l'action comme paramètre métier", ChampCibles)
	}
}

// TestLeContexteDePageCompleteToujours : les paramètres tirés de l'URL par le
// handler doivent survivre au chemin groupé, sinon les actions recevraient une
// cible sans son groupe.
func TestLeContexteDePageCompleteToujours(t *testing.T) {
	corps := corpsGroupe("add_user", "username", "alice")
	r := requetePost(t, "", corps)

	p := parametresPourCible(r, action.Params{"group": "paris"}, "username", "alice")
	if p.Get("group") != "paris" {
		t.Fatalf("group = %q, attendu paris", p.Get("group"))
	}
}

// --- La boucle ---------------------------------------------------------------

// TestUneExecutionParCibleAvecSesPropresParametres.
func TestUneExecutionParCibleAvecSesPropresParametres(t *testing.T) {
	vus, restaurer := espion(nil)
	defer restaurer()

	corps := corpsGroupe("add_user", "username", "alice", "bob", "carol")
	corps.Set("target_group", "paris")
	r := requetePost(t, "group=paris", corps)

	res, err := executerParCible(r, "group.add_user", action.Appelant{}, nil, "username")
	if err != nil {
		t.Fatalf("erreur inattendue : %v", err)
	}
	if len(*vus) != 3 {
		t.Fatalf("%d exécution(s), attendu 3", len(*vus))
	}
	for i, attendu := range []string{"alice", "bob", "carol"} {
		if got := (*vus)[i].Get("username"); got != attendu {
			t.Fatalf("exécution %d : username = %q, attendu %q", i, got, attendu)
		}
		if got := (*vus)[i].Get("group"); got != "paris" {
			t.Fatalf("exécution %d : group = %q, attendu paris", i, got)
		}
	}
	if !strings.Contains(res.Message, "3 réussites") {
		t.Fatalf("message = %q, il doit annoncer le nombre de réussites", res.Message)
	}
}

// TestUnEchecAuMilieuEstNomme : le lot continue, et le compte rendu désigne la
// cible en échec avec son motif. Une réussite partielle silencieuse serait
// pire qu'un échec complet.
func TestUnEchecAuMilieuEstNomme(t *testing.T) {
	_, restaurer := espion(map[string]error{"bob": errors.New("bob est déjà membre")})
	defer restaurer()

	corps := corpsGroupe("add_user", "username", "alice", "bob", "carol")
	r := requetePost(t, "", corps)

	res, err := executerParCible(r, "group.add_user", action.Appelant{}, nil, "username")
	if err != nil {
		t.Fatalf("un succès partiel ne doit pas être une erreur : %v", err)
	}
	for _, attendu := range []string{"2 réussites", "bob", "déjà membre"} {
		if !strings.Contains(res.Message, attendu) {
			t.Fatalf("message = %q : %q manque", res.Message, attendu)
		}
	}
}

// TestToutEnEchecEstUneErreur : quand rien n'a abouti, l'appelant doit recevoir
// une erreur, pas un message de succès.
func TestToutEnEchecEstUneErreur(t *testing.T) {
	reponses := map[string]error{
		"alice": errors.New("refus a"),
		"bob":   errors.New("refus b"),
	}
	_, restaurer := espion(reponses)
	defer restaurer()

	corps := corpsGroupe("add_user", "username", "alice", "bob")
	r := requetePost(t, "", corps)

	_, err := executerParCible(r, "group.add_user", action.Appelant{}, nil, "username")
	if err == nil {
		t.Fatal("aucune cible n'a abouti et pourtant aucune erreur n'est rendue")
	}
	for _, attendu := range []string{"alice", "bob", "refus a", "refus b"} {
		if !strings.Contains(err.Error(), attendu) {
			t.Fatalf("erreur = %q : %q manque", err.Error(), attendu)
		}
	}
}

// TestUneSeuleCibleRendLErreurTelleQuelle.
//
// La reconnaissance de *ErrRefusee par MessageDActionPourAffichage doit
// survivre au passage par le chemin groupé. Sinon un formulaire converti au
// groupé perdrait le mot « refusée », que les administrateurs cherchent des
// yeux et que les scripts d'intégration reconnaissent.
func TestUneSeuleCibleRendLErreurTelleQuelle(t *testing.T) {
	sentinelle := &action.ErrRefusee{Action: "group.add_user", Cle: "write:add:user", Motif: "aucun droit sur lyon"}
	_, restaurer := espion(map[string]error{"alice": sentinelle})
	defer restaurer()

	corps := corpsGroupe("add_user", "username", "alice")
	r := requetePost(t, "", corps)

	_, err := executerParCible(r, "group.add_user", action.Appelant{}, nil, "username")
	var refus *action.ErrRefusee
	if !errors.As(err, &refus) {
		t.Fatalf("erreur = %v : *ErrRefusee n'est plus reconnaissable, "+
			"MessageDActionPourAffichage n'écrira plus « Permission refusée »", err)
	}
}

// --- Les refus, avant toute écriture -----------------------------------------

// TestAucuneCibleEstUnRefus : un <select multiple> dont rien n'est coché
// n'envoie aucun champ. L'action ne doit pas partir avec une cible vide.
func TestAucuneCibleEstUnRefus(t *testing.T) {
	vus, restaurer := espion(nil)
	defer restaurer()

	corps := corpsGroupe("add_user", "username")
	r := requetePost(t, "", corps)

	if _, err := executerParCible(r, "group.add_user", action.Appelant{}, nil, "username"); err == nil {
		t.Fatal("une soumission sans cible a été acceptée")
	}
	if len(*vus) != 0 {
		t.Fatalf("%d exécution(s) alors qu'aucune cible n'était désignée", len(*vus))
	}
}

// TestAuDelaDuPlafondRienNestExecute.
//
// Le refus doit précéder la première écriture. Refuser après en avoir écrit
// deux cents laisserait un état partiel qu'aucun message ne décrit.
func TestAuDelaDuPlafondRienNestExecute(t *testing.T) {
	vus, restaurer := espion(nil)
	defer restaurer()

	corps := corpsGroupe("add_user", "username")
	for i := 0; i <= MaxCiblesGroupees; i++ {
		corps.Add("username", fmt.Sprintf("compte%d", i))
	}
	r := requetePost(t, "", corps)

	if _, err := executerParCible(r, "group.add_user", action.Appelant{}, nil, "username"); err == nil {
		t.Fatalf("plus de %d cibles ont été acceptées", MaxCiblesGroupees)
	}
	if len(*vus) != 0 {
		t.Fatalf("%d exécution(s) avant le refus : état partiel non décrit", len(*vus))
	}
}

// TestChampDeTransportNonGroupable : boucler sur « action » n'a pas de sens et
// trahit un formulaire mal écrit. Refus explicite plutôt que comportement
// absurde.
func TestChampDeTransportNonGroupable(t *testing.T) {
	vus, restaurer := espion(nil)
	defer restaurer()

	for champ := range champsNonGroupables {
		corps := url.Values{}
		corps.Set("action", "add_user")
		corps.Set(ChampCibles, champ)
		corps.Add(champ, "a")
		corps.Add(champ, "b")
		r := requetePost(t, "", corps)

		if _, err := executerParCible(r, "group.add_user", action.Appelant{}, nil, champ); err == nil {
			t.Fatalf("le champ de transport %q a été accepté comme porteur de cibles", champ)
		}
	}
	if len(*vus) != 0 {
		t.Fatalf("%d exécution(s) sur un champ de transport", len(*vus))
	}
}

// --- Le compte rendu ---------------------------------------------------------

// TestLeCompteRenduNommeLesEchecs.
//
// Les réussites peuvent être abrégées : leur liste n'apprend rien de plus que
// leur nombre. Les échecs, non — c'est sur eux que l'administrateur doit agir,
// et un « et 3 autres » sans nom l'obligerait à tout revérifier.
func TestLeCompteRenduNommeLesEchecs(t *testing.T) {
	echecs := []resultatDeCible{
		{cible: "dave", err: errors.New("motif d")},
		{cible: "erin", err: errors.New("motif e")},
	}
	msg := compteRenduGroupe([]string{"alice", "bob"}, echecs)

	attendus := []string{"2 réussites", "alice", "bob", "2 échecs", "dave", "motif d", "erin", "motif e"}
	for _, attendu := range attendus {
		if !strings.Contains(msg, attendu) {
			t.Fatalf("compte rendu = %q : %q manque", msg, attendu)
		}
	}
}

// TestLeCompteRenduAbregeLesReussitesNombreuses.
func TestLeCompteRenduAbregeLesReussitesNombreuses(t *testing.T) {
	var beaucoup []string
	for i := 0; i < 40; i++ {
		beaucoup = append(beaucoup, fmt.Sprintf("compte%d", i))
	}
	msg := compteRenduGroupe(beaucoup, nil)
	if !strings.Contains(msg, "40 réussites") {
		t.Fatalf("compte rendu = %q : le nombre manque", msg)
	}
	if strings.Contains(msg, "compte39") {
		t.Fatalf("compte rendu = %q : quarante noms ont été énumérés", msg)
	}
}

// TestLeCompteRenduNestJamaisVide : un message vide s'afficherait comme une
// bannière blanche, et l'administrateur ne saurait pas si son geste a porté.
func TestLeCompteRenduNestJamaisVide(t *testing.T) {
	if msg := compteRenduGroupe([]string{"alice"}, nil); strings.TrimSpace(msg) == "" {
		t.Fatal("compte rendu vide pour une réussite")
	}
	echec := []resultatDeCible{{cible: "a", err: errors.New("x")}}
	if msg := compteRenduGroupe(nil, echec); strings.TrimSpace(msg) == "" {
		t.Fatal("compte rendu vide pour un échec")
	}
}
