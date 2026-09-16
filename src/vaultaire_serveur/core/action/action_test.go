package action

import (
	"errors"
	"strings"
	"testing"
)

// Ces tests portent sur une seule question : peut-on faire exécuter une action
// sans détenir le droit correspondant ?
//
// Le module web répondait oui, par une voie que personne n'avait choisie : une
// action absente de la table `action → clé RBAC` laissait la clé vide, et le
// contrôle était sauté. Rien ne le signalait.
//
// D'où la forme retenue ici. On ne vérifie pas que le contrôle fonctionne quand
// il est demandé — c'est facile et ça ne prouve rien. On vérifie qu'il n'existe
// AUCUN chemin qui l'évite.

// --- outils de test ---------------------------------------------------------

type droitsFixes struct {
	autorise bool
	motif    string

	// Trace de ce qui a été demandé : c'est elle qui permet de distinguer
	// « autorisé » de « jamais vérifié ». Les deux produisent une exécution ;
	// seul l'enregistrement les sépare.
	appels []appelDroit

	// Trace séparée des appels « un domaine suffit », pour vérifier qu'une
	// action interroge bien la sémantique qu'elle déclare.
	appelsUnDomaine []appelDroit

	// Trace des appels « le droit quelque part suffit », troisième sémantique.
	appelsPartout []appelDroit
}

type appelDroit struct {
	cle      string
	domaines []string
}

func (d *droitsFixes) Autorise(_ []int, cle string, domaines []string) (bool, string) {
	d.appels = append(d.appels, appelDroit{cle: cle, domaines: domaines})
	return d.autorise, d.motif
}

// AutoriseSurUnDomaine : même réponse fixe, mais tracée à part.
//
// La distinction compte pour les tests : une action de lecture doit passer par
// CETTE méthode, une écriture par l'autre. Répondre pareil sans les séparer
// laisserait passer une action qui interroge la mauvaise — et le contrôle
// serait alors plus laxiste, ou plus strict, que déclaré.
func (d *droitsFixes) AutoriseSurUnDomaine(_ []int, cle string, domaines []string) (bool, string) {
	d.appelsUnDomaine = append(d.appelsUnDomaine, appelDroit{cle: cle, domaines: domaines})
	return d.autorise, d.motif
}

// AutorisePartout : troisième sémantique, tracée à part elle aussi.
//
// Aucune liste de domaines n'est reçue, et c'est précisément ce que les tests
// doivent pouvoir constater : une action de liste qui passerait encore une
// liste de domaines retomberait dans le défaut d'origine.
func (d *droitsFixes) AutorisePartout(_ []int, cle string) (bool, string) {
	d.appelsPartout = append(d.appelsPartout, appelDroit{cle: cle})
	return d.autorise, d.motif
}

// TestUnDomaineSuffitChoisitLaBonneVerification.
//
// Le champ UnDomaineSuffit ne sert à rien s'il n'oriente pas réellement le
// contrôle. Un exécuteur qui appellerait toujours Autorise durcirait les
// lectures ; un qui appellerait toujours AutoriseSurUnDomaine relâcherait les
// écritures. Aucune des deux erreurs ne se voit à la lecture du code appelant
// — d'où ce test, qui observe QUELLE méthode a été interrogée.
func TestUnDomaineSuffitChoisitLaBonneVerification(t *testing.T) {
	rien := func(Appelant, Params) (Resultat, error) { return Resultat{}, nil }

	cas := []struct {
		nom             string
		unDomaineSuffit bool
	}{
		{"ecriture.test", false},
		{"lecture.test", true},
	}

	for _, c := range cas {
		r := NouveauRegistre()
		if err := r.Enregistrer(Definition{
			Nom:             c.nom,
			CleRBAC:         "read:get:user",
			Portee:          PorteeGlobale,
			UnDomaineSuffit: c.unDomaineSuffit,
			Resume:          "essai",
			Executer:        rien,
		}); err != nil {
			t.Fatalf("%s : %v", c.nom, err)
		}

		d := &droitsFixes{autorise: true}
		ex := &Executeur{Registre: r, Droits: d}
		if _, err := ex.Controler(c.nom, Appelant{Username: "x"}, Params{}); err != nil {
			t.Fatalf("%s : %v", c.nom, err)
		}

		strictes, souples := len(d.appels), len(d.appelsUnDomaine)
		if c.unDomaineSuffit {
			if souples != 1 || strictes != 0 {
				t.Errorf("%s : lecture contrôlée par la voie stricte (%d strict, %d souple)",
					c.nom, strictes, souples)
			}
		} else {
			if strictes != 1 || souples != 0 {
				t.Errorf("%s : écriture contrôlée par la voie souple (%d strict, %d souple)",
					c.nom, strictes, souples)
			}
		}
	}
}

type journalMemoire struct {
	refus      []string
	executions []string
	echecs     []string
}

func (j *journalMemoire) Refus(m string)     { j.refus = append(j.refus, m) }
func (j *journalMemoire) Execution(m string) { j.executions = append(j.executions, m) }
func (j *journalMemoire) Echec(m string)     { j.echecs = append(j.echecs, m) }

func actionValide(nom string, execute *bool) Definition {
	return Definition{
		Nom:     nom,
		CleRBAC: "write:create:user",
		Portee:  PorteeGlobale,
		Resume:  "action de test",
		Executer: func(Appelant, Params) (Resultat, error) {
			if execute != nil {
				*execute = true
			}
			return Resultat{Message: "fait"}, nil
		},
	}
}

// --- fail-closed à l'enregistrement -----------------------------------------

// TestActionSansCleRBACRefusee est le test central.
//
// Sur l'ancien modèle, une action sans clé s'exécutait sans contrôle. Ici elle
// n'existe pas : le registre la refuse, et le programme s'arrête au démarrage
// plutôt que de servir une action non protégée.
func TestActionSansCleRBACRefusee(t *testing.T) {
	r := NouveauRegistre()

	d := actionValide("user.create", nil)
	d.CleRBAC = ""

	err := r.Enregistrer(d)
	if err == nil {
		t.Fatal("une action sans clé RBAC est acceptée : elle s'exécuterait sans contrôle de droits")
	}
	if !strings.Contains(err.Error(), "clé RBAC") {
		t.Errorf("le message ne nomme pas la cause : %v", err)
	}
	if _, existe := r.Definition("user.create"); existe {
		t.Fatal("l'action est présente dans le registre malgré le refus")
	}
}

// TestActionAvecCleVideDEspaces : « " " » n'est pas une clé.
//
// Sans TrimSpace, une clé faite d'espaces passerait le contrôle « != "" » et
// serait ensuite comparée à des permissions réelles — qu'elle ne pourrait jamais
// égaler. L'action serait donc enregistrée et systématiquement refusée : une
// panne, là où l'on croyait poser une protection.
func TestActionAvecCleVideDEspaces(t *testing.T) {
	r := NouveauRegistre()
	d := actionValide("user.create", nil)
	d.CleRBAC = "   "

	if err := r.Enregistrer(d); err == nil {
		t.Fatal("une clé faite d'espaces est acceptée")
	}
}

// TestActionSansPorteeRefusee.
//
// Une portée absente rendrait une liste de domaines vide. Le contrôle porterait
// alors sur rien — techniquement exécuté, effectivement inopérant. C'est la
// forme la plus trompeuse du défaut : le code du contrôle est bien là.
func TestActionSansPorteeRefusee(t *testing.T) {
	r := NouveauRegistre()
	d := actionValide("user.create", nil)
	d.Portee = nil

	err := r.Enregistrer(d)
	if err == nil {
		t.Fatal("une action sans portée est acceptée : son contrôle de droits ne porterait sur aucun domaine")
	}
	if !strings.Contains(err.Error(), "portée") {
		t.Errorf("le message ne nomme pas la cause : %v", err)
	}
}

func TestActionSansExecuterOuSansNomRefusee(t *testing.T) {
	r := NouveauRegistre()

	sansNom := actionValide("", nil)
	if err := r.Enregistrer(sansNom); err == nil {
		t.Error("action sans nom acceptée")
	}

	sansCorps := actionValide("user.create", nil)
	sansCorps.Executer = nil
	if err := r.Enregistrer(sansCorps); err == nil {
		t.Error("action sans fonction d'exécution acceptée")
	}
}

// TestDoubleEnregistrementRefuse.
//
// Deux définitions du même nom : l'une écraserait l'autre selon l'ordre des
// fichiers. Une action pourrait alors changer de comportement — ou de clé
// RBAC — sur un simple renommage, sans qu'aucune ligne de code n'ait bougé.
func TestDoubleEnregistrementRefuse(t *testing.T) {
	r := NouveauRegistre()
	if err := r.Enregistrer(actionValide("user.create", nil)); err != nil {
		t.Fatalf("premier enregistrement refusé : %v", err)
	}
	if err := r.Enregistrer(actionValide("user.create", nil)); err == nil {
		t.Fatal("second enregistrement du même nom accepté : la définition retenue dépendrait de l'ordre des fichiers")
	}
}

// --- fail-closed à l'exécution ----------------------------------------------

// TestActionInconnueRefusee : rien ne s'exécute par défaut.
func TestActionInconnueRefusee(t *testing.T) {
	e := &Executeur{
		Registre: NouveauRegistre(),
		Droits:   &droitsFixes{autorise: true},
	}

	_, err := e.Executer("user.create", Appelant{Username: "alice"}, Params{})
	if err == nil {
		t.Fatal("une action absente du registre s'exécute")
	}
	var inconnue *ErrInconnue
	if !errors.As(err, &inconnue) {
		t.Fatalf("erreur de type %T, attendu *ErrInconnue", err)
	}
}

// TestDroitVerifieAvantExecution est LE test de non-régression du fail-open.
//
// Il ne se contente pas de constater que l'action n'a pas tourné : il vérifie
// que le vérificateur a bien été INTERROGÉ, avec la bonne clé.
//
// La distinction est celle qui manquait. Une action refusée pour une autre
// raison — paramètre absent, erreur de base — produirait le même résultat
// visible qu'un refus de droit, et un test qui ne regarderait que l'issue
// passerait sur un code qui ne vérifie rien.
func TestDroitVerifieAvantExecution(t *testing.T) {
	var aExecute bool
	r := NouveauRegistre()
	if err := r.Enregistrer(actionValide("user.create", &aExecute)); err != nil {
		t.Fatalf("enregistrement : %v", err)
	}

	droits := &droitsFixes{autorise: false, motif: "droit absent"}
	journal := &journalMemoire{}
	e := &Executeur{Registre: r, Droits: droits, Journal: journal}

	_, err := e.Executer("user.create", Appelant{Username: "alice", GroupIDs: []int{1}}, Params{})

	if aExecute {
		t.Fatal("l'action a été exécutée malgré le refus de droit")
	}
	if len(droits.appels) != 1 {
		t.Fatalf("le vérificateur a été appelé %d fois, attendu 1 — "+
			"le contrôle est contourné", len(droits.appels))
	}
	if droits.appels[0].cle != "write:create:user" {
		t.Fatalf("droit vérifié : %q, attendu %q", droits.appels[0].cle, "write:create:user")
	}
	var refus *ErrRefusee
	if !errors.As(err, &refus) {
		t.Fatalf("erreur de type %T, attendu *ErrRefusee", err)
	}
	if len(journal.refus) != 1 {
		t.Fatal("le refus n'a pas été journalisé : une tentative n'aurait laissé aucune trace")
	}
}

// TestActionAutoriseeSExecute : le contrôle ne doit pas tout refuser.
func TestActionAutoriseeSExecute(t *testing.T) {
	var aExecute bool
	r := NouveauRegistre()
	if err := r.Enregistrer(actionValide("user.create", &aExecute)); err != nil {
		t.Fatalf("enregistrement : %v", err)
	}

	e := &Executeur{Registre: r, Droits: &droitsFixes{autorise: true}, Journal: &journalMemoire{}}
	res, err := e.Executer("user.create", Appelant{Username: "alice"}, Params{})
	if err != nil {
		t.Fatalf("action autorisée refusée : %v", err)
	}
	if !aExecute {
		t.Fatal("action autorisée non exécutée")
	}
	if res.Message == "" {
		t.Error("résultat sans message : l'appelant n'aurait rien à afficher")
	}
}

// TestExecuteurSansVerificateurRefuse.
//
// Un exécuteur mal câblé ne doit pas laisser passer les actions. C'est la
// variante « oubli de branchement » du fail-open : le registre serait en place,
// les clés déclarées, et rien ne serait vérifié.
func TestExecuteurSansVerificateurRefuse(t *testing.T) {
	var aExecute bool
	r := NouveauRegistre()
	if err := r.Enregistrer(actionValide("user.create", &aExecute)); err != nil {
		t.Fatalf("enregistrement : %v", err)
	}

	e := &Executeur{Registre: r} // Droits nil
	if _, err := e.Executer("user.create", Appelant{}, Params{}); err == nil {
		t.Fatal("exécution acceptée sans vérificateur de droits")
	}
	if aExecute {
		t.Fatal("l'action a tourné alors qu'aucun contrôle n'était possible")
	}
}

// TestPorteeTransmiseAuVerificateur.
//
// La portée décide de l'étendue du droit exigé. Si elle n'était pas transmise,
// un délégué d'un seul domaine pourrait agir sur une entité d'un autre — le
// contrôle aurait lieu, mais sur le mauvais périmètre.
func TestPorteeTransmiseAuVerificateur(t *testing.T) {
	r := NouveauRegistre()
	d := actionValide("user.update", nil)
	d.Portee = func(p Params) ([]string, error) {
		return []string{"domaine-de-" + p.Get("username")}, nil
	}
	if err := r.Enregistrer(d); err != nil {
		t.Fatalf("enregistrement : %v", err)
	}

	droits := &droitsFixes{autorise: true}
	e := &Executeur{Registre: r, Droits: droits}
	if _, err := e.Executer("user.update", Appelant{}, Params{"username": "alice"}); err != nil {
		t.Fatalf("exécution : %v", err)
	}

	if len(droits.appels) != 1 {
		t.Fatalf("%d appels au vérificateur, attendu 1", len(droits.appels))
	}
	got := droits.appels[0].domaines
	if len(got) != 1 || got[0] != "domaine-de-alice" {
		t.Fatalf("domaines transmis %v, attendu [domaine-de-alice] — "+
			"le droit serait exigé sur le mauvais périmètre", got)
	}
}

// TestPorteeEnErreurEmpecheLExecution.
//
// Si la portée ne peut être déterminée — entité introuvable, base injoignable —
// on ne sait pas sur quoi vérifier le droit. Exécuter quand même reviendrait à
// traiter l'ignorance comme une autorisation.
func TestPorteeEnErreurEmpecheLExecution(t *testing.T) {
	var aExecute bool
	r := NouveauRegistre()
	d := actionValide("user.update", &aExecute)
	d.Portee = func(Params) ([]string, error) { return nil, errors.New("base injoignable") }
	if err := r.Enregistrer(d); err != nil {
		t.Fatalf("enregistrement : %v", err)
	}

	e := &Executeur{Registre: r, Droits: &droitsFixes{autorise: true}}
	if _, err := e.Executer("user.update", Appelant{}, Params{}); err == nil {
		t.Fatal("exécution acceptée alors que la portée est indéterminable")
	}
	if aExecute {
		t.Fatal("l'action a tourné sans que son périmètre de droits soit connu")
	}
}

// TestToutesLesActionsDeclarentUneCle balaie un registre garni.
//
// Ce test tourne sur le registre réel une fois les actions portées : il
// constitue l'inventaire des droits et échoue si l'une d'elles y échappe.
// Ici, sur un registre construit à la main, il vérifie surtout que la
// vérification elle-même est correcte.
func TestToutesLesActionsDeclarentUneCle(t *testing.T) {
	r := NouveauRegistre()
	for _, nom := range []string{"user.create", "user.delete", "group.add_user"} {
		if err := r.Enregistrer(actionValide(nom, nil)); err != nil {
			t.Fatalf("enregistrement de %s : %v", nom, err)
		}
	}

	defs := r.Definitions()
	if len(defs) != 3 {
		t.Fatalf("%d actions, attendu 3", len(defs))
	}
	for _, d := range defs {
		if strings.TrimSpace(d.CleRBAC) == "" {
			t.Errorf("action %q sans clé RBAC dans le registre", d.Nom)
		}
		if d.Portee == nil {
			t.Errorf("action %q sans portée dans le registre", d.Nom)
		}
	}
	// Tri : l'inventaire doit être stable d'une exécution à l'autre, sans quoi
	// il serait illisible et impossible à comparer entre deux versions.
	if defs[0].Nom != "group.add_user" {
		t.Errorf("inventaire non trié : %q en tête", defs[0].Nom)
	}
}

// --- Params -----------------------------------------------------------------

func TestParamsGetNettoieLesBordures(t *testing.T) {
	p := Params{"username": "  alice  ", "password": "  secret  "}

	if got := p.Get("username"); got != "alice" {
		t.Fatalf("Get rend %q : un nom suivi d'un espace créerait un compte distinct, "+
			"visuellement identique au premier", got)
	}
	// Le mot de passe échappe au nettoyage : le rogner empêcherait l'utilisateur
	// de se connecter avec ce qu'il a réellement saisi.
	if got := p.Brut("password"); got != "  secret  " {
		t.Fatalf("Brut rend %q, attendu la valeur intacte", got)
	}
}

func TestParamsPresenteDistingueAbsentEtVide(t *testing.T) {
	p := Params{"prenom": ""}

	if !p.Presente("prenom") {
		t.Error("un paramètre présent mais vide est vu comme absent : " +
			"impossible de distinguer « effacer » de « ne pas toucher »")
	}
	if p.Presente("nom") {
		t.Error("un paramètre jamais fourni est vu comme présent")
	}
}
