package testrunner

import (
	"errors"
	"fmt"
	"sort"
	"strings"

	"vaultaire/core/action"
	dbgpo "vaultaire/core/database/db_gpo"
	"vaultaire/core/gpo"
	"vaultaire/core/storage"
)

// Tests du contrôle d'accès du registre d'actions.
//
// # Ce qu'ils couvrent, et pourquoi ici
//
// Le registre est le seul endroit où se décide qui a le droit de faire quoi :
// la ligne de commande et l'interface web y passent toutes les deux. Un défaut
// à cet endroit n'ouvre pas une porte, il les ouvre toutes.
//
// Ces tests ne touchent PAS la base. Les vérificateurs de droits, le contrôle
// d'appartenance au groupe protégé et la résolution des domaines sont
// remplacés par des doublures : le test pose lui-même « cet appelant détient
// write:create:user sur paris », et observe ce que le registre décide. Ils
// tournent donc toujours, y compris quand la base ne répond pas — c'est-à-dire
// aussi les jours où l'on a le plus besoin de savoir si le contrôle tient.
//
// Ce qu'ils NE couvrent pas, et qu'il faut savoir : que
// permission.CheckPermissionsAllDomains réponde juste. Ils vérifient que le
// registre POSE la bonne question et respecte la réponse, pas que la base y
// réponde correctement.

// --- doublures ---------------------------------------------------------------

// droitsFictifs répond d'après une table posée par le test.
//
// La clé est « cle|domaine ». Le droit est exigé sur TOUS les domaines de la
// portée : la doublure refuse dès qu'un seul manque, ce qui reproduit
// CheckPermissionsAllDomains — et non CheckPermissionsMultipleDomains, dont la
// tolérance est précisément ce que le registre a écarté.
type droitsFictifs struct {
	accordes map[string]bool
}

func (d droitsFictifs) Autorise(_ []int, cle string, domaines []string) (bool, string) {
	if len(domaines) == 0 {
		// Une portée vide autoriserait tout le monde : il n'y aurait rien à
		// vérifier. Le registre est censé ne jamais en produire (voir
		// domainesOuGlobal) ; si cela arrive, c'est un refus et un signal.
		return false, "portée vide"
	}
	for _, dom := range domaines {
		if !d.accordes[cle+"|"+dom] {
			return false, fmt.Sprintf("droit %s manquant sur %s", cle, dom)
		}
	}
	return true, ""
}

// AutoriseSurUnDomaine reproduit CheckPermissionsMultipleDomains.
//
// Employée par les actions qui déclarent UnDomaineSuffit — les lectures. La
// doublure doit répondre aux DEUX questions, faute de quoi elle n'implémente
// pas l'interface : c'est ce qui empêche d'oublier d'éprouver l'une des deux
// sémantiques.
func (d droitsFictifs) AutoriseSurUnDomaine(_ []int, cle string, domaines []string) (bool, string) {
	if len(domaines) == 0 {
		return false, "portée vide"
	}
	for _, dom := range domaines {
		if d.accordes[cle+"|"+dom] {
			return true, ""
		}
	}
	return false, fmt.Sprintf("droit %s sur aucun de %v", cle, domaines)
}

// AutorisePartout reproduit permission.HasActionAnywhere.
//
// Ne reçoit AUCUN domaine, et c'est le point : elle répond « ce droit est-il
// accordé quelque part ? ». La doublure balaie donc les droits accordés à la
// recherche de la clé, quel que soit le domaine associé.
//
// C'est cette sémantique qui manquait au registre. Les listes déclaraient
// PorteeGlobale — donc la liste `["*"]` — avec « un seul domaine suffit » : le
// seul candidat étant `*`, elles exigeaient le droit global et leur filtre ne
// servait jamais.
func (d droitsFictifs) AutorisePartout(_ []int, cle string) (bool, string) {
	for accorde := range d.accordes {
		if strings.HasPrefix(accorde, cle+"|") && d.accordes[accorde] {
			return true, ""
		}
	}
	return false, fmt.Sprintf("droit %s accordé sur aucun domaine", cle)
}

// superadminFictif : appartenance au groupe protégé, décidée par le test.
type superadminFictif struct{ membres map[string]bool }

func (s superadminFictif) EstSuperadmin(u string) bool { return s.membres[u] }

// journalFictif retient ce qui a été tracé.
//
// Un refus non journalisé est presque aussi gênant qu'une absence de refus :
// personne ne saurait qu'une tentative a eu lieu.
type journalFictif struct {
	refus      []string
	executions []string
	echecs     []string
}

func (j *journalFictif) Refus(m string)     { j.refus = append(j.refus, m) }
func (j *journalFictif) Execution(m string) { j.executions = append(j.executions, m) }

// Echec est SÉPARÉ d'Execution, et la doublure doit le rester.
//
// Les deux passaient par Execution, donc au même niveau : une écriture qui
// échoue se lisait comme une écriture réussie dans un journal filtré sur INFO.
// Si la doublure les remettait dans la même tranche, un test ne pourrait plus
// distinguer les deux cas et la régression repasserait sans bruit.
func (j *journalFictif) Echec(m string) { j.echecs = append(j.echecs, m) }

// porteeFixe substitue la résolution des domaines.
//
// Sans elle, chaque portée interrogerait l'annuaire ; sans base, toutes
// retomberaient sur « droit global exigé » et la délégation par domaine — le
// cœur du modèle — resterait intestée.
type porteeFixe struct{ domaines []string }

func (p porteeFixe) Domaines(_ action.Definition, _ action.Params) ([]string, error) {
	return p.domaines, nil
}

// porteeCassee simule un annuaire illisible.
type porteeCassee struct{}

func (porteeCassee) Domaines(_ action.Definition, _ action.Params) ([]string, error) {
	return nil, errors.New("annuaire injoignable")
}

// --- assemblage --------------------------------------------------------------

// catalogueReel garnit le catalogue partagé une seule fois.
//
// EnregistrerTout refuse les doublons : un second appel ferait paniquer
// MustEnregistrer. Le testrunner peut être appelé après que main l'a déjà
// garni, ou avant — les deux doivent marcher.
func catalogueReel() *action.Registre {
	if action.Catalogue.Nombre() == 0 {
		action.EnregistrerTout()
	}
	return action.Catalogue
}

// executeurDeTest monte un exécuteur sur le VRAI catalogue avec des doublures.
//
// Le catalogue est le vrai : ce sont les définitions de production — leurs
// clés, leurs exigences de groupe protégé — qui sont mises à l'épreuve. Seuls
// les répondeurs sont fictifs.
func executeurDeTest(accordes map[string]bool, membres map[string]bool, dom []string) (*action.Executeur, *journalFictif) {
	j := &journalFictif{}
	return &action.Executeur{
		Registre:   catalogueReel(),
		Droits:     droitsFictifs{accordes: accordes},
		Superadmin: superadminFictif{membres: membres},
		Journal:    j,
		Portees:    porteeFixe{domaines: dom},
	}, j
}

func estRefus(err error) bool {
	var r *action.ErrRefusee
	return errors.As(err, &r)
}

// --- la suite ----------------------------------------------------------------

// testRBAC est le point d'entrée appelé par Run.
func testRBAC() []Result {
	var out []Result
	out = append(out, testCatalogueGarni()...)
	out = append(out, testFiltrageDesListes()...)
	out = append(out, testInvariantsDesDefinitions()...)
	out = append(out, testMatriceDesDroits()...)
	out = append(out, testGroupeProtege()...)
	out = append(out, testSocleFailClosed()...)
	out = append(out, testEnregistrementRefuseLIncomplet()...)
	out = append(out, testGPORespecteLeRBAC()...)
	return out
}

// testGPORespecteLeRBAC : contrôle dédié aux GPO.
//
// # Pourquoi les GPO méritent leur propre vérification
//
// Une GPO ne porte pas une donnée d'annuaire : elle porte des règles sudo, des
// fichiers déposés en root, des restrictions de shell — appliquées à tout le
// parc visé, au démarrage et à chaque rafraîchissement. C'est l'objet dont le
// contrôle a le plus de conséquences, et le dernier à avoir rejoint le
// registre.
//
// La matrice générale les couvre déjà comme les autres. Ce test ajoute ce qui
// leur est propre.
func testGPORespecteLeRBAC() []Result {
	var out []Result
	const (
		domA = "paris.fr"
		domB = "lyon.fr"
	)

	var gpoActions []action.Definition
	for _, d := range catalogueReel().Definitions() {
		if strings.Contains(d.Nom, "gpo") {
			gpoActions = append(gpoActions, d)
		}
	}

	if len(gpoActions) == 0 {
		out = append(out, Result{"GPO.ActionsPresentes", false,
			"aucune action GPO au catalogue — les GPO ne seraient contrôlées par rien"})
		return out
	}
	out = append(out, Result{
		fmt.Sprintf("GPO.ActionsPresentes (%d actions)", len(gpoActions)), true, ""})

	// 1. Chaque action GPO exige une clé qui parle DE GPO.
	//
	// Une action GPO contrôlée par « write:update:group », par exemple,
	// laisserait quiconque administre un groupe modifier les règles poussées
	// sur les machines de ce groupe. Le droit accordé ne serait plus celui
	// qu'on croit lire dans le nom de la permission.
	var mauvaiseCle, superadminInattendu, ecritureSouple []string
	for _, d := range gpoActions {
		if !strings.HasSuffix(d.CleRBAC, ":gpo") {
			mauvaiseCle = append(mauvaiseCle, d.Nom+" → "+d.CleRBAC)
		}
		// 2. Aucune action GPO ne doit exiger le groupe protégé.
		//
		// Les GPO se DÉLÈGUENT par domaine, c'est tout l'objet du modèle.
		// Exiger l'appartenance au groupe protégé les retirerait aux délégués
		// sans que la table des permissions le montre.
		if d.ExigeSuperadmin {
			superadminInattendu = append(superadminInattendu, d.Nom)
		}
		// 3. Une ÉCRITURE de GPO ne se contente jamais d'un domaine.
		if strings.HasPrefix(d.CleRBAC, "write:") && d.UnDomaineSuffit {
			ecritureSouple = append(ecritureSouple, d.Nom)
		}
	}

	verdictGPO := func(nom string, fautifs []string, quoi string) Result {
		if len(fautifs) == 0 {
			return Result{nom, true, ""}
		}
		sort.Strings(fautifs)
		return Result{nom, false, quoi + " : " + strings.Join(fautifs, ", ")}
	}

	out = append(out,
		verdictGPO("GPO.CleSpecifiqueAuxGPO", mauvaiseCle,
			"actions GPO contrôlées par une clé qui ne parle pas de GPO"),
		verdictGPO("GPO.DeleguablesParDomaine", superadminInattendu,
			"actions GPO réservées au groupe protégé — plus déléguables par domaine"),
		verdictGPO("GPO.EcrituresStrictes", ecritureSouple,
			"écritures GPO se contentant d'un domaine — la portée deviendrait extensible"),
	)

	// 4. LE cas qui compte : la portée extensible.
	//
	// Une GPO liée à paris ET lyon s'applique aux deux parcs à la fois. Un
	// délégué qui n'a le droit que sur paris ne doit pas pouvoir la modifier —
	// sinon il pousse des règles sudo sur des machines de lyon.
	//
	// C'est la manœuvre décrite dans actions_gpo.go : je lie la GPO à un
	// groupe de mon domaine, ce qui me donne le droit d'écriture ; je la lie
	// ensuite à un groupe que je ne contrôle pas, et je continue de passer les
	// contrôles grâce au premier.
	appelant := action.Appelant{Username: "delegue-paris", GroupIDs: []int{1}}
	var portesOuvertes []string
	for _, d := range gpoActions {
		if !strings.HasPrefix(d.CleRBAC, "write:") {
			continue
		}
		// Droit sur paris seulement, GPO couvrant paris ET lyon.
		ex, _ := executeurDeTest(
			map[string]bool{d.CleRBAC + "|" + domA: true},
			map[string]bool{"delegue-paris": true},
			[]string{domA, domB})
		if _, err := ex.Controler(d.Nom, appelant, action.Params{}); !estRefus(err) {
			portesOuvertes = append(portesOuvertes,
				fmt.Sprintf("%s (err=%v)", d.Nom, err))
		}
	}
	out = append(out, verdictGPO("GPO.PorteeNonExtensible", portesOuvertes,
		"écritures autorisées sur une GPO qui déborde du périmètre de l'appelant — "+
			"des règles sudo seraient poussées sur un parc étranger"))

	// 5. La LECTURE, elle, reste tolérante.
	//
	// Voir la liste des GPO d'un domaine qu'on administre partiellement
	// n'accorde aucun pouvoir. Durcir la lecture retirerait aux délégués la
	// vue de leur propre parc.
	var lectureTropDure []string
	for _, d := range gpoActions {
		if !strings.HasPrefix(d.CleRBAC, "read:") {
			continue
		}
		ex, _ := executeurDeTest(
			map[string]bool{d.CleRBAC + "|" + domA: true},
			map[string]bool{"delegue-paris": true},
			[]string{domA, domB})
		if _, err := ex.Controler(d.Nom, appelant, action.Params{}); err != nil {
			lectureTropDure = append(lectureTropDure, fmt.Sprintf("%s (err=%v)", d.Nom, err))
		}
	}
	out = append(out, verdictGPO("GPO.LectureResteDeleguee", lectureTropDure,
		"lectures GPO refusées à un délégué dont un domaine est couvert"))

	return out
}

// testCatalogueGarni : le défaut qui a motivé ce fichier.
//
// EnregistrerTout n'était appelée QUE par les tests. Le serveur démarrait avec
// un catalogue vide : toute action, en ligne de commande comme sur le web,
// répondait « action inconnue ». Rien ne le signalait — un catalogue vide et un
// catalogue garni se compilent pareil.
func testCatalogueGarni() []Result {
	var out []Result
	cat := catalogueReel()

	if n := cat.Nombre(); n == 0 {
		out = append(out, Result{"RBAC.CatalogueGarni", false,
			"le catalogue est vide après EnregistrerTout"})
		return out
	} else {
		out = append(out, Result{fmt.Sprintf("RBAC.CatalogueGarni (%d actions)", n), true, ""})
	}

	// Un exécuteur sur catalogue VIDE doit le dire, et non répondre « action
	// inconnue » — les deux messages envoient chercher la faute à des endroits
	// opposés.
	vide := &action.Executeur{
		Registre: action.NouveauRegistre(),
		Droits:   droitsFictifs{},
	}
	_, err := vide.Controler("user.create", action.Appelant{Username: "x"}, action.Params{})
	switch {
	case err == nil:
		out = append(out, Result{"RBAC.CatalogueVideEstSignale", false,
			"un catalogue vide a autorisé une action"})
	case !strings.Contains(err.Error(), "catalogue d'actions vide"):
		out = append(out, Result{"RBAC.CatalogueVideEstSignale", false,
			"message trompeur sur catalogue vide : " + err.Error()})
	default:
		out = append(out, Result{"RBAC.CatalogueVideEstSignale", true, ""})
	}
	return out
}

// perimetreFictif : « cet appelant voit ces domaines-là, et rien d'autre ».
//
// Les domaines de chaque entité sont posés par le test plutôt que résolus dans
// l'annuaire. C'est ce qui rend le filtrage éprouvable sans base.
type perimetreFictif struct {
	global    bool
	autorises map[string]bool
	domaines  map[string][]string // « u:alice », « c:poste-1 », « p:lecture »
}

func (p perimetreFictif) Global() bool { return p.global }

func (p perimetreFictif) AutoriseUnDes(domaines []string) bool {
	if p.global {
		return true
	}
	for _, d := range domaines {
		if p.autorises[d] {
			return true
		}
	}
	return false
}

func (p perimetreFictif) DomainesDe(genre action.GenreEntite, id string) []string {
	return p.domaines[string(genre)+":"+id]
}

type resolveurFictif struct{ p perimetreFictif }

func (r resolveurFictif) Perimetre(_ []int, _ string) action.Perimetre { return r.p }

// testFiltrageDesListes éprouve la réduction au périmètre.
//
// # Ce que ces tests protègent
//
// Le filtrage vivait dans le serveur web et nulle part ailleurs : la ligne de
// commande rendait l'annuaire entier dès qu'on avait le droit quelque part. Le
// déplacer dans le registre l'unifie — encore faut-il qu'il s'applique.
func testFiltrageDesListes() []Result {
	var out []Result

	// 1. Toute action de LISTE filtre, ou dit par écrit pourquoi elle ne le
	// fait pas.
	//
	// Le repérage se fait sur le NOM et non sur une liste écrite à la main :
	// celle-ci aurait vieilli au premier ajout, et son silence aurait
	// ressemblé à un succès. La convention de nommage est elle-même tenue par
	// RBAC.NomsEnObjetPointVerbe.
	//
	// Le registre refuse déjà ce cas à l'enregistrement. Ce test vérifie deux
	// choses de plus : que ce refus fonctionne, et qu'aucune justification
	// n'est bâclée — « voir plus haut » ou une chaîne de trois mots ne dit
	// rien à qui la relira dans six mois.
	var sansFiltre, justificationCourte []string
	for _, d := range catalogueReel().Definitions() {
		if !strings.Contains(d.Nom, ".list") || d.Filtre != nil {
			continue
		}
		if strings.TrimSpace(d.FiltreInutile) == "" {
			sansFiltre = append(sansFiltre, d.Nom)
		} else if len(strings.Fields(d.FiltreInutile)) < 6 {
			justificationCourte = append(justificationCourte,
				d.Nom+" : « "+d.FiltreInutile+" »")
		}
	}
	if len(sansFiltre) > 0 {
		sort.Strings(sansFiltre)
		out = append(out, Result{"Filtrage.ToutesLesListesFiltrent", false,
			"actions de liste sans filtre ni justification — elles rendraient " +
				"l'annuaire entier : " + strings.Join(sansFiltre, ", ")})
	} else {
		out = append(out, Result{"Filtrage.ToutesLesListesFiltrent", true, ""})
	}
	if len(justificationCourte) > 0 {
		sort.Strings(justificationCourte)
		out = append(out, Result{"Filtrage.ExemptionsJustifiees", false,
			"justifications trop courtes pour être relues : " +
				strings.Join(justificationCourte, " ; ")})
	} else {
		out = append(out, Result{"Filtrage.ExemptionsJustifiees", true, ""})
	}

	// Le registre refuse-t-il vraiment une liste sans filtre ?
	errListe := action.NouveauRegistre().Enregistrer(action.Definition{
		Nom: "essai.list", CleRBAC: "read:get:user", Portee: action.PorteeGlobale,
		Resume: "essai",
		Executer: func(action.Appelant, action.Params) (action.Resultat, error) {
			return action.Resultat{}, nil
		},
	})
	if errListe == nil {
		out = append(out, Result{"Filtrage.EnregistrementRefuseUneListeSansFiltre", false,
			"une action de liste sans filtre ni justification a été enregistrée"})
	} else {
		out = append(out, Result{"Filtrage.EnregistrementRefuseUneListeSansFiltre", true, ""})
	}

	// 2. CHAQUE filtre masque ce qui est hors périmètre, et rien d'autre.
	//
	// # Pourquoi une table écrite à la main est inévitable ici
	//
	// Chaque filtre porte sur un type de données différent : on ne peut pas
	// fabriquer mécaniquement un échantillon pour un « any ». La table est donc
	// écrite, avec le défaut habituel — elle vieillit.
	//
	// Le garde-fou est que sa COUVERTURE est vérifiée contre le catalogue réel :
	// un filtre ajouté demain sans échantillon fait échouer le test. Ce n'est
	// donc pas la table qui décide de ce qui est éprouvé, c'est le catalogue.
	//
	// Une première version n'éprouvait que user.list. Neutraliser le filtre des
	// permissions ou des GPO ne se voyait alors nulle part.
	perim := perimetreFictif{
		autorises: map[string]bool{"paris.fr": true},
		domaines: map[string][]string{
			"utilisateur:alice":       {"paris.fr"},
			"utilisateur:bob":         {"lyon.fr"},
			"utilisateur:carla":       {"lyon.fr", "paris.fr"},
			"client:poste-paris":      {"paris.fr"},
			"client:poste-lyon":       {"lyon.fr"},
			"permission:lecture":      {"paris.fr"},
			"permission:secrete":      {"lyon.fr"},
			"permission_client:agent": {"paris.fr"},
			"permission_client:ext":   {"lyon.fr"},
			"gpo:bureau":              {"paris.fr"},
			"gpo:serveurs":            {"lyon.fr"},
		},
	}

	// Chaque échantillon a exactement UNE entrée hors périmètre.
	echantillons := map[string]any{
		"user.list": []storage.GetUsers{
			{Username: "alice"}, {Username: "bob"}, {Username: "carla"},
		},
		"group.list": []storage.GroupDetails{
			{GroupName: "g1", DomainName: "paris.fr"},
			{GroupName: "g2", DomainName: "lyon.fr"},
		},
		"group.list_users": action.UtilisateursDeGroupe{
			Groupe: "g", Utilisateurs: []storage.DisplayUsersByGroup{
				{Username: "alice"}, {Username: "bob"},
			},
		},
		"group.list_clients": action.MachinesDeGroupe{
			Groupe: "g", Machines: []storage.GetClientsByGroup{
				{ComputeurID: "poste-paris"}, {ComputeurID: "poste-lyon"},
			},
		},
		"client.list": []storage.GetClientsByPermission{
			{ComputeurID: "poste-paris"}, {ComputeurID: "poste-lyon"},
		},
		"permission.list": []storage.UserPermission{
			{Name: "lecture"}, {Name: "secrete"},
		},
		"client_permission.list": []storage.ClientPermission{
			{Name: "agent"}, {Name: "ext"},
		},
		// Sessions : deux types seulement, mais cinq actions — les filtres se
		// partagent selon ce qu'ils rendent, pas selon qui les appelle.
		"session.list_users": []storage.UserConnected{
			{Username: "alice"}, {Username: "bob"},
		},
		"session.list_users_by_group": []storage.UserConnected{
			{Username: "alice"}, {Username: "bob"},
		},
		"session.list_clients": []storage.ClientConnected{
			{ComputeurID: "poste-paris"}, {ComputeurID: "poste-lyon"},
		},
		"session.list_clients_by_group": []storage.ClientConnected{
			{ComputeurID: "poste-paris"}, {ComputeurID: "poste-lyon"},
		},
		"session.list_clients_by_type": []storage.ClientConnected{
			{ComputeurID: "poste-paris"}, {ComputeurID: "poste-lyon"},
		},

		// L'arborescence : la donnée filtrée est la liste PLATE des groupes,
		// pas l'arbre. GroupDomain porte déjà son domaine, aucune résolution.
		"domain.list_tree": []storage.GroupDomain{
			{GroupName: "g1", DomainName: "paris.fr"},
			{GroupName: "g2", DomainName: "lyon.fr"},
		},

		// Conformité GPO : la ligne décrit une MACHINE, le filtre porte donc
		// sur les domaines de la machine.
		"gpo.list_compliance": []dbgpo.ComplianceRow{
			{ComputeurID: "poste-paris"}, {ComputeurID: "poste-lyon"},
		},

		"gpo.list": []dbgpo.PolicySummary{
			{Policy: gpo.Policy{Name: "bureau"}},
			{Policy: gpo.Policy{Name: "serveurs"}},
		},
	}

	var nonMasques, sansEchantillon, masquesEnGlobal []string
	for _, def := range catalogueReel().Definitions() {
		if def.Filtre == nil {
			continue
		}
		brut, connu := echantillons[def.Nom]
		if !connu {
			sansEchantillon = append(sansEchantillon, def.Nom)
			continue
		}
		if _, masquees := def.Filtre(brut, perim); masquees != 1 {
			nonMasques = append(nonMasques,
				fmt.Sprintf("%s (%d masquée(s), attendu 1)", def.Nom, masquees))
		}
		if _, m := def.Filtre(brut, perimetreFictif{global: true}); m != 0 {
			masquesEnGlobal = append(masquesEnGlobal,
				fmt.Sprintf("%s (%d masquée(s))", def.Nom, m))
		}
	}

	verdictFiltre := func(nom string, fautifs []string, quoi string) Result {
		if len(fautifs) == 0 {
			return Result{nom, true, ""}
		}
		sort.Strings(fautifs)
		return Result{nom, false, quoi + " : " + strings.Join(fautifs, " ; ")}
	}

	out = append(out,
		verdictFiltre("Filtrage.MasqueHorsPerimetre", nonMasques,
			"filtres qui ne masquent pas ce qui est hors périmètre"),
		verdictFiltre("Filtrage.ChaqueFiltreEstEprouve", sansEchantillon,
			"filtres sans échantillon — leur comportement n'est pas vérifié"),
		verdictFiltre("Filtrage.PerimetreGlobalNeMasqueRien", masquesEnGlobal,
			"filtres qui masquent malgré un périmètre global"),
	)

	// 3. L'entité à CHEVAL sur deux domaines reste visible.
	//
	// Même règle que UnDomaineSuffit, appliquée à la visibilité. Vérifiée à
	// part parce qu'elle porte sur une entrée précise et non sur un décompte.
	d, ok := catalogueReel().Definition("user.list")
	if !ok || d.Filtre == nil {
		out = append(out, Result{"Filtrage.EntiteACheval", false, "user.list sans filtre"})
		return out
	}
	brut := echantillons["user.list"]
	filtrees, _ := d.Filtre(brut, perim)
	vus := map[string]bool{}
	for _, u := range filtrees.([]storage.GetUsers) {
		vus[u.Username] = true
	}
	switch {
	case !vus["alice"]:
		out = append(out, Result{"Filtrage.EntiteACheval", false,
			"alice (paris) masquée alors qu'elle est dans le périmètre"})
	case vus["bob"]:
		out = append(out, Result{"Filtrage.EntiteACheval", false,
			"bob (lyon) visible hors du périmètre"})
	case !vus["carla"]:
		out = append(out, Result{"Filtrage.EntiteACheval", false,
			"carla (lyon + paris) masquée alors qu'un de ses domaines est dans le périmètre"})
	default:
		out = append(out, Result{"Filtrage.EntiteACheval", true, ""})
	}

	// 4. L'EXÉCUTEUR applique bien le filtre déclaré.
	//
	// Les cas ci-dessus éprouvent les filtres eux-mêmes ; celui-ci vérifie
	// qu'ils sont branchés. Un filtre parfait que personne n'appelle laisse
	// passer exactement autant qu'un filtre absent — et rien, dans les trois
	// premiers cas, ne l'aurait signalé.
	//
	// Une action-sonde plutôt que user.list : celle-ci interrogerait la base.
	reg := action.NouveauRegistre()
	_ = reg.Enregistrer(action.Definition{
		Nom:             "test.list_sonde",
		CleRBAC:         "read:get:user",
		Portee:          action.PorteeGlobale,
		UnDomaineSuffit: true,
		Filtre:          d.Filtre,
		Resume:          "sonde de filtrage",
		Executer: func(action.Appelant, action.Params) (action.Resultat, error) {
			return action.Resultat{Message: "3 utilisateur(s).", Donnees: brut}, nil
		},
	})
	exSonde := &action.Executeur{
		Registre:   reg,
		Droits:     droitsFictifs{accordes: map[string]bool{"read:get:user|*": true}},
		Portees:    porteeFixe{domaines: []string{"*"}},
		Perimetres: resolveurFictif{p: perim},
	}
	res, err := exSonde.Executer("test.list_sonde",
		action.Appelant{Username: "testeur", GroupIDs: []int{1}}, action.Params{})
	apres, _ := res.Donnees.([]storage.GetUsers)
	switch {
	case err != nil:
		out = append(out, Result{"Filtrage.LExecuteurApplique", false, err.Error()})
	case len(apres) != 2:
		out = append(out, Result{"Filtrage.LExecuteurApplique", false,
			fmt.Sprintf("%d entrée(s) rendues, attendu 2 — le filtre déclaré n'a pas été appliqué",
				len(apres))})
	case !strings.Contains(res.Message, "périmètre"):
		out = append(out, Result{"Filtrage.LExecuteurApplique", false,
			"le message ne signale pas les entrées masquées : une liste tronquée " +
				"se lit alors comme une liste complète"})
	default:
		out = append(out, Result{"Filtrage.LExecuteurApplique", true, ""})
	}

	return out
}

// testInvariantsDesDefinitions vérifie ce que chaque action déclare.
func testInvariantsDesDefinitions() []Result {
	var out []Result
	var sansControle, sansPortee, sansResume, malNommees []string

	for _, d := range catalogueReel().Definitions() {
		if strings.TrimSpace(d.CleRBAC) == "" && !d.ExigeSuperadmin {
			sansControle = append(sansControle, d.Nom)
		}
		if d.Portee == nil {
			sansPortee = append(sansPortee, d.Nom)
		}
		if strings.TrimSpace(d.Resume) == "" {
			sansResume = append(sansResume, d.Nom)
		}
		// « objet.verbe » : c'est cette forme que lisent les journaux et les
		// formulaires web. Une action nommée autrement casse le rapprochement
		// entre une trace et l'action qui l'a produite.
		if parties := strings.Split(d.Nom, "."); len(parties) != 2 ||
			parties[0] == "" || parties[1] == "" {
			malNommees = append(malNommees, d.Nom)
		}
	}

	verdict := func(nom string, fautifs []string, explication string) Result {
		if len(fautifs) == 0 {
			return Result{nom, true, ""}
		}
		sort.Strings(fautifs)
		return Result{nom, false, explication + " : " + strings.Join(fautifs, ", ")}
	}

	out = append(out,
		verdict("RBAC.ToutesLesActionsDeclarentUnControle", sansControle,
			"actions sans clé RBAC ni exigence de groupe protégé"),
		verdict("RBAC.ToutesLesActionsDeclarentUnePortee", sansPortee,
			"actions sans portée — le contrôle ne porterait sur rien"),
		verdict("RBAC.ToutesLesActionsOntUnResume", sansResume,
			"actions sans résumé — invisibles dans l'aide et l'inventaire"),
		verdict("RBAC.NomsEnObjetPointVerbe", malNommees,
			"noms hors de la forme objet.verbe"),
	)
	return out
}

// testMatriceDesDroits éprouve CHAQUE action du catalogue sur quatre cas.
//
// Le balayage porte sur le catalogue réel plutôt que sur une liste écrite à la
// main : une action ajoutée demain est éprouvée sans que personne y pense. Une
// liste manuelle, elle, aurait vieilli dès le premier ajout — et son silence
// aurait ressemblé à un succès.
func testMatriceDesDroits() []Result {
	var out []Result
	const (
		domA = "paris.fr"
		domB = "lyon.fr"
	)

	var refusManquant, refusMauvaisDomaine, accesRefuse, refusNonTrace []string
	var lectureTropStricte, ecritureTropLaxiste []string

	for _, d := range catalogueReel().Definitions() {
		// Les actions réservées au groupe protégé sont éprouvées à part : leur
		// contrôle ne passe pas par une clé RBAC.
		if d.CleRBAC == "" {
			continue
		}
		// Aucune ÉCRITURE ne doit se contenter d'un domaine.
		//
		// UnDomaineSuffit est réservé aux lectures. Le poser sur une écriture
		// rendrait la délégation par domaine inopérante là où elle compte le
		// plus : un délégué de paris pourrait modifier une entité qui touche
		// aussi lyon. Rien dans le code ne l'empêche — c'est un champ booléen —
		// donc c'est ici que ça se vérifie.
		if d.UnDomaineSuffit && !strings.HasPrefix(d.CleRBAC, "read:") {
			ecritureTropLaxiste = append(ecritureTropLaxiste, d.Nom+" ("+d.CleRBAC+")")
		}

		// ... et RÉCIPROQUEMENT, toute lecture doit le déclarer.
		//
		// Sans cette seconde moitié, retirer UnDomaineSuffit d'une lecture ne
		// se voyait nulle part : le cas « droit partiel » attend alors un
		// refus, et le vérificateur strict refuse — le test passait donc pour
		// la mauvaise raison. Une lecture durcie par mégarde rend invisibles
		// aux délégués les entités à cheval sur deux domaines, sans qu'aucun
		// message ne le dise.
		if strings.HasPrefix(d.CleRBAC, "read:") && !d.UnDomaineSuffit {
			lectureTropStricte = append(lectureTropStricte,
				d.Nom+" : lecture sans UnDomaineSuffit")
		}

		appelant := action.Appelant{Username: "testeur", GroupIDs: []int{1}}

		// Les actions à exigence CONDITIONNELLE de groupe protégé sont
		// éprouvées ici avec l'appelant DANS le groupe : sinon le refus
		// observé viendrait de l'appartenance, pas du RBAC, et le test
		// passerait pour une raison qui n'est pas celle qu'il croit mesurer.
		membres := map[string]bool{"testeur": true}

		// 1. Aucun droit → refus.
		ex, j := executeurDeTest(map[string]bool{}, membres, []string{domA})
		if _, err := ex.Controler(d.Nom, appelant, action.Params{}); !estRefus(err) {
			refusManquant = append(refusManquant, fmt.Sprintf("%s (err=%v)", d.Nom, err))
		}
		// Trace vérifiée indépendamment du refus, et non dans un « else if ».
		// Enchaînée, elle n'était évaluée que si le refus avait eu lieu : une
		// version qui refuserait sans tracer serait passée inaperçue derrière
		// l'échec du premier cas.
		if len(j.refus) == 0 {
			refusNonTrace = append(refusNonTrace, d.Nom)
		}

		// 2. Droit sur un AUTRE domaine que celui de la portée → refus.
		//
		// C'est le cœur de la délégation : un délégué de lyon n'agit pas sur
		// paris. Sans ce cas, un contrôle qui ignorerait les domaines
		// passerait les trois autres.
		ex, _ = executeurDeTest(map[string]bool{d.CleRBAC + "|" + domB: true}, membres, []string{domA})
		if _, err := ex.Controler(d.Nom, appelant, action.Params{}); !estRefus(err) {
			refusMauvaisDomaine = append(refusMauvaisDomaine, fmt.Sprintf("%s (err=%v)", d.Nom, err))
		}

		// 3. Droit sur le bon domaine → le contrôle passe.
		ex, _ = executeurDeTest(map[string]bool{d.CleRBAC + "|" + domA: true}, membres, []string{domA})
		if _, err := ex.Controler(d.Nom, appelant, action.Params{}); err != nil {
			accesRefuse = append(accesRefuse, fmt.Sprintf("%s (err=%v)", d.Nom, err))
		}

		// 4. Droit sur UN SEUL des deux domaines de la portée.
		//
		// Le résultat attendu DÉPEND de la nature de l'action, et c'est tout
		// l'objet du champ UnDomaineSuffit :
		//
		//   - ÉCRITURE : refus. Une entité présente dans deux domaines exige
		//     le droit dans les deux ; se satisfaire d'un seul laisserait un
		//     délégué de paris agir sur un compte qui a aussi des droits à
		//     lyon.
		//
		//   - LECTURE : acceptation. Ce même compte lui est légitimement
		//     VISIBLE — il fait partie de son périmètre, et le lui cacher
		//     l'empêcherait de constater qu'il y est.
		//
		// Vérifier les deux sens importe autant : un test qui n'exigerait que
		// le refus passerait sur du code ayant durci toutes les lectures, ce
		// qui casserait la délégation sans que rien ne le signale.
		ex, _ = executeurDeTest(map[string]bool{d.CleRBAC + "|" + domA: true}, membres, []string{domA, domB})
		_, err := ex.Controler(d.Nom, appelant, action.Params{})
		if d.UnDomaineSuffit {
			if err != nil {
				lectureTropStricte = append(lectureTropStricte,
					fmt.Sprintf("%s (err=%v)", d.Nom, err))
			}
		} else if !estRefus(err) {
			refusMauvaisDomaine = append(refusMauvaisDomaine,
				fmt.Sprintf("%s (droit partiel accepté)", d.Nom))
		}
	}

	verdict := func(nom string, fautifs []string, explication string) Result {
		if len(fautifs) == 0 {
			return Result{nom, true, ""}
		}
		sort.Strings(fautifs)
		return Result{nom, false, explication + " : " + strings.Join(fautifs, " ; ")}
	}

	out = append(out,
		verdict("RBAC.RefusSansDroit", refusManquant,
			"actions autorisées sans aucun droit"),
		verdict("RBAC.RefusHorsDomaine", refusMauvaisDomaine,
			"actions autorisées avec un droit sur le mauvais domaine"),
		verdict("RBAC.AccesAvecLeDroit", accesRefuse,
			"actions refusées alors que le droit exact était détenu"),
		verdict("RBAC.RefusJournalise", refusNonTrace,
			"refus non tracés — une tentative sans trace est invisible"),
		verdict("RBAC.LectureVoitSonPerimetre", lectureTropStricte,
			"lectures refusées alors que l'appelant a le droit sur UN des domaines — "+
				"une entité de son périmètre lui devient invisible"),
		verdict("RBAC.AucuneEcritureNeSeContenteDUnDomaine", ecritureTropLaxiste,
			"écritures déclarant UnDomaineSuffit — la délégation par domaine ne tient plus"),
	)
	return out
}

// testGroupeProtege éprouve les actions réservées au groupe protégé.
func testGroupeProtege() []Result {
	var out []Result
	var passeSansAppartenance, refuseAvecAppartenance []string
	compte := 0

	// Tous les droits RBAC imaginables, pour prouver que l'appartenance au
	// groupe protégé ne se contourne PAS en accumulant des permissions.
	tousDroits := map[string]bool{}
	for _, d := range catalogueReel().Definitions() {
		if d.CleRBAC != "" {
			tousDroits[d.CleRBAC+"|*"] = true
			tousDroits[d.CleRBAC+"|paris.fr"] = true
		}
	}

	for _, d := range catalogueReel().Definitions() {
		if !d.ExigeSuperadmin {
			continue
		}
		compte++
		appelant := action.Appelant{Username: "intrus", GroupIDs: []int{1}}

		ex, _ := executeurDeTest(tousDroits, map[string]bool{}, []string{"*"})
		if _, err := ex.Controler(d.Nom, appelant, action.Params{}); !estRefus(err) {
			passeSansAppartenance = append(passeSansAppartenance, d.Nom)
		}

		ex, _ = executeurDeTest(tousDroits, map[string]bool{"intrus": true}, []string{"*"})
		if _, err := ex.Controler(d.Nom, appelant, action.Params{}); err != nil {
			refuseAvecAppartenance = append(refuseAvecAppartenance,
				fmt.Sprintf("%s (err=%v)", d.Nom, err))
		}
	}

	if compte == 0 {
		out = append(out, Result{"RBAC.GroupeProtege", false,
			"aucune action n'exige le groupe protégé — la protection des certificats " +
				"et de la politique de mot de passe a disparu"})
		return out
	}

	if len(passeSansAppartenance) > 0 {
		sort.Strings(passeSansAppartenance)
		out = append(out, Result{"RBAC.GroupeProtegeIncontournable", false,
			"actions passées sans appartenance, malgré tous les droits RBAC : " +
				strings.Join(passeSansAppartenance, ", ")})
	} else {
		out = append(out, Result{
			fmt.Sprintf("RBAC.GroupeProtegeIncontournable (%d actions)", compte), true, ""})
	}

	if len(refuseAvecAppartenance) > 0 {
		sort.Strings(refuseAvecAppartenance)
		out = append(out, Result{"RBAC.GroupeProtegeAccorde", false,
			strings.Join(refuseAvecAppartenance, " ; ")})
	} else {
		out = append(out, Result{"RBAC.GroupeProtegeAccorde", true, ""})
	}

	// Un exécuteur DÉPOURVU de vérificateur d'appartenance doit refuser, pas
	// laisser passer : ne pas pouvoir répondre à la question n'est pas une
	// autorisation.
	for _, d := range catalogueReel().Definitions() {
		if !d.ExigeSuperadmin {
			continue
		}
		sansVerif := &action.Executeur{
			Registre: catalogueReel(),
			Droits:   droitsFictifs{accordes: tousDroits},
			Portees:  porteeFixe{domaines: []string{"*"}},
		}
		_, err := sansVerif.Controler(d.Nom, action.Appelant{Username: "x"}, action.Params{})
		if err == nil {
			out = append(out, Result{"RBAC.SansVerificateurAppartenanceRefuse", false,
				d.Nom + " autorisée sans vérificateur d'appartenance"})
			return out
		}
		break
	}
	out = append(out, Result{"RBAC.SansVerificateurAppartenanceRefuse", true, ""})

	return out
}

// testSocleFailClosed éprouve les garde-fous de l'exécuteur lui-même.
func testSocleFailClosed() []Result {
	var out []Result
	appelant := action.Appelant{Username: "testeur", GroupIDs: []int{1}}

	// Exécuteur sans vérificateur de droits : refus, pas exécution.
	sansDroits := &action.Executeur{Registre: catalogueReel()}
	if _, err := sansDroits.Controler("user.create", appelant, action.Params{}); err == nil {
		out = append(out, Result{"Socle.SansVerificateurDeDroitsRefuse", false,
			"une action a été autorisée par un exécuteur sans vérificateur"})
	} else {
		out = append(out, Result{"Socle.SansVerificateurDeDroitsRefuse", true, ""})
	}

	// Action inconnue : erreur typée, distincte d'un échec métier.
	ex, _ := executeurDeTest(map[string]bool{}, map[string]bool{}, []string{"*"})
	_, err := ex.Controler("nexiste.pas", appelant, action.Params{})
	var inconnue *action.ErrInconnue
	if !errors.As(err, &inconnue) {
		out = append(out, Result{"Socle.ActionInconnueTypee", false,
			fmt.Sprintf("erreur inattendue : %v", err)})
	} else {
		out = append(out, Result{"Socle.ActionInconnueTypee", true, ""})
	}

	// Portée indéterminable : refus.
	//
	// Ne pas savoir dans quel domaine se trouve une entité n'autorise pas à
	// agir dessus. Le cas se produit quand l'annuaire est illisible — soit le
	// moment où l'on est le moins en mesure de juger.
	cassee := &action.Executeur{
		Registre:   catalogueReel(),
		Droits:     droitsFictifs{accordes: map[string]bool{"write:create:user|*": true}},
		Superadmin: superadminFictif{membres: map[string]bool{"testeur": true}},
		Portees:    porteeCassee{},
	}
	//
	// Le MOTIF est vérifié, pas seulement le refus.
	//
	// Une première version se contentait de « err != nil ». Elle passait même
	// en supprimant la vérification de l'erreur de portée : les domaines
	// devenaient alors nil, et le refus venait du vérificateur de droits, pas
	// du contrôle qu'on croyait mesurer. Un test qui passe pour la mauvaise
	// raison ne protège de rien — et se remarque encore moins qu'un test
	// absent.
	_, err = cassee.Controler("user.create", appelant, action.Params{})
	switch {
	case err == nil:
		out = append(out, Result{"Socle.PorteeIndeterminableRefuse", false,
			"action autorisée alors que sa portée était illisible"})
	case !strings.Contains(err.Error(), "indéterminable"):
		out = append(out, Result{"Socle.PorteeIndeterminableRefuse", false,
			"refus obtenu, mais pas pour la portée illisible : " + err.Error()})
	default:
		out = append(out, Result{"Socle.PorteeIndeterminableRefuse", true, ""})
	}

	// Controler NE DOIT PAS exécuter l'action.
	//
	// Si elle l'exécutait, tous les tests ci-dessus auraient écrit en base —
	// et le contrôle « refusé » serait indiscernable d'un « exécuté puis
	// annulé ».
	reg := action.NouveauRegistre()
	execute := false
	_ = reg.Enregistrer(action.Definition{
		Nom:     "test.sonde",
		CleRBAC: "write:create:user",
		Portee:  action.PorteeGlobale,
		Resume:  "sonde de test",
		Executer: func(action.Appelant, action.Params) (action.Resultat, error) {
			execute = true
			return action.Resultat{Message: "fait"}, nil
		},
	})
	sonde := &action.Executeur{
		Registre: reg,
		Droits:   droitsFictifs{accordes: map[string]bool{"write:create:user|*": true}},
		Portees:  porteeFixe{domaines: []string{"*"}},
	}
	if _, err := sonde.Controler("test.sonde", appelant, action.Params{}); err != nil {
		out = append(out, Result{"Socle.ControlerNExecutePas", false, "contrôle refusé : " + err.Error()})
	} else if execute {
		out = append(out, Result{"Socle.ControlerNExecutePas", false,
			"Controler a exécuté l'action — un simple contrôle a produit un effet"})
	} else {
		out = append(out, Result{"Socle.ControlerNExecutePas", true, ""})
	}

	// Une action REFUSÉE ne s'exécute pas.
	execute = false
	refuse := &action.Executeur{
		Registre: reg,
		Droits:   droitsFictifs{accordes: map[string]bool{}},
		Portees:  porteeFixe{domaines: []string{"*"}},
	}
	if _, err := refuse.Executer("test.sonde", appelant, action.Params{}); !estRefus(err) {
		out = append(out, Result{"Socle.RefusEmpecheLExecution", false,
			fmt.Sprintf("erreur inattendue : %v", err)})
	} else if execute {
		out = append(out, Result{"Socle.RefusEmpecheLExecution", false,
			"l'action s'est exécutée malgré le refus"})
	} else {
		out = append(out, Result{"Socle.RefusEmpecheLExecution", true, ""})
	}

	// PorteeGlobale exige le droit global, et non « aucun domaine ».
	dom, err := action.PorteeGlobale(action.Params{})
	if err != nil || len(dom) != 1 || dom[0] != "*" {
		out = append(out, Result{"Socle.PorteeGlobaleExigeEtoile", false,
			fmt.Sprintf("PorteeGlobale = %v, %v", dom, err)})
	} else {
		out = append(out, Result{"Socle.PorteeGlobaleExigeEtoile", true, ""})
	}

	return out
}

// testEnregistrementRefuseLIncomplet : le registre refuse ce qui n'est pas
// contrôlable, au moment de l'enregistrement et non à l'usage.
func testEnregistrementRefuseLIncomplet() []Result {
	var out []Result
	rien := func(action.Appelant, action.Params) (action.Resultat, error) {
		return action.Resultat{}, nil
	}

	cas := []struct {
		nom        string
		def        action.Definition
		doitEchoue bool
		pourquoi   string
	}{
		{
			nom:        "Enregistrement.RefuseSansControle",
			def:        action.Definition{Nom: "x.y", Portee: action.PorteeGlobale, Executer: rien},
			doitEchoue: true,
			pourquoi:   "action sans clé RBAC ni ExigeSuperadmin acceptée",
		},
		{
			nom: "Enregistrement.RefuseSuperadminConditionnelSeul",
			def: action.Definition{
				Nom:               "x.y",
				Portee:            action.PorteeGlobale,
				Executer:          rien,
				ExigeSuperadminSi: func(action.Params) bool { return false },
			},
			doitEchoue: true,
			pourquoi: "ExigeSuperadminSi seul accepté — sa condition peut être fausse, " +
				"l'action tournerait alors sans aucun contrôle",
		},
		{
			nom:        "Enregistrement.RefuseSansPortee",
			def:        action.Definition{Nom: "x.y", CleRBAC: "write:create:user", Executer: rien},
			doitEchoue: true,
			pourquoi:   "action sans portée acceptée — le droit ne porterait sur rien",
		},
		{
			nom:        "Enregistrement.RefuseSansExecution",
			def:        action.Definition{Nom: "x.y", CleRBAC: "write:create:user", Portee: action.PorteeGlobale},
			doitEchoue: true,
			pourquoi:   "action sans fonction d'exécution acceptée",
		},
		{
			nom:        "Enregistrement.RefuseSansNom",
			def:        action.Definition{CleRBAC: "write:create:user", Portee: action.PorteeGlobale, Executer: rien},
			doitEchoue: true,
			pourquoi:   "action sans nom acceptée",
		},
		{
			nom: "Enregistrement.AccepteUneDefinitionComplete",
			def: action.Definition{
				Nom: "x.y", CleRBAC: "write:create:user",
				Portee: action.PorteeGlobale, Executer: rien, Resume: "essai",
			},
			doitEchoue: false,
			pourquoi:   "définition complète refusée",
		},
	}

	for _, c := range cas {
		err := action.NouveauRegistre().Enregistrer(c.def)
		if c.doitEchoue && err == nil {
			out = append(out, Result{c.nom, false, c.pourquoi})
		} else if !c.doitEchoue && err != nil {
			out = append(out, Result{c.nom, false, c.pourquoi + " : " + err.Error()})
		} else {
			out = append(out, Result{c.nom, true, ""})
		}
	}

	// Doublon : deux définitions du même nom, l'une écraserait l'autre selon
	// l'ordre des fichiers.
	reg := action.NouveauRegistre()
	def := action.Definition{
		Nom: "x.y", CleRBAC: "write:create:user",
		Portee: action.PorteeGlobale, Executer: rien, Resume: "essai",
	}
	_ = reg.Enregistrer(def)
	if err := reg.Enregistrer(def); err == nil {
		out = append(out, Result{"Enregistrement.RefuseLesDoublons", false,
			"un doublon a été accepté — la définition retenue dépendrait de l'ordre des fichiers"})
	} else {
		out = append(out, Result{"Enregistrement.RefuseLesDoublons", true, ""})
	}

	return out
}
