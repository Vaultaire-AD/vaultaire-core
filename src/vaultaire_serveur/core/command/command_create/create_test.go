package commandcreate

import (
	"strings"
	"testing"
)

// Tests de l'analyse syntaxique de « create ».
//
// Cette commande ne fait plus qu'une chose : traduire une syntaxe en paramètres
// nommés. C'est donc exactement ce qui est éprouvé ici — pas les droits, pas
// l'écriture en base, qui vivent dans core/action et y sont testés.
//
// # Ce que ces tests gardent
//
// Un paramètre qu'on oublie de transmettre ne produit aucune erreur : l'action
// le reçoit absent et se comporte comme si l'utilisateur ne l'avait pas fourni.
// C'est ainsi que la description des permissions a disparu — l'action la lit, la
// base la porte, le formulaire web la renseigne, et seule cette commande n'avait
// aucun moyen de la donner. Rien ne le signalait.

func TestExtraireOptionsSortLaDescriptionDesPositionnels(t *testing.T) {
	options, positionnels := extraireOptions([]string{"lecture", "non", "--desc", "accès en lecture"})

	if got := options.Get("description"); got != "accès en lecture" {
		t.Errorf("description = %q, attendue %q", got, "accès en lecture")
	}
	if len(positionnels) != 2 || positionnels[0] != "lecture" || positionnels[1] != "non" {
		t.Errorf("positionnels = %v, attendus [lecture non]", positionnels)
	}
}

// TestOptionRetireeDesPositionnels : c'est le point du découpage.
//
// Laissée dans la liste, « --desc » serait comptée comme un argument de
// position. L'action recevrait alors « --desc » comme valeur de web_admin et
// refuserait la création sur un motif incompréhensible — ou pire, la ferait
// avec la mauvaise valeur.
func TestOptionRetireeDesPositionnels(t *testing.T) {
	_, positionnels := extraireOptions([]string{"lecture", "--desc", "texte", "non"})

	for _, p := range positionnels {
		if strings.HasPrefix(p, "--") {
			t.Errorf("positionnels = %v : l'option %q y est restée", positionnels, p)
		}
	}
	if len(positionnels) != 2 {
		t.Errorf("positionnels = %v, attendus 2 éléments", positionnels)
	}
}

// TestOptionSansValeurNeConsommePasLArgumentSuivant.
//
// « create -p lecture --desc » en fin de ligne ne doit ni paniquer ni inventer
// une description. L'option est simplement ignorée.
func TestOptionSansValeurEnFinDeLigne(t *testing.T) {
	options, positionnels := extraireOptions([]string{"lecture", "oui", "--desc"})

	if got := options.Get("description"); got != "" {
		t.Errorf("description = %q, attendue vide", got)
	}
	if len(positionnels) != 2 {
		t.Errorf("positionnels = %v, attendus [lecture oui]", positionnels)
	}
}

func TestSansOptionRienNeChange(t *testing.T) {
	options, positionnels := extraireOptions([]string{"lecture", "oui"})

	if len(options) != 0 {
		t.Errorf("options = %v, attendues vides", options)
	}
	if len(positionnels) != 2 {
		t.Errorf("positionnels = %v", positionnels)
	}
}

// TestAideNAnnoncePasUneValeurRefusee.
//
// L'aide annonçait « <yes/not> ». « not » n'a jamais figuré parmi les valeurs
// acceptées : qui recopiait l'aide à la lettre obtenait « valeur "not"
// invalide » et n'avait aucune raison de soupçonner l'aide elle-même.
//
// Le test porte sur le texte parce que c'est là qu'était le défaut. Une aide
// est du code : elle se vérifie.
func TestAideNAnnoncePasUneValeurRefusee(t *testing.T) {
	texte := aide()

	if strings.Contains(texte, "not>") || strings.Contains(texte, "/not") {
		t.Error("l'aide annonce encore « not », qui n'est pas une valeur acceptée")
	}
	for _, attendu := range []string{"create -pc", "--desc", "oui|non"} {
		if !strings.Contains(texte, attendu) {
			t.Errorf("l'aide ne mentionne pas %q", attendu)
		}
	}
}

// TestActionsUtiliseesCouvreLesRoutes.
//
// La liste est vérifiée au démarrage contre le registre : une action manquante
// ferait échouer la commande au moment où quelqu'un la tape. L'oublier en
// ajoutant une route revient à retirer ce garde-fou pour cette route-là.
func TestActionsUtiliseesCouvreLesRoutes(t *testing.T) {
	declarees := map[string]bool{}
	for _, a := range ActionsUtilisees {
		declarees[a] = true
	}

	for _, attendue := range []string{
		"user.create", "group.create", "client.create",
		"permission.create", "client_permission.create",
	} {
		if !declarees[attendue] {
			t.Errorf("%q absente d'ActionsUtilisees : la route correspondante "+
				"échouerait au moment où quelqu'un tape la commande", attendue)
		}
	}
}
