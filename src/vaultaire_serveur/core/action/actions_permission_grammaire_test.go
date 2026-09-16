package action

import (
	"strings"
	"testing"

	"vaultaire/core/storage"
)

// Ces tests portent sur les gardes qui refusent AVANT toute écriture.
//
// C'est ce qui les rend exécutables sans base : chacun vérifie que l'action
// s'arrête avant d'atteindre la couche de persistance. Un test qui atteindrait
// la base prouverait d'ailleurs le contraire de ce qu'il cherche — la garde
// aurait laissé passer.

// TestCleInconnueRefusee est le premier des trois écarts constatés entre
// « update -pu » et l'interface web.
//
// La ligne de commande se contentait de permission.IsValidAction, qui vérifie
// la FORME « catégorie:action:objet ». Une clé bien formée mais inconnue du
// moteur RBAC s'insérait donc en base, n'y était jamais évaluée, et restait
// invisible : la fiche affichait un droit qui n'accordait rien.
func TestCleInconnueRefusee(t *testing.T) {
	_, err := reglerActionPermission(
		Appelant{Username: "root"},
		Params{"permission_name": "lecture", "field": "write:invente:machin", "op": "all"},
	)
	if err == nil {
		t.Fatal("une clé inconnue du moteur RBAC a été acceptée")
	}
	if !strings.Contains(err.Error(), "inconnue") {
		t.Errorf("message %q : ne dit pas que la clé est inconnue", err)
	}
}

// TestCleAdministrableAcceptee : la garde ne doit pas refuser les clés
// légitimes.
//
// Sans ce cas, une garde qui refuserait TOUT passerait le test précédent — et
// rendrait la page de permissions inutilisable.
func TestCleAdministrableAcceptee(t *testing.T) {
	for _, cle := range []string{"read:get:user", "write:create:group", "web_admin"} {
		if !ActionPermissionAdministrable(cle) {
			t.Errorf("clé légitime %q refusée par la garde", cle)
		}
	}
	if ActionPermissionAdministrable("pas_une_cle") {
		t.Error("clé fantaisiste acceptée")
	}
}

// TestActionGlobaleRefuseUnDomaine est le deuxième écart, et le plus lourd.
//
// `web_admin` ne s'évalue que sur « * ». Lui donner une liste de domaines la
// REFUSE au lieu de la restreindre : la commande
//
//	update -pu <perm> web_admin -a 0 paris
//
// retirait donc l'accès à l'interface d'administration à tous les groupes
// portant cette permission — y compris à celui qui la tapait, qui n'avait
// alors plus l'interface pour revenir en arrière. Le web l'interdisait déjà ;
// la ligne de commande le permettait.
func TestActionGlobaleRefuseUnDomaine(t *testing.T) {
	for _, op := range []string{"-a", "add", "-r", "remove"} {
		_, err := reglerActionPermission(
			Appelant{Username: "root"},
			Params{
				"permission_name": "lecture",
				"field":           "web_admin",
				"op":              op,
				"domain":          "paris.fr",
				"propagation":     "0",
			},
		)
		if err == nil {
			t.Fatalf("op %q : un domaine a été accepté sur web_admin — "+
				"l'accès à l'interface d'administration aurait été retiré", op)
		}
		if !strings.Contains(err.Error(), "tous les domaines") {
			t.Errorf("op %q : message %q n'explique pas pourquoi", op, err)
		}
	}
}

// TestDomaineRequisPourAjoutEtRetrait.
func TestDomaineRequisPourAjoutEtRetrait(t *testing.T) {
	for _, op := range []string{"-a", "-r"} {
		_, err := reglerActionPermission(
			Appelant{Username: "root"},
			Params{"permission_name": "lecture", "field": "read:get:user", "op": op},
		)
		if err == nil {
			t.Fatalf("op %q acceptée sans domaine", op)
		}
		if !strings.Contains(err.Error(), "omaine") {
			t.Errorf("op %q : message %q ne nomme pas le domaine manquant", op, err)
		}
	}
}

// TestOperationInconnueRefusee : fail-closed sur l'opération.
//
// Un « default » qui laisserait passer écrirait la valeur courante inchangée
// et annoncerait un succès — le pire des deux mondes, puisque l'utilisateur
// croirait son réglage appliqué.
func TestOperationInconnueRefusee(t *testing.T) {
	_, err := reglerActionPermission(
		Appelant{Username: "root"},
		Params{"permission_name": "lecture", "field": "read:get:user", "op": "peut-etre"},
	)
	if err == nil {
		t.Fatal("opération inconnue acceptée")
	}
	if !strings.Contains(err.Error(), "inconnue") {
		t.Errorf("message %q", err)
	}
}

// TestNomDePermissionRequis.
func TestNomDePermissionRequis(t *testing.T) {
	_, err := reglerActionPermission(
		Appelant{Username: "root"},
		Params{"field": "read:get:user", "op": "all"},
	)
	if err == nil {
		t.Fatal("action acceptée sans nom de permission")
	}
}

// TestLesDeuxVocabulairesSontAcceptes.
//
// La ligne de commande écrit « -a » et « -r », le web « add » et « remove ».
// Imposer un vocabulaire unique aurait cassé la syntaxe que les
// administrateurs ont dans leurs scripts — et l'échec ne se serait vu qu'à
// l'exécution du script, pas au portage.
func TestLesDeuxVocabulairesSontAcceptes(t *testing.T) {
	cas := map[string]string{
		"-a":     OpPermissionAjout,
		"add":    OpPermissionAjout,
		"-r":     OpPermissionRetrait,
		"remove": OpPermissionRetrait,
		"nil":    OpPermissionNil,
		"all":    OpPermissionAll,
	}
	for entree, attendu := range cas {
		got, ok := normaliserOperation(entree)
		if !ok || got != attendu {
			t.Errorf("normaliserOperation(%q) = %q, %v ; attendu %q", entree, got, ok, attendu)
		}
	}
	if _, ok := normaliserOperation("supprime-tout"); ok {
		t.Error("une opération fantaisiste a été normalisée")
	}
}

// TestRetraitDistingueLesDeuxModesDePropagation est le troisième écart.
//
// Un même domaine peut figurer avec ET sans propagation. Retirer « avec
// propagation » ne doit pas être accepté quand le domaine n'est présent que
// « sans » — sinon UpdatePermissionAction, qui est silencieuse sur un domaine
// absent, laissait annoncer « domaine retiré » alors que rien n'avait changé.
func TestRetraitDistingueLesDeuxModesDePropagation(t *testing.T) {
	pa := storage.PermissionAction{
		WithPropagation:    []string{"lyon.fr"},
		WithoutPropagation: []string{"paris.fr"},
	}

	verifier := func(domaine, propagation string, attendu bool) {
		t.Helper()
		if got := domaineAccorde(pa, domaine, propagation); got != attendu {
			t.Errorf("domaine %q propagation %q : %v, attendu %v", domaine, propagation, got, attendu)
		}
	}

	verifier("paris.fr", "0", true)
	verifier("paris.fr", "1", false) // présent sans propagation seulement
	verifier("lyon.fr", "1", true)
	verifier("lyon.fr", "0", false) // présent avec propagation seulement
	verifier("nice.fr", "0", false)
}
