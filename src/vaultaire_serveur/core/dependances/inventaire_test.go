package dependances

import (
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
)

// `go test ./core/dependances/ -update` réécrit la page au lieu de la vérifier.
// C'est ce que lance automatisation/dependances.sh.
var majPage = flag.Bool("update", false, "réécrire la page d'inventaire des dépendances")

// charger lit tout ce dont les tests ont besoin, ou arrête le test.
func charger(t *testing.T) (string, *Inventaire, *Roles) {
	t.Helper()
	racine, err := RacineDuDepot()
	if err != nil {
		t.Fatalf("%v", err)
	}
	inv, err := Scanner(racine)
	if err != nil {
		t.Fatalf("inventaire impossible : %v", err)
	}
	roles, err := LireRoles(racine)
	if err != nil {
		t.Fatalf("%v", err)
	}
	return racine, inv, roles
}

// TestInventaireAJour : la page décrit-elle encore le dépôt ?
//
// C'est le test qui donne sa valeur à la page. Une liste de dépendances tenue à
// la main diverge — c'est ce qui avait produit la liste de modules fausse dans
// dev.yaml — et son silence ressemble à un succès. Ici, ajouter une dépendance
// sans régénérer la page fait échouer l'intégration continue.
func TestInventaireAJour(t *testing.T) {
	racine, inv, roles := charger(t)
	chemin := filepath.Join(racine, CheminDoc)

	page, err := os.ReadFile(chemin)
	if err != nil {
		t.Fatalf("%v", err)
	}
	attendu := Rendre(inv, roles)

	if *majPage {
		nouvelle, err := RemplacerBloc(string(page), attendu)
		if err != nil {
			t.Fatalf("%v", err)
		}
		if err := os.WriteFile(chemin, []byte(nouvelle), 0o644); err != nil {
			t.Fatalf("%v", err)
		}
		t.Log("page régénérée : " + CheminDoc)
		return
	}

	actuel, err := BlocActuel(string(page))
	if err != nil {
		t.Fatalf("%v", err)
	}
	if actuel != attendu {
		t.Errorf("%s ne décrit plus le dépôt.\n\n"+
			"Régénérez-la : ./automatisation/dependances.sh\n\n"+
			"%s", CheminDoc, premiereDifference(actuel, attendu))
	}
}

// TestChaqueDependanceEstExpliquee.
//
// Une version sans explication ne sert à rien : savoir qu'on tire
// `github.com/pkg/sftp` ne dit pas si on peut s'en passer. Savoir qu'elle porte
// `create -c … -join` le dit. C'est la seule partie de l'inventaire qui ne se
// génère pas, donc la seule qu'un test doive exiger.
func TestChaqueDependanceEstExpliquee(t *testing.T) {
	_, inv, roles := charger(t)

	var manquantes []string
	for _, d := range inv.Go {
		if strings.TrimSpace(roles.Role[d.Chemin]) == "" {
			manquantes = append(manquantes, d.Chemin)
		}
	}
	for _, img := range inv.Images {
		if strings.TrimSpace(roles.Role[img.Reference]) == "" {
			manquantes = append(manquantes, img.Reference)
		}
	}
	if len(manquantes) > 0 {
		sort.Strings(manquantes)
		t.Errorf("sans explication dans %s :\n  %s\n\n"+
			"Ajoutez une ligne « <chemin> = à quoi ça sert ».",
			CheminRoles, strings.Join(manquantes, "\n  "))
	}
}

// TestAucuneExplicationOrpheline.
//
// L'inverse : une dépendance retirée du code doit quitter le fichier des rôles.
// Sinon il grossit d'entrées mortes, et on finit par ne plus savoir lesquelles
// décrivent quelque chose de réel.
func TestAucuneExplicationOrpheline(t *testing.T) {
	_, inv, roles := charger(t)

	connues := map[string]bool{}
	for _, d := range inv.Go {
		connues[d.Chemin] = true
	}
	for _, img := range inv.Images {
		connues[img.Reference] = true
	}

	var orphelines []string
	for chemin := range roles.Role {
		if !connues[chemin] {
			orphelines = append(orphelines, chemin)
		}
	}
	if len(orphelines) > 0 {
		sort.Strings(orphelines)
		t.Errorf("décrites dans %s mais absentes du dépôt :\n  %s",
			CheminRoles, strings.Join(orphelines, "\n  "))
	}
}

// TestAucuneDivergenceNonDeclaree.
//
// LE test de ce lot. Trois divergences dormaient dans le dépôt, dont
// `golang.org/x/crypto` en TROIS versions — la bibliothèque de crypto. Un
// correctif de sécurité appliqué dans un module et pas dans les deux autres
// n'aurait alerté personne.
//
// Elles ne sont pas interdites : aligner n'est pas toujours possible tout de
// suite. Elles doivent être ÉCRITES, avec leur raison. Une divergence qu'on a
// décidé d'accepter et une divergence qu'on n'a pas vue se ressemblent
// beaucoup, et c'est la seule chose qui les sépare.
func TestAucuneDivergenceNonDeclaree(t *testing.T) {
	_, inv, roles := charger(t)

	var muettes []string
	for _, d := range inv.Go {
		if !d.Divergente() {
			continue
		}
		if strings.TrimSpace(roles.Divergence[d.Chemin]) == "" {
			var détails []string
			for _, v := range d.VersionsTriees() {
				détails = append(détails, v+" ("+strings.Join(d.Versions[v], ", ")+")")
			}
			muettes = append(muettes, d.Chemin+" : "+strings.Join(détails, " / "))
		}
	}
	if len(muettes) > 0 {
		sort.Strings(muettes)
		t.Errorf("divergences de version non déclarées :\n  %s\n\n"+
			"Alignez les versions, ou écrivez la raison dans %s :\n"+
			"  !<chemin> = pourquoi elles diffèrent",
			strings.Join(muettes, "\n  "), CheminRoles)
	}
}

// TestUneDivergenceDeclareeQuiNExistePlus.
//
// Une justification qui survit à l'alignement des versions laisse croire que le
// problème est toujours là — et fait renoncer à le regarder.
func TestUneDivergenceDeclareeQuiNExistePlus(t *testing.T) {
	_, inv, roles := charger(t)

	divergentes := map[string]bool{}
	for _, d := range inv.Go {
		if d.Divergente() {
			divergentes[d.Chemin] = true
		}
	}
	for chemin := range roles.Divergence {
		if !divergentes[chemin] {
			t.Errorf("%s justifie une divergence sur %s, qui n'existe plus : "+
				"retirez la ligne", CheminRoles, chemin)
		}
	}
}

// TestLInventaireNEstJamaisVide : un scan qui ne trouve rien rendrait un tableau
// vide, c'est-à-dire « aucune dépendance » — et le test passerait.
func TestLInventaireNEstJamaisVide(t *testing.T) {
	_, inv, _ := charger(t)
	if len(inv.Go) == 0 {
		t.Error("aucune dépendance Go trouvée : le scan est cassé")
	}
	if len(inv.Images) == 0 {
		t.Error("aucune image de base trouvée : le scan des Dockerfiles est cassé")
	}
}

// premiereDifference montre la première ligne qui diffère, plutôt que deux
// tableaux entiers qu'on ne comparera pas à l'œil.
func premiereDifference(actuel, attendu string) string {
	a := strings.Split(actuel, "\n")
	b := strings.Split(attendu, "\n")
	for i := 0; i < len(a) || i < len(b); i++ {
		ga, gb := "", ""
		if i < len(a) {
			ga = a[i]
		}
		if i < len(b) {
			gb = b[i]
		}
		if ga != gb {
			return fmt.Sprintf("première différence, ligne %d du bloc :\n"+
				"  page    : %s\n  attendu : %s", i+1, ga, gb)
		}
	}
	return ""
}
