package webserveur

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// lireFichier rend une source du paquet.
func lireFichier(t *testing.T, nom string) string {
	t.Helper()
	contenu, err := os.ReadFile(nom)
	if err != nil {
		t.Fatalf("lecture de %s : %v", nom, err)
	}
	return string(contenu)
}

// lireGabarit rend un gabarit, par le même chemin que le serveur.
//
// RepertoireGabarits et non un chemin recopié : le jour où l'emplacement change,
// ce test suit au lieu d'échouer sur un fichier introuvable — ce qui se lirait
// comme une régression alors que ce serait un déménagement.
func lireGabarit(t *testing.T, nom string) string {
	t.Helper()
	chemin := filepath.Join(RepertoireGabarits(), nom)
	contenu, err := os.ReadFile(chemin)
	if err != nil {
		t.Fatalf("lecture de %s : %v", chemin, err)
	}
	return string(contenu)
}

// La page de conformité ne doit RIEN recalculer.
//
// # La condition posée à cette page
//
// « Le tri et les états viennent de db_gpo.TrierConformite et
// ComplianceRow.Fraicheur : ne pas les recopier dans le gabarit, sans quoi la
// CLI et le web finiront par ne plus dire la même chose. »
//
// C'est un risque réel et lent : deux vues qui recalculeraient séparément « en
// retard » ou « non vérifié » ne divergeraient pas tout de suite. Personne ne
// remarquerait l'écart tant qu'il serait petit, et quand il grandirait, on ne
// saurait plus laquelle des deux avait raison — alors que c'est la vue qu'on
// consulte quand quelque chose ne va pas.
//
// Un commentaire ne suffit pas à tenir cette condition dans le temps. Ces tests
// la rendent vérifiable.
//
// # Pourquoi une inspection du TEXTE
//
// L'alternative serait de rendre la page et de comparer à la CLI, ce qui
// demanderait une base peuplée, un serveur HTTP et un agent qui rapporte. Ce
// test-là n'existerait pas. Celui-ci lit les sources et attrape la recopie au
// moment où elle est écrite.

const fichierConformite = "web_admin_conformite.go"

// TestLaPageNeRecalculeAucunEtat.
//
// Les seuils et les comparaisons de dates sont la propriété de db_gpo. Les
// retrouver ici signifierait qu'on a réécrit « en retard » côté web.
func TestLaPageNeRecalculeAucunEtat(t *testing.T) {
	source := lireFichier(t, fichierConformite)

	interdits := []struct {
		motif  *regexp.Regexp
		raison string
	}{
		{regexp.MustCompile(`ToleranceRapport|IntervalleRapportAgent`),
			"la page compare elle-même les délais au lieu d'appeler Fraicheur"},
		{regexp.MustCompile(`\bsort\.`),
			"la page trie : l'ordre vient de TrierConformite, appelé par ListCompliance"},
		{regexp.MustCompile(`DriftCount\s*[=><!]=?\s*0`),
			"la page décide elle-même de l'état de conformité au lieu d'appeler EtatConformite"},
		{regexp.MustCompile(`ModulesTotal\s*-\s*ModulesFailed`),
			"la page recompose « appliqués / total » au lieu d'appeler ModulesAppliques"},
		{regexp.MustCompile(`time\.Since`),
			"la page calcule un âge : AgeRelatif le fait, et prend l'instant en paramètre"},
	}

	for _, ligne := range strings.Split(source, "\n") {
		nue := strings.TrimSpace(ligne)
		// Les commentaires sont tolérés : le fichier EXPLIQUE ce qu'il ne fait
		// pas, et l'interdire rendrait la raison indicible.
		if strings.HasPrefix(nue, "//") {
			continue
		}
		for _, i := range interdits {
			if i.motif.MatchString(nue) {
				t.Errorf("%s : %s\n    %s", fichierConformite, i.raison, nue)
			}
		}
	}
}

// TestLaPageEmprunteLesFonctionsPartagees.
//
// L'inverse du test précédent. Ne rien recalculer ne suffit pas : encore
// faut-il appeler ce qui décide. Une page qui n'appellerait ni `Fraicheur` ni
// `EtatConformite` afficherait des colonnes vides — un défaut visible, mais
// autant le nommer ici.
func TestLaPageEmprunteLesFonctionsPartagees(t *testing.T) {
	source := lireFichier(t, fichierConformite)

	for _, attendu := range []string{
		"Fraicheur(",
		"EtatConformite()",
		"ModulesAppliques()",
		"dbgpo.AgeRelatif(",
		"dbgpo.ResumerParc(",
		"ARetenirDansLaVueDesEcarts(",
	} {
		if !strings.Contains(source, attendu) {
			t.Errorf("%s n'appelle pas %s : soit la colonne est vide, soit elle "+
				"est recalculée ailleurs", fichierConformite, attendu)
		}
	}
}

// TestLesGabaritsNeDecidentDeRien.
//
// Un gabarit peut comparer des chaînes — `{{ if eq .Etat "à jour" }}` — pour
// choisir une couleur, et c'est légitime : c'est de la mise en forme. Ce qu'il
// ne doit pas faire, c'est arithmétique sur les compteurs, parce que c'est là
// que se recrée un état.
func TestLesGabaritsNeDecidentDeRien(t *testing.T) {
	for _, nom := range []string{
		"admin_gpo_compliance.html",
		"admin_gpo_compliance_detail.html",
	} {
		contenu := lireGabarit(t, nom)
		for _, interdit := range []string{
			"DriftCount", // l'état de conformité vient de EtatConformite
			"ReportedAt", // l'âge vient de AgeRelatif
			"JamaisRapporte",
		} {
			if strings.Contains(contenu, interdit) {
				t.Errorf("%s manipule %s : l'état doit venir du paquet, pas du gabarit",
					nom, interdit)
			}
		}
	}
}
