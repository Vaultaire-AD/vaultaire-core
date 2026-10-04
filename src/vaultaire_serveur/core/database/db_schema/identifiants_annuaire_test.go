package dbschema

import (
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// Sentinelle du point 129 : toute création d'un compte ou d'un groupe pose son
// identifiant.
//
// # Ce que ce test ferme
//
// `entry_uuid` admet NULL — il le faut, pour l'ajouter sur une base en service.
// Une insertion qui oublie la colonne réussit donc sans rien dire, et l'entrée
// est servie SANS identifiant jusqu'au prochain démarrage du core, qui lui en
// donne un. Un client qui l'importe dans l'intervalle la verra ensuite changer
// d'identifiant : exactement ce que le point devait rendre impossible.
//
// # L'exception, et elle est unique
//
// create_data_base.go insère les deux lignes initiales dans le texte du schéma,
// qui ne sait pas tirer un UUID. Elles reçoivent le leur quelques lignes plus
// bas, dans le même démarrage, par EnsureIdentifiantsAnnuaire.
func TestTouteCreationDEntreePoseSonIdentifiant(t *testing.T) {
	insertion := regexp.MustCompile("(?is)INSERT\\s+(?:IGNORE\\s+)?INTO\\s+`?(users|groups)`?\\s*\\(([^)]*)\\)")

	racine := filepath.Join("..", "..", "..") // src/vaultaire_serveur
	trouvees := 0
	err := filepath.WalkDir(racine, func(chemin string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() || !strings.HasSuffix(chemin, ".go") || strings.HasSuffix(chemin, "_test.go") {
			return nil
		}
		contenu, err := os.ReadFile(chemin)
		if err != nil {
			return err
		}
		for _, m := range insertion.FindAllStringSubmatch(string(contenu), -1) {
			trouvees++
			if filepath.Base(chemin) == "create_data_base.go" {
				continue
			}
			if !strings.Contains(m[2], ColonneIdentifiant) {
				t.Errorf("%s insère dans %s sans %s : l'entrée serait servie sans identifiant "+
					"jusqu'au prochain redémarrage, puis en changerait.\n  colonnes : %s",
					chemin, m[1], ColonneIdentifiant, strings.Join(strings.Fields(m[2]), " "))
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if trouvees < 4 {
		t.Fatalf("%d insertion(s) trouvée(s) dans users et groups, au moins 4 attendues : "+
			"le motif ne reconnaît plus les requêtes, ce test ne vérifierait rien", trouvees)
	}
}

// Les identifiants entrent dans le texte des requêtes de migration : ils
// doivent passer le motif de schematools, sans quoi le core s'arrête au
// démarrage.
func TestLesIdentifiantsDeLaMigrationSontAcceptes(t *testing.T) {
	motif := regexp.MustCompile(`^[a-z_]{1,64}$`)
	noms := []string{ColonneIdentifiant}
	for _, t := range tablesIdentifiees {
		noms = append(noms, t.Table, t.Cle, t.Index)
	}
	for _, n := range noms {
		if !motif.MatchString(n) {
			t.Errorf("%q serait refusé par schematools", n)
		}
	}
}
