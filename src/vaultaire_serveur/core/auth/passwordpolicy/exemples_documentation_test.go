package passwordpolicy

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	dbauthpolicy "vaultaire/core/database/db_authpolicy"
)

// Les mots de passe d'exemple de la documentation passent la politique —
// TO-DO 151.
//
// # Le défaut
//
// Le premier geste de la formation (jalon 2.2) échouait : « Alice-2026! » fait
// onze caractères, et contient « alice ». Le démarrage rapide du README aussi,
// et le compte de service du jalon 8.1 — « il contient keycloak ». Le lecteur
// ne savait pas si l'erreur venait de lui ou du produit.
//
// Rien ne le voyait : la politique a été durcie (TO-DO 100) sans que personne
// ne relise les exemples. Ce test les relit à chaque `go test` : le prochain
// durcissement rougira ici, pas devant un stagiaire.
//
// # Ce qui est lu
//
// README.md, toute la formation (docs/training) et le manuel
// (docs/Utilisation/MAN.md) : chaque `create -u <id> <domaine> <mdp>` et
// chaque `update -u <id> -p <mdp>`, dans un bloc de code ou dans le texte.
//
// Le compte est contrôlé comme l'action le contrôle : `create -u` sous la forme
// « id@domaine » (les libellés du domaine sont alors interdits), `update -u`
// sous l'identifiant tel qu'il est tapé.
//
// # Ce qui est écarté
//
// Les lignes de SYNTAXE (`<motdepasse>`, `password`, `…`) : ce ne sont pas des
// mots de passe. La liste est fermée — un mot qui s'y ajoute s'y ajoute ici,
// en le voyant.

// racineDuDepot remonte de core/auth/passwordpolicy à la racine du dépôt.
func racineDuDepot(t *testing.T) string {
	t.Helper()
	racine, err := filepath.Abs(filepath.Join("..", "..", "..", "..", ".."))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(racine, "docs", "training", "README.md")); err != nil {
		t.Fatalf("racine du dépôt introuvable depuis %s : %v", racine, err)
	}
	return racine
}

// Un argument : entre apostrophes, entre guillemets, ou un mot.
const argument = `('[^']*'|"[^"]*"|\S+)`

var (
	motifCreation = regexp.MustCompile(`create -u\s+` + argument + `\s+` + argument + `\s+` + argument)
	// --permanent (TO-DO 144) se place avant -p : un exemple qui l'emploie
	// doit être contrôlé comme les autres.
	motifChangement = regexp.MustCompile(`update -u\s+` + argument + `\s+(?:--permanent\s+)?-p\s+` + argument)
)

// gabarits sont les mots de passe qui n'en sont pas : ceux des lignes de
// syntaxe.
var gabarits = map[string]bool{
	"password": true, "pass": true, "motdepasse": true, "mdp": true,
	"…": true, "...": true,
}

func sansGuillemets(s string) string {
	if len(s) >= 2 && (s[0] == '\'' || s[0] == '"') && s[len(s)-1] == s[0] {
		return s[1 : len(s)-1]
	}
	return s
}

func estUnGabarit(mdp string) bool {
	return strings.HasPrefix(mdp, "<") || gabarits[strings.ToLower(mdp)]
}

type exemple struct {
	ou, compte, motDePasse string
}

func exemplesDeLaDocumentation(t *testing.T) []exemple {
	t.Helper()
	racine := racineDuDepot(t)

	fichiers := []string{
		filepath.Join(racine, "README.md"),
		filepath.Join(racine, "docs", "Utilisation", "MAN.md"),
	}
	err := filepath.WalkDir(filepath.Join(racine, "docs", "training"), func(p string, d os.DirEntry, err error) error {
		if err == nil && !d.IsDir() && strings.HasSuffix(p, ".md") {
			fichiers = append(fichiers, p)
		}
		return err
	})
	if err != nil {
		t.Fatal(err)
	}

	var trouves []exemple
	for _, f := range fichiers {
		contenu, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		relatif, _ := filepath.Rel(racine, f)
		for n, ligne := range strings.Split(string(contenu), "\n") {
			ou := relatif + ":" + itoa(n+1)
			for _, m := range motifCreation.FindAllStringSubmatch(ligne, -1) {
				id, domaine, mdp := sansGuillemets(m[1]), sansGuillemets(m[2]), sansGuillemets(m[3])
				if estUnGabarit(mdp) || strings.HasPrefix(id, "<") {
					continue
				}
				trouves = append(trouves, exemple{ou, id + "@" + domaine, mdp})
			}
			for _, m := range motifChangement.FindAllStringSubmatch(ligne, -1) {
				id, mdp := sansGuillemets(m[1]), sansGuillemets(m[2])
				if estUnGabarit(mdp) || strings.HasPrefix(id, "<") {
					continue
				}
				trouves = append(trouves, exemple{ou, id, mdp})
			}
		}
	}
	return trouves
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	s := ""
	for ; n > 0; n /= 10 {
		s = string(rune('0'+n%10)) + s
	}
	return s
}

func TestLesMotsDePasseDExempleSontAcceptes(t *testing.T) {
	exemples := exemplesDeLaDocumentation(t)

	// Garde-fou : si l'extraction ne trouve plus rien (motif cassé, pages
	// déplacées), ce test passerait sans rien vérifier.
	if len(exemples) < 8 {
		t.Fatalf("seulement %d exemple(s) trouvé(s) : l'extraction est cassée, "+
			"le test ne vérifie plus rien", len(exemples))
	}

	for _, e := range exemples {
		exigences := ExigencesPour(dbauthpolicy.MinLengthDefaut, e.compte)
		if manques := Controler(exigences, e.motDePasse); len(manques) > 0 {
			t.Errorf("%s : le mot de passe d'exemple de %s serait REFUSÉ (%s) — "+
				"le lecteur qui le recopie échoue", e.ou, e.compte, strings.Join(manques, " ; "))
		}
	}
}

// Les gabarits sont bien écartés, et seulement eux.
func TestLExtractionEcarteLaSyntaxeEtGardeLesExemples(t *testing.T) {
	cas := map[string]bool{ // ligne -> un exemple attendu
		"create -u <identifiant> <domaine> <motdepasse> <jj/mm/aaaa>":     false,
		"create -u username domain password birthdate":                    false,
		"`update -u vaultaire -p <nouveau>`":                              false,
		"vlt update -u <autre> -p …":                                      false,
		"vlt create -u alice.martin infra.acme.lan 'Long-Exemple-42' 1/1": true,
		`vlt update -u bob -p "une phrase de passe"`:                      true,
		"vlt update -u svc --permanent -p 'Long-Exemple-42'":              true,
		"create -u alice company.com secret123 06/02/1992":                true,
	}
	for ligne, attendu := range cas {
		trouve := false
		for _, m := range motifCreation.FindAllStringSubmatch(ligne, -1) {
			if !estUnGabarit(sansGuillemets(m[3])) && !strings.HasPrefix(m[1], "<") {
				trouve = true
			}
		}
		for _, m := range motifChangement.FindAllStringSubmatch(ligne, -1) {
			if !estUnGabarit(sansGuillemets(m[2])) && !strings.HasPrefix(m[1], "<") {
				trouve = true
			}
		}
		if trouve != attendu {
			t.Errorf("%q : exemple trouvé = %v, attendu %v", ligne, trouve, attendu)
		}
	}
}
