package dnsdatabase

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"regexp"
	"strings"
	"testing"
)

// Le nom de table d'une zone (TO-DO 105).
//
// # Ce que ces tests gardent
//
// Le nom de zone devient un nom de table, inséré dans des requêtes SQL. Il y
// entrait sans validation ni citation, depuis l'administration ET depuis les
// requêtes DNS reçues du réseau. Deux promesses :
//
//   - seul un nom fait de lettres, chiffres, tirets et points passe ;
//   - aucune requête du paquet n'insère un nom de table sans être passée par
//     identifiantTable — y compris une requête ajoutée demain.

func TestUnNomDeZoneOrdinairePasse(t *testing.T) {
	cas := map[string]string{
		"acme.lan":        "zone_acme_lan",
		"infra.acme.lan":  "zone_infra_acme_lan",
		"mon-site.fr":     "zone_mon-site_fr",
		"a.b.c.d.e":       "zone_a_b_c_d_e",
		"10.in-addr.arpa": "zone_10_in-addr_arpa",
		"Acme.lan":        "zone_Acme_lan",
	}
	for zone, attendu := range cas {
		got, err := NomDeTable(zone)
		if err != nil || got != attendu {
			t.Errorf("NomDeTable(%q) = %q, %v ; attendu %q", zone, got, err, attendu)
		}
	}
}

func TestToutCeQuiNEstPasUnNomDeZoneEstRefuse(t *testing.T) {
	// Pas des charges utiles : des familles de caractères qui n'ont rien à
	// faire dans un nom de zone. La liste blanche doit les refuser toutes,
	// sans qu'aucune ait été prévue une à une.
	mauvais := []string{
		"", ".", "acme..lan", ".acme.lan", "acme.lan.", "-acme.lan", "acme-.lan",
		"ac me.lan", "acme.lan\n", "acme\tlan",
		"acme`lan", "acme,lan", "acme'lan", "acme\"lan", "acme;lan",
		"acme(lan)", "acme/lan", "acme\\lan", "acme*lan", "acme_lan",
		"acmé.lan", "acme\x00lan",
		strings.Repeat("a", 60),
	}
	for _, zone := range mauvais {
		if _, err := NomDeTable(zone); err == nil {
			t.Errorf("nom de zone %q accepté : il deviendrait un nom de table", zone)
		}
	}
}

func TestLeNomRelEnBaseEstReverifie(t *testing.T) {
	// Une ligne de dns_zones écrite avant ce correctif peut porter n'importe
	// quoi : elle ne doit entrer dans aucune requête.
	for _, nom := range []string{"zone_acme_lan`", "users", "zone_", "zone_a,b", "zone_a b"} {
		if _, err := identifiantTable(nom); err == nil {
			t.Errorf("nom de table %q accepté à l'usage", nom)
		}
	}
	got, err := identifiantTable("zone_acme_lan")
	if err != nil || got != "`zone_acme_lan`" {
		t.Fatalf("identifiantTable = %q, %v : un nom valide doit être cité", got, err)
	}
}

// sqlAvecTable reconnaît un littéral SQL qui insère un nom de table : par %s,
// ou par concaténation (« FROM ` + table »).
var sqlAvecTable = regexp.MustCompile(`(?i)\b(FROM|INTO|TABLE|EXISTS|UPDATE)\s+(%s|$)`)

// TestAucuneRequeteNeContourneLaCitation.
//
// La correction ne tient que si TOUTES les requêtes passent par
// identifiantTable. Les douze d'aujourd'hui y passent ; ce test relit les
// sources pour qu'une treizième, écrite demain d'après un ancien fichier, ne
// rouvre pas le défaut sans que personne le voie.
func TestAucuneRequeteNeContourneLaCitation(t *testing.T) {
	entrees, err := os.ReadDir(".")
	if err != nil {
		t.Fatal(err)
	}
	fset := token.NewFileSet()
	verifiees := 0
	for _, e := range entrees {
		nom := e.Name()
		if !strings.HasSuffix(nom, ".go") || strings.HasSuffix(nom, "_test.go") || nom == "nom_de_table.go" {
			continue
		}
		f, err := parser.ParseFile(fset, nom, nil, 0)
		if err != nil {
			t.Fatal(err)
		}
		for _, d := range f.Decls {
			fn, ok := d.(*ast.FuncDecl)
			if !ok || fn.Body == nil {
				continue
			}
			insere, protege := false, false
			ast.Inspect(fn.Body, func(n ast.Node) bool {
				switch x := n.(type) {
				case *ast.BasicLit:
					if x.Kind == token.STRING && sqlAvecTable.MatchString(x.Value) {
						insere = true
					}
				case *ast.CallExpr:
					if id, ok := x.Fun.(*ast.Ident); ok &&
						(id.Name == "identifiantTable" || id.Name == "tableDeZone") {
						protege = true
					}
				}
				return true
			})
			if insere {
				verifiees++
				if !protege {
					t.Errorf("%s : %s insère un nom de table dans une requête sans passer par "+
						"identifiantTable — le nom de zone y entrerait sans validation ni citation",
						nom, fn.Name.Name)
				}
			}
		}
	}
	if verifiees < 8 {
		t.Fatalf("%d fonction(s) reconnue(s) seulement : le motif ne voit plus les requêtes, "+
			"et ce test ne vérifierait rien", verifiees)
	}
}
