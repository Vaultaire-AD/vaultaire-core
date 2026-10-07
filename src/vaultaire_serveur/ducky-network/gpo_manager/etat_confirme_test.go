package gpomanager

import (
	"os"
	"strings"
	"testing"
)

// « Rien à faire » date la portée — TO-DO 166.
//
// La requête elle-même est éprouvée contre une base (db_gpo). Ce test tient le
// BRANCHEMENT : c'est en répondant 05_03 ou 05_07 que le core apprend qu'une
// machine est à jour, et un remaniement de serveScope qui laisserait tomber
// l'appel remettrait tout un parc stable « en retard » sans qu'aucun test de
// requête ne le voie.
func TestRienAFaireDateLaPortee(t *testing.T) {
	brut, err := os.ReadFile("handlers.go")
	if err != nil {
		t.Fatal(err)
	}
	source := string(brut)
	debut := strings.Index(source, "func serveScope(")
	if debut < 0 {
		t.Fatal("serveScope introuvable dans handlers.go")
	}
	corps := source[debut:]
	reponse := strings.Index(corps, "return replyUnchanged(")
	confirmation := strings.Index(corps, "dbgpo.ConfirmerEtat(")
	if reponse < 0 {
		t.Fatal("serveScope ne répond plus « rien à faire » par replyUnchanged")
	}
	if confirmation < 0 || confirmation > reponse {
		t.Fatal("serveScope répond « rien à faire » sans dater la portée : une machine dont la politique " +
			"ne change pas passera « en retard » au bout de trois cycles, et y restera")
	}
}
