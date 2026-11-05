package commandcreate

import (
	"strings"
	"testing"
)

// create -u … --permanent (TO-DO 144) : retiré avant la lecture des positions.
func TestExtrairePermanent(t *testing.T) {
	reste, ok := ExtrairePermanent([]string{"svc", "svc.acme.lan", "Ancre-Violon-Galet-91", "01/01/2000", "--permanent"})
	if !ok || strings.Join(reste, " ") != "svc svc.acme.lan Ancre-Violon-Galet-91 01/01/2000" {
		t.Fatalf("%v %v", reste, ok)
	}
	// Placé au milieu, il ne décale pas les positions : sinon il deviendrait le
	// prénom, et la date le nom.
	reste, ok = ExtrairePermanent([]string{"svc", "--permanent", "svc.acme.lan", "Ancre-Violon-Galet-91", "01/01/2000"})
	if !ok || reste[1] != "svc.acme.lan" || len(reste) != 4 {
		t.Fatalf("%v %v", reste, ok)
	}
	if _, ok := ExtrairePermanent([]string{"alice", "acme.lan", "Lune-Orange-Velo-42", "14/03/1990"}); ok {
		t.Fatal("sans drapeau, un compte provisoire — le défaut ne doit pas bouger")
	}
}
