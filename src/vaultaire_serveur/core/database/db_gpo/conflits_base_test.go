package dbgpo

import (
	"fmt"
	"testing"
	"time"
)

// TO-DO 222 : les conflits d'une portée, contre une VRAIE base
// (VAULTAIRE_TEST_DSN) — rangés, remplacés, effacés, et le changement dit.
func TestEnBaseLesConflitsSontRangesPuisEffaces(t *testing.T) {
	db := baseConformite(t)
	if _, err := db.Exec(tableConflitsDDL); err != nil {
		t.Fatal(err)
	}
	m := fmt.Sprint("PC-", time.Now().UnixNano())
	if ch, err := RangerConflits(db, m, "machine", "", ""); err != nil || ch {
		t.Fatalf("rien à effacer : %v %v", ch, err)
	}
	if ch, err := RangerConflits(db, m, "machine", "", "le service chronyd …"); err != nil || !ch {
		t.Fatalf("apparition : %v %v", ch, err)
	}
	if ch, err := RangerConflits(db, m, "machine", "", "le service chronyd …"); err != nil || ch {
		t.Fatalf("le même conflit n'est pas un changement : %v %v", ch, err)
	}
	if _, err := RangerConflits(db, m, "user", "alice@acme.lan", "la variable X …"); err != nil {
		t.Fatal(err)
	}
	c, err := ConflitsDeLaMachine(db, m)
	if err != nil || len(c) != 2 || c[0].Scope != "machine" || c[1].TargetUser != "alice@acme.lan" || c[0].SeenAt.IsZero() {
		t.Fatalf("%+v %v", c, err)
	}
	if ch, err := RangerConflits(db, m, "machine", "", ""); err != nil || !ch {
		t.Fatalf("disparition : %v %v", ch, err)
	}
	if c, _ := ConflitsDeLaMachine(db, m); len(c) != 1 {
		t.Fatalf("après effacement : %+v", c)
	}
}
