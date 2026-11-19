package commandcreate

import (
	"reflect"
	"testing"
)

func TestExtraireEmail(t *testing.T) {
	args, e, err := ExtraireEmail([]string{"lea", "acme.lan", "--email", "lea@acme.fr", "pw", "01/01/1990"})
	if err != nil || e != "lea@acme.fr" || !reflect.DeepEqual(args, []string{"lea", "acme.lan", "pw", "01/01/1990"}) {
		t.Fatalf("ExtraireEmail = %v %q %v", args, e, err)
	}
	if _, e, _ := ExtraireEmail([]string{"lea", "d", "pw"}); e != "" {
		t.Fatalf("sans --email : %q", e)
	}
	for _, mauvais := range [][]string{
		{"lea", "--email"},
		{"lea", "--email", "-g", "x"},
		{"lea", "--email", "a@b.fr", "--email", "c@d.fr"},
	} {
		if _, _, err := ExtraireEmail(mauvais); err == nil {
			t.Errorf("ExtraireEmail(%v) : refus attendu", mauvais)
		}
	}
}
