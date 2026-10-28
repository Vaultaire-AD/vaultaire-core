package candidate

import "testing"

// TO-DO 245 : hasSubordinates est OPÉRATIONNEL — demandé nommément ou par
// « + », jamais par « * », jamais sur « 1.1 ».
func TestHasSubordinatesEstOperationnel(t *testing.T) {
	u := UserEntry{BaseDN: "acme.lan"}
	u.User.Username = "alice"
	entrees := map[string]struct {
		e       interface{ GetAttributes([]string, bool) map[string][]string }
		attendu string
	}{
		"compte":  {u, "FALSE"},
		"groupe":  {GroupEntry{Name: "g", BaseDN: "acme.lan"}, "FALSE"},
		"OU":      {OUEntry{Name: "users", BaseDN: "acme.lan"}, "TRUE"},
		"domaine": {DomainEntry{DNName: "acme.lan"}, "TRUE"},
		"domaine sans enfant": {DomainEntry{DNName: "svc.acme.lan", Feuille: true}, "FALSE"},
	}
	for nom, c := range entrees {
		if _, la := c.e.GetAttributes([]string{"*"}, false)[AttrHasSubordinates]; la {
			t.Errorf("%s : hasSubordinates servi sur « * »", nom)
		}
		if n := len(c.e.GetAttributes([]string{"1.1"}, false)); n != 0 {
			t.Errorf("%s : %d attribut(s) servi(s) sur « 1.1 »", nom, n)
		}
		for _, demande := range [][]string{{"+"}, {"hasSubordinates"}} {
			v := c.e.GetAttributes(demande, false)[AttrHasSubordinates]
			if len(v) != 1 || v[0] != c.attendu {
				t.Errorf("%s, demandé %v : hasSubordinates = %v, attendu %s", nom, demande, v, c.attendu)
			}
		}
	}
}
