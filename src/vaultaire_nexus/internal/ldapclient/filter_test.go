package ldapclient

import "testing"

func TestCompileFilter(t *testing.T) {
	ok := []string{
		"(uid=alice)",
		"(objectClass=*)",
		"(&(objectClass=inetOrgPerson)(uid=alice))",
		"(|(uid=a)(uid=b)(!(uid=c)))",
		"(uid=" + EscapeFilter("a*)(uid=*") + ")",
	}
	for _, f := range ok {
		if _, err := CompileFilter(f); err != nil {
			t.Errorf("%s : %v", f, err)
		}
	}
	ko := []string{"uid=alice", "(uid=al*)", "(uid>=3)", "(&(uid=a)", "(uid=a))", `(uid=\4)`}
	for _, f := range ko {
		if _, err := CompileFilter(f); err == nil {
			t.Errorf("%s accepté", f)
		}
	}
}

func TestEscape(t *testing.T) {
	if got := EscapeFilter("a*b(c)d\\"); got != `a\2ab\28c\29d\5c` {
		t.Errorf("EscapeFilter : %s", got)
	}
	if got := EscapeDN("Dupont, Jean"); got != `Dupont\, Jean` {
		t.Errorf("EscapeDN : %s", got)
	}
}
