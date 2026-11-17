package commandcreate

import (
	"strings"
	"testing"
)

func TestExtraireGroupe(t *testing.T) {
	args, g, err := ExtraireGroupe([]string{"bob", "users.admin.local", "-g", "admin-users", "pw", "01/01/1990"})
	if err != nil || g != "admin-users" || strings.Join(args, " ") != "bob users.admin.local pw 01/01/1990" {
		t.Fatalf("args=%v groupe=%q err=%v", args, g, err)
	}
	if _, g, err := ExtraireGroupe([]string{"bob", "d", "pw", "--group", "x"}); err != nil || g != "x" {
		t.Fatalf("--group : %q %v", g, err)
	}
	if _, g, _ := ExtraireGroupe([]string{"bob", "d", "pw"}); g != "" {
		t.Fatal("groupe inventé")
	}
	for _, mauvais := range [][]string{
		{"bob", "d", "-g"},
		{"bob", "d", "-g", "--permanent"},
		{"bob", "-g", "a", "-g", "b"},
	} {
		if _, _, err := ExtraireGroupe(mauvais); err == nil {
			t.Errorf("%v accepté", mauvais)
		}
	}
}
