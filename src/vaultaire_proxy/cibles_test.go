package main

import (
	"strings"
	"testing"
)

// avecPort : les cores appris par leur adresse Ducky, joints sur un autre port.
func TestAvecPortRemplaceEtDedoublonne(t *testing.T) {
	got := avecPort([]string{"10.0.0.1:6666", "[2001:db8::1]:6666", "10.0.0.1:7666", "pas-une-adresse"}, 636)
	if strings.Join(got, ",") != "10.0.0.1:636,[2001:db8::1]:636" {
		t.Fatalf("cibles = %v : le port LDAPS doit remplacer le port Ducky, une même machine une seule fois", got)
	}
}
