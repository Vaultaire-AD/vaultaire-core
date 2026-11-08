package dbschema

import (
	"strings"
	"testing"
)

// Une base neuve (CREATE TABLE) et une base complétée (MODIFY) doivent porter
// des colonnes de version identiques — même raison que pour colonnesAjoutees.
func TestLesVersionsSontDefiniesALIdentique(t *testing.T) {
	schema := lireSchema(t)
	for _, c := range colonnesVersion {
		if !strings.Contains(schema, c.Nom+" "+c.Definition) {
			t.Errorf("le CREATE TABLE ne contient pas %q", c.Nom+" "+c.Definition)
		}
	}
}

// La version la plus longue qu'un build de release peut produire tient.
func TestUneVersionDeReleaseTient(t *testing.T) {
	pire := "2.3.0+" + strings.Repeat("f", 40) + " (2026-11-06T00:19:15+01:00)"
	if len(pire) > LargeurVersion {
		t.Fatalf("%d caractères pour une colonne de %d", len(pire), LargeurVersion)
	}
}
