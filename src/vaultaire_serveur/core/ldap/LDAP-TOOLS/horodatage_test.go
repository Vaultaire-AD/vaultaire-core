package ldaptools

import "testing"

// Le point 126 tient à une conversion : la date que la base rend n'est pas celle
// que LDAP attend, et une date fausse est pire qu'une date absente sur ce
// chemin-là.

func TestUneDateSQLDevientUnGeneralizedTime(t *testing.T) {
	cas := map[string]string{
		"2026-03-15 12:00:00":        "20260315120000Z",
		"2026-03-15T12:00:00Z":       "20260315120000Z",
		"2026-03-15 12:00:00.123456": "20260315120000Z",
		"2026-03-15":                 "20260315000000Z",
		// Un décalage explicite est ramené à UTC : 12h00 à UTC+2 est 10h00 UTC.
		"2026-03-15T12:00:00+02:00": "20260315100000Z",
	}
	for sql, attendu := range cas {
		if obtenu := VersGeneralizedTime(sql); obtenu != attendu {
			t.Errorf("%q => %q, attendu %q", sql, obtenu, attendu)
		}
	}
}

// UNE DATE ILLISIBLE NE DEVIENT RIEN.
//
// Pas une date approchée, pas l'instant présent, pas le zéro de l'époque. Un
// attribut sans valeur n'existe pas en LDAP (RFC 4512 §2.5), et c'est le bon
// comportement ici : un client incrémental qui lit une date aberrante saute des
// entrées ou les relit toutes, sans qu'aucune erreur ne le dise.
func TestUneDateIllisibleNeDevientRien(t *testing.T) {
	for _, sql := range []string{"", "   ", "0000-00-00 00:00:00", "hier", "15/03/2026"} {
		if obtenu := VersGeneralizedTime(sql); obtenu != "" {
			t.Errorf("%q => %q, attendu une chaîne vide", sql, obtenu)
		}
	}
}

// Le résultat s'ordonne comme du texte : c'est toute la raison de ce format, et
// c'est ce dont dépend le filtre `>=` du point 119 sur une date.
func TestLOrdreDuTexteEstLOrdreDuTemps(t *testing.T) {
	avant := VersGeneralizedTime("2026-03-15 12:00:00")
	apres := VersGeneralizedTime("2026-03-15 12:00:01")
	if !(avant < apres) {
		t.Errorf("%q n'est pas avant %q dans l'ordre du texte", avant, apres)
	}
}
