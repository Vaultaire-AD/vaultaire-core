package main

import "testing"

func TestSeulsUnNomOuUneAdresseSontAcceptes(t *testing.T) {
	bons := []string{"vaultaire-mariadb", "db.acme.lan", "mariadb.vaultaire.svc.cluster.local", "10.0.0.5", "::1"}
	mauvais := []string{"", "http://db", "db:3306", "db/x", "-db", "db..lan", "a b", "db;rm"}
	for _, h := range bons {
		if !hoteValide(h) {
			t.Errorf("%q refusé", h)
		}
	}
	for _, h := range mauvais {
		if hoteValide(h) {
			t.Errorf("%q accepté", h)
		}
	}
}
