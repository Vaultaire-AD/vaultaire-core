package newmodule

import (
	"testing"
	"time"

	ldapstorage "vaultaire/core/ldap/LDAP_Storage"
)

// TestEffectiveSizeLimit : la borne serveur ne peut être que RÉDUITE par le client.
//
// sizeLimit vaut 0 pour « sans limite » — ce qu'envoie tout client hostile. La
// borne serveur est donc la seule qui tienne face à quelqu'un qui ne coopère pas.
func TestEffectiveSizeLimit(t *testing.T) {
	original := ldapstorage.MaxSearchEntries
	defer func() { ldapstorage.MaxSearchEntries = original }()
	ldapstorage.MaxSearchEntries = 1000

	cas := []struct {
		demandé, attendu int
		pourquoi         string
	}{
		{0, 1000, "0 signifie « sans limite » : la borne serveur s'applique"},
		{500, 500, "une demande plus stricte est honorée"},
		{5000, 1000, "une demande plus large est ramenée à la borne"},
		{1000, 1000, "égalité"},
		{-1, 1000, "valeur négative : la borne s'applique"},
	}
	for _, c := range cas {
		if got := effectiveSizeLimit(c.demandé); got != c.attendu {
			t.Errorf("effectiveSizeLimit(%d) = %d, attendu %d — %s",
				c.demandé, got, c.attendu, c.pourquoi)
		}
	}
}

// TestEffectiveTimeLimit : même règle pour le temps.
func TestEffectiveTimeLimit(t *testing.T) {
	original := ldapstorage.MaxSearchDurationSeconds
	defer func() { ldapstorage.MaxSearchDurationSeconds = original }()
	ldapstorage.MaxSearchDurationSeconds = 30

	cas := []struct {
		demandé int
		attendu time.Duration
	}{
		{0, 30 * time.Second},
		{10, 10 * time.Second},
		{120, 30 * time.Second},
		{-5, 30 * time.Second},
	}
	for _, c := range cas {
		if got := effectiveTimeLimit(c.demandé); got != c.attendu {
			t.Errorf("effectiveTimeLimit(%d) = %s, attendu %s", c.demandé, got, c.attendu)
		}
	}
}

// TestBornesDesactivables : une borne serveur à 0 rend la main au client.
//
// Un exploitant qui veut retirer la limite doit pouvoir le faire ; c'est un
// choix, pas un défaut.
func TestBornesDesactivables(t *testing.T) {
	origSize := ldapstorage.MaxSearchEntries
	origTime := ldapstorage.MaxSearchDurationSeconds
	defer func() {
		ldapstorage.MaxSearchEntries = origSize
		ldapstorage.MaxSearchDurationSeconds = origTime
	}()
	ldapstorage.MaxSearchEntries = 0
	ldapstorage.MaxSearchDurationSeconds = 0

	if got := effectiveSizeLimit(0); got != 0 {
		t.Errorf("borne désactivée + client sans limite : %d, attendu 0 (illimité)", got)
	}
	if got := effectiveSizeLimit(50); got != 50 {
		t.Errorf("borne désactivée + client à 50 : %d, attendu 50", got)
	}
	if got := effectiveTimeLimit(0); got != 0 {
		t.Errorf("délai désactivé : %s, attendu 0", got)
	}
}
