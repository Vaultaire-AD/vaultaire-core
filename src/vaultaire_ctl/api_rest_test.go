package main

import (
	"crypto/sha256"
	"encoding/hex"
	"testing"
)

// La chaîne signée par le client doit être EXACTEMENT celle que le serveur
// recompose (core/api/rest_auth.go). Le même cas est figé des deux côtés
// (TestChaineCanoniqueFigee, dans core/api/rest_test.go).
func TestChaineCanoniqueFigee(t *testing.T) {
	got := string(chaineCanoniqueREST("post", "/api/v1/users", "a=1", "alice", 1763300000, "n-1", []byte(`{"x":1}`)))
	somme := sha256.Sum256([]byte(`{"x":1}`))
	attendu := "VAULTAIRE-REST-1\nPOST\n/api/v1/users\na=1\nalice\n1763300000\nn-1\n" + hex.EncodeToString(somme[:])
	if got != attendu {
		t.Fatalf("chaîne\n%q\nattendu\n%q", got, attendu)
	}
}
