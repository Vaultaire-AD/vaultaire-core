package clusterlink

import (
	"errors"
	"io"
	"log/slog"
	"strings"
	"testing"
	"time"

	"duckynetworkclient/V1/duckynetwork/storage"

	"vaultaire_nexus/internal/auth"
)

func TestCorrelationParRef(t *testing.T) {
	l := &Link{log: slog.New(slog.NewTextHandler(io.Discard, nil))}
	refA, chA := l.corr.ouvrir("alice")
	refB, chB := l.corr.ouvrir("bob")
	if refA == refB || len(refA) != 24 {
		t.Fatalf("refs : %q %q", refA, refB)
	}
	// Réponses dans le désordre : chacune va à sa demande.
	l.handle08(storage.Trames_struct_client{Message_Order: []string{"08", "02"},
		Content: "ref:" + refB + "\nuser:bob\ngroups:\nrights:read:nexus\nttl:300"}, nil)
	l.handle08(storage.Trames_struct_client{Message_Order: []string{"08", "03"},
		Content: "ref:" + refA + "\ncode:mfa_required\nreason:code requis"}, nil)
	a, b := <-chA, <-chB
	if a.code != "08_03" || a.champs["code"] != "mfa_required" {
		t.Errorf("A : %+v", a)
	}
	if b.code != "08_02" || b.champs["user"] != "bob" {
		t.Errorf("B : %+v", b)
	}
	// Une réponse sans demande, ou déjà livrée, est ignorée sans bloquer.
	done := make(chan struct{})
	go func() {
		l.handle08(storage.Trames_struct_client{Message_Order: []string{"08", "02"}, Content: "ref:" + refA}, nil)
		l.handle08(storage.Trames_struct_client{Message_Order: []string{"08", "02"}, Content: "ref:inconnu"}, nil)
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("une réponse orpheline bloque la réception")
	}
}

func TestIdentiteVerifieLeCompte(t *testing.T) {
	r := reponse{code: "08_02", champs: lireChamps("ref:x\nuser:alice\nname:Alice M\ngroups:Dev@dev.lan, Infra@infra.lan\nrights:read:nexus,write:nexus")}
	id, err := identite(r, "ALICE@dev.lan")
	if err != nil || id.Name != "Alice M" || len(id.Groups) != 2 || strings.Join(id.Rights, ",") != "read:nexus,write:nexus" {
		t.Fatalf("%v %+v", err, id)
	}
	if _, err := identite(r, "bob"); !errors.Is(err, auth.ErrUnavailable) {
		t.Errorf("réponse pour un autre compte acceptée : %v", err)
	}
	// Un nom affiché contenant « : » garde la suite.
	if lireChamps("name:A: B")["name"] != "A: B" {
		t.Error("valeur tronquée au second deux-points")
	}
}

func TestCodesDErreur(t *testing.T) {
	cas := map[string]error{
		"bad_credentials":     auth.ErrBadCredentials,
		"mfa_required":        auth.ErrMFARequired,
		"mfa_invalid":         auth.ErrMFAInvalid,
		"mfa_enroll_required": auth.ErrMFAEnroll,
		"expired":             auth.ErrExpired,
		"locked":              auth.ErrLocked,
		"revoked":             auth.ErrRevoked,
		"deleted":             auth.ErrDeleted,
		"unknown":             auth.ErrUnknown,
		"denied":              auth.ErrDenied,
		"unavailable":         auth.ErrUnavailable,
		"code_du_futur":       auth.ErrUnavailable,
	}
	for code, want := range cas {
		if got := erreurDe(code, "r"); !errors.Is(got, want) {
			t.Errorf("%s → %v, attendu %v", code, got, want)
		}
	}
}

func TestSansRaccordementIndisponible(t *testing.T) {
	var l *Link
	if l.connecte() {
		t.Error("lien nil considéré comme connecté")
	}
	l2 := &Link{timeout: time.Second}
	l2.set("échec", "pas de core")
	if _, err := l2.VerifyUser("alice", "x", "", ""); !errors.Is(err, auth.ErrUnavailable) {
		t.Errorf("%v", err)
	}
	if _, err := l2.VerifyUser("alice", "x\ny", "", ""); !errors.Is(err, auth.ErrBadCredentials) {
		t.Errorf("saut de ligne accepté : %v", err)
	}
}
