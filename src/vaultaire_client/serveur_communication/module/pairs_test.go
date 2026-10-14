package module

import (
	"net"
	"strings"
	"testing"
	"time"
)

// TO-DO 186 : un pair qui accepte la connexion sans répondre ne retient plus
// l'essai — l'agent passe au suivant dans sa borne.

// pairMuet accepte les connexions et ne dit jamais rien.
func pairMuet(t *testing.T) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			t.Cleanup(func() { c.Close() })
		}
	}()
	return ln.Addr().String()
}

// pairFerme rend une adresse sur laquelle personne n'écoute.
func pairFerme(t *testing.T) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	a := ln.Addr().String()
	ln.Close()
	return a
}

func bornesCourtes(t *testing.T, adresses []string) {
	t.Helper()
	ancC, ancP, ancA := DelaiConnexionPair, DelaiPoigneePair, adressesAEssayer
	DelaiConnexionPair, DelaiPoigneePair = 300*time.Millisecond, 400*time.Millisecond
	adressesAEssayer = func() []string { return adresses }
	t.Cleanup(func() { DelaiConnexionPair, DelaiPoigneePair, adressesAEssayer = ancC, ancP, ancA })
}

func TestUnPairMuetNeRetientPasLEssai(t *testing.T) {
	muet1, muet2 := pairMuet(t), pairMuet(t)
	bornesCourtes(t, []string{muet1, muet2})

	debut := time.Now()
	ds, err := EstablishDuckySession("vaultaire", "vaultaire")
	duree := time.Since(debut)

	if err == nil || ds != nil {
		t.Fatal("une session a été « établie » avec deux pairs muets")
	}
	// Deux pairs, 400 ms chacun : moins de 2 s, quand l'ancienne lecture sans
	// borne ne rendait jamais la main.
	if duree > 2*time.Second {
		t.Errorf("rendu en %s : la poignée de main n'est pas bornée", duree)
	}
	// Le SECOND pair a été essayé : c'est lui qui porte le dernier échec.
	if e := Etat(); !strings.Contains(e.DernierEchec, "tous les nœuds") && !strings.Contains(err.Error(), muet2) {
		t.Errorf("le second pair ne semble pas essayé : %v / %+v", err, e)
	}
	if !strings.Contains(err.Error(), muet2) {
		t.Errorf("l'erreur ne nomme pas le dernier pair essayé (%s) : %v", muet2, err)
	}
}

func TestUnPairFermeEtUnPairMuetSontPassesTousLesDeux(t *testing.T) {
	ferme, muet := pairFerme(t), pairMuet(t)
	bornesCourtes(t, []string{ferme, muet})

	debut := time.Now()
	_, err := EstablishDuckySession("vaultaire", "vaultaire")
	if err == nil {
		t.Fatal("aucune erreur")
	}
	if !strings.Contains(err.Error(), muet) {
		t.Errorf("le pair muet, second de la liste, n'a pas été atteint : %v", err)
	}
	if d := time.Since(debut); d > 2*time.Second {
		t.Errorf("rendu en %s", d)
	}
}
