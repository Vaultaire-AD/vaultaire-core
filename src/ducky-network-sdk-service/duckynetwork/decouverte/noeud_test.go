package decouverte

import (
	"testing"
	"time"

	"duckynetworkclient/V1/duckynetwork/storage"
)

// Le nœud ne doit se croire enregistré que sur un accusé POSITIF du core
// (TO-DO 73). Avant, la trame émise suffisait : un proxy refusé par le core
// journalisait « enregistré », battait dans le vide, et n'était ni distribué aux
// agents ni exempté du plafond par adresse du core.

func accuseRecu(t *testing.T, contenu string) (bool, string, bool) {
	t.Helper()
	attente := armerAccuse()
	HandleTrame(storage.Trames_struct_client{Message_Order: []string{"04", "02"}, Content: contenu}, nil)
	return attendreAccuse(attente, 2*time.Second)
}

func TestUnAccuseOkVautEnregistrement(t *testing.T) {
	ok, _, recu := accuseRecu(t, "ok\nproxy1")
	if !recu || !ok {
		t.Fatalf("accusé « ok » : reçu=%v accepté=%v", recu, ok)
	}
}

func TestUnRefusNeVautPasEnregistrement(t *testing.T) {
	ok, motif, recu := accuseRecu(t, "refus\nce nom de nœud appartient déjà à un autre client")
	if !recu {
		t.Fatal("le refus n'a pas été signalé à l'attente")
	}
	if ok {
		t.Fatal("refus du core pris pour un enregistrement — c'est le défaut du point 73")
	}
	if motif == "" {
		t.Error("refus sans motif : le journal ne dirait pas quoi corriger")
	}
}

// Un accusé réduit à « ok », ou même vide, vaut acceptation : les cores
// antérieurs au point 73 ne refusaient jamais par ce canal.
func TestUnAccuseSansContenuVautAcceptation(t *testing.T) {
	if ok, _, recu := accuseRecu(t, ""); !recu || !ok {
		t.Fatalf("accusé vide : reçu=%v accepté=%v", recu, ok)
	}
}

// Un core ANTÉRIEUR au point 73 reste muet sur un refus : l'attente doit
// expirer, pour que le nœud retente au battement suivant au lieu de se croire
// enregistré.
func TestLeSilenceDuCoreExpire(t *testing.T) {
	attente := armerAccuse()
	debut := time.Now()
	ok, _, recu := attendreAccuse(attente, 150*time.Millisecond)
	if recu || ok {
		t.Fatal("sans accusé, le nœud ne doit pas se considérer enregistré")
	}
	if time.Since(debut) > 2*time.Second {
		t.Fatalf("attente de %s : le délai ne borne rien", time.Since(debut))
	}
}

// Un accusé qui arrive alors que personne ne l'attend ne doit rien bloquer :
// c'est la goroutine de LECTURE du SDK qui y passe.
func TestUnAccuseSansAttenteNeBloquePas(t *testing.T) {
	desarmerAccuse()
	fini := make(chan struct{})
	go func() {
		HandleTrame(storage.Trames_struct_client{Message_Order: []string{"04", "02"}, Content: "ok"}, nil)
		close(fini)
	}()
	select {
	case <-fini:
	case <-time.After(2 * time.Second):
		t.Fatal("la réception d'un accusé non attendu bloque la lecture")
	}
}
