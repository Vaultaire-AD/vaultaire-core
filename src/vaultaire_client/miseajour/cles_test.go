package miseajour

import (
	"encoding/base64"
	"errors"
	"strings"
	"testing"
	"time"

	"duckynetworkclient/V1/duckynetwork/storage"

	"vaultaire_client/paquet"
)

func avecJeu(t *testing.T, n int, appliquer func(string, paquet.Enveloppe) (paquet.Jeu, error)) {
	t.Helper()
	avN, avA := numeroLocal, appliquerJeu
	t.Cleanup(func() { numeroLocal, appliquerJeu = avN, avA })
	numeroLocal = func() int { return n }
	appliquerJeu = appliquer
}

func reponseJeu(numero, corps, env string) storage.Trames_struct_client {
	return storage.Trames_struct_client{Message_Order: []string{"09", "10"}, SessionIntegritykey: "CLE",
		Content: numero + "\n" + base64.StdEncoding.EncodeToString([]byte(corps)) + "\n" +
			base64.StdEncoding.EncodeToString([]byte(env))}
}

const envTest = "vaultaire-pkg-sig-v1\nSHA256:abc\nAAAA\n"

func TestDemandeJeu(t *testing.T) {
	avecJeu(t, 3, nil)
	storage.Computeur_ID = "poste-1"
	l := strings.Split(DemandeJeu("CLE"), "\n")
	if len(l) != 6 || l[0] != "09_09" || l[2] != "CLE" || l[4] != "poste-1" || l[5] != "3" {
		t.Errorf("%q", l)
	}
}

// Un jeu appliqué : la réponse EST la demande suivante, avec le nouveau
// numéro — la machine remonte la chaîne et le déclare.
func TestUnJeuAppliqueRedemande(t *testing.T) {
	n := 1
	var recu string
	avecJeu(t, 1, func(corps string, _ paquet.Enveloppe) (paquet.Jeu, error) {
		recu, n = corps, 2
		return paquet.Jeu{Numero: 2}, nil
	})
	numeroLocal = func() int { return n }
	rep := HandleTrame(reponseJeu("2", "corps\n", envTest), nil)
	if recu != "corps\n" || !strings.HasPrefix(rep, "09_09\n") || !strings.HasSuffix(rep, "\n2") {
		t.Errorf("%q / %q", recu, rep)
	}
}

func TestUnJeuRefuseNeRedemandePas(t *testing.T) {
	avecJeu(t, 1, func(string, paquet.Enveloppe) (paquet.Jeu, error) {
		return paquet.Jeu{}, errors.New("signé par SHA256:x, clé inconnue de ce côté")
	})
	if rep := HandleTrame(reponseJeu("5", "corps\n", envTest), nil); rep != "" {
		t.Errorf("%q", rep)
	}
}

func TestAJourEtIllisible(t *testing.T) {
	appels := 0
	avecJeu(t, 1, func(string, paquet.Enveloppe) (paquet.Jeu, error) { appels++; return paquet.Jeu{}, nil })
	for _, c := range []string{"a_jour", "deux\nlignes", "2\n!!!\n!!!"} {
		if rep := HandleTrame(storage.Trames_struct_client{Message_Order: []string{"09", "10"}, Content: c}, nil); rep != "" {
			t.Errorf("%q : %q", c, rep)
		}
	}
	if appels != 0 {
		t.Error("une réponse illisible a été appliquée")
	}
}

func TestSuiviJeu(t *testing.T) {
	var s suiviJeu
	t0 := time.Date(2026, 10, 18, 16, 0, 0, 0, time.UTC)
	if s.doitDemander("", true, t0) || s.doitDemander("A", false, t0) {
		t.Error("demande sans session, ou vers un core qui ne sait pas")
	}
	if !s.doitDemander("A", true, t0) {
		t.Fatal("session neuve")
	}
	s.derniereCle, s.derniere = "A", t0
	if s.doitDemander("A", true, t0.Add(30*time.Minute)) {
		t.Error("redemande avant l'heure")
	}
	if !s.doitDemander("A", true, t0.Add(IntervalleJeuCles)) || !s.doitDemander("B", true, t0.Add(time.Minute)) {
		t.Error("ni l'heure ni la session neuve ne redemandent")
	}
}
