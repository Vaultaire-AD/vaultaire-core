package decouverte

import (
	"strings"
	"testing"
	"time"

	"duckynetworkclient/V1/duckynetwork/enligne"
	"duckynetworkclient/V1/duckynetwork/storage"
)

func TestLa0419SeLit(t *testing.T) {
	cfg, err := AnalyserConfigurationRelais("core\n7\n{\"relais\":[]}")
	if err != nil || cfg.Mode != ModeCore || cfg.Revision != 7 || cfg.Document != `{"relais":[]}` {
		t.Fatalf("mode core : %+v, %v", cfg, err)
	}
	if cfg, err := AnalyserConfigurationRelais("fichier\n0"); err != nil || cfg.Mode != ModeFichier {
		t.Fatalf("mode fichier : %+v, %v", cfg, err)
	}
	if cfg, err := AnalyserConfigurationRelais(" Inchange "); err != nil || cfg.Mode != ModeInchange {
		t.Fatalf("mode inchangé : %+v, %v", cfg, err)
	}
	for _, mauvais := range []string{"", "core", "core\n7", "core\nsept\n{}", "core\n0\n{}", "autre\n1\n{}"} {
		if _, err := AnalyserConfigurationRelais(mauvais); err == nil {
			t.Errorf("04_19 %q acceptée", mauvais)
		}
	}
}

// Le compte rendu tient sur une ligne, quoi qu'on lui donne : la trame est
// découpée par lignes.
func TestLeCompteRenduTientSurUneLigne(t *testing.T) {
	trame := ConstruireEtatRelais("CLE", "proxy-1", "{\n  \"revision\": 3\r\n}")
	lignes := strings.Split(trame, "\n")
	if len(lignes) != 6 || lignes[0] != "04_18" || lignes[4] != "proxy-1" {
		t.Fatalf("trame 04_18 inattendue : %q", lignes)
	}
}

// Rien n'est émis vers un core qui n'a pas annoncé la capacité : il fermerait
// la connexion.
func TestLeCompteRenduNePartPasVersUnCoreQuiNeLeConnaitPas(t *testing.T) {
	var envoyees []string
	Configure(func(trame string) { envoyees = append(envoyees, trame) }, "proxy-1")
	t.Cleanup(func() { Configure(nil, ""); enligne.Apprendre("") })
	cle := func() string { return "CLE" }

	enligne.Apprendre("client_giveinformation") // core antérieur à la 2.2
	if EmettreEtatRelais(cle, "{}") || len(envoyees) != 0 {
		t.Fatalf("04_18 émise vers un core qui ne l'annonce pas : %q", envoyees)
	}

	enligne.Apprendre("client_giveinformation\nonline:2\ncapacites:relais")
	if !EmettreEtatRelais(cle, "{}") || len(envoyees) != 1 || !strings.HasPrefix(envoyees[0], "04_18\n") {
		t.Fatalf("04_18 non émise vers un core qui l'annonce : %q", envoyees)
	}
}

// Une 04_19 est remise à qui l'applique, hors du fil de lecture, et le mode
// « inchangé » ne dérange personne.
func TestLa0419EstRemiseAuProxy(t *testing.T) {
	recues := make(chan ConfigurationRelais, 4)
	SurConfigurationRelais(func(c ConfigurationRelais) { recues <- c })
	t.Cleanup(func() { SurConfigurationRelais(nil) })

	recevoir19 := func(contenu string) {
		HandleTrame(storage.Trames_struct_client{Message_Order: []string{"04", "19"}, Content: contenu}, nil)
	}

	recevoir19("inchange")
	recevoir19("core\n4\n{\"relais\":[{\"nom\":\"ducky\"}]}")
	select {
	case c := <-recues:
		if c.Mode != ModeCore || c.Revision != 4 {
			t.Fatalf("configuration remise : %+v", c)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("la 04_19 n'a pas été remise")
	}
	select {
	case c := <-recues:
		t.Fatalf("une seule remise attendue, reçu aussi %+v", c)
	case <-time.After(100 * time.Millisecond):
	}
}
