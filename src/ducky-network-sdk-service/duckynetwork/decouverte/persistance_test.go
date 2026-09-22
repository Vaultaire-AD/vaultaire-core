package decouverte

import "testing"

func TestSeulsLesNoeudsDeConfianceSontTransmis(t *testing.T) {
	ancien := empreintesDeConfiance
	defer func() { empreintesDeConfiance = ancien; SurNouvelleListe(nil) }()
	empreintesDeConfiance = func() ([]string, error) { return []string{"SHA256:a"}, nil }

	var recu []Noeud
	SurNouvelleListe(func(n []Noeud) { recu = n })
	notifier([]Noeud{
		{Hostname: "p1", IP: "10.0.0.5", Port: 6666, Role: "proxy", Empreinte: "SHA256:inconnue"},
		{Hostname: "c1", IP: "10.0.0.1", Port: 6666, Role: "core", Empreinte: "SHA256:a"},
	})
	// Le proxy est gardé : un core de confiance figure dans la liste, et le
	// proxy relaie ce core. Son empreinte à lui n'entre pas en compte.
	if len(recu) != 2 || recu[0].Hostname != "p1" || recu[1].Hostname != "c1" {
		t.Fatalf("reçu %+v", recu)
	}
	if DerniereReception().IsZero() {
		t.Fatal("heure de réception non notée")
	}
}

func TestSansConfianceRienNEstTransmis(t *testing.T) {
	ancien := empreintesDeConfiance
	defer func() { empreintesDeConfiance = ancien; SurNouvelleListe(nil) }()
	empreintesDeConfiance = func() ([]string, error) { return nil, nil }
	appele := false
	SurNouvelleListe(func([]Noeud) { appele = true })
	notifier([]Noeud{{Hostname: "c1", IP: "10.0.0.1", Port: 6666, Role: "core", Empreinte: "SHA256:a"}})
	if appele {
		t.Fatal("liste transmise sans liste de confiance (confiance au premier usage)")
	}
}

func TestUnProxySeulNEstPasPersiste(t *testing.T) {
	ancien := empreintesDeConfiance
	defer func() { empreintesDeConfiance = ancien }()
	empreintesDeConfiance = func() ([]string, error) { return []string{"SHA256:p"}, nil }
	// Même si l'empreinte du proxy figurait (par erreur) dans la liste de
	// confiance, sans core de confiance il n'est pas gardé.
	if got := NoeudsDeConfiance([]Noeud{{Hostname: "p1", Role: "proxy", Empreinte: "SHA256:p"}}); len(got) != 0 {
		t.Fatalf("%+v", got)
	}
}
