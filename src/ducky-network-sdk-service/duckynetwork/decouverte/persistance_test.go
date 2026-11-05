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

// TO-DO 255 : le core est hors rotation, la liste ne porte que le proxy. Elle
// est arrivée sur une session vérifiée : le proxy est gardé.
func TestUnProxySeulEstPersisteSurUneMachineDeConfiance(t *testing.T) {
	ancien := empreintesDeConfiance
	defer func() { empreintesDeConfiance = ancien }()
	empreintesDeConfiance = func() ([]string, error) { return []string{"SHA256:core"}, nil }
	got := NoeudsDeConfiance([]Noeud{{Hostname: "p1", Role: "proxy", Empreinte: "SHA256:inconnue"}})
	if len(got) != 1 || got[0].Hostname != "p1" {
		t.Fatalf("%+v : un core hors rotation laissait l'agent sans issue", got)
	}
}

// Sans liste de confiance, même un proxy n'est pas gardé.
func TestUnProxyNEstPasPersisteEnConfianceAuPremierUsage(t *testing.T) {
	ancien := empreintesDeConfiance
	defer func() { empreintesDeConfiance = ancien }()
	empreintesDeConfiance = func() ([]string, error) { return nil, nil }
	if got := NoeudsDeConfiance([]Noeud{{Hostname: "p1", Role: "proxy"}}); len(got) != 0 {
		t.Fatalf("%+v", got)
	}
}

// Un CORE inconnu reste écarté : seule son empreinte le rend fiable.
func TestUnCoreInconnuResteEcarte(t *testing.T) {
	ancien := empreintesDeConfiance
	defer func() { empreintesDeConfiance = ancien }()
	empreintesDeConfiance = func() ([]string, error) { return []string{"SHA256:a"}, nil }
	got := NoeudsDeConfiance([]Noeud{
		{Hostname: "c2", Role: "core", Empreinte: "SHA256:inconnue"},
		{Hostname: "p1", Role: "proxy"},
	})
	if len(got) != 1 || got[0].Hostname != "p1" {
		t.Fatalf("%+v", got)
	}
}
