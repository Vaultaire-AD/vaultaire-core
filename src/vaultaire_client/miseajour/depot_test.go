package miseajour

import (
	"errors"
	"testing"

	"vaultaire_client/config"
)

func TestBases(t *testing.T) {
	b, err := Bases([]string{"nexus1.acme.lan:8843", " ", "nexus2.acme.lan:8843"}, "https://miroir.lan")
	if err != nil || len(b) != 2 || b[0].URL != "https://nexus1.acme.lan:8843" || b[0].Source != SourceCluster {
		t.Fatalf("annoncés : %+v, %v", b, err)
	}
	// Le repli ne passe jamais devant ce que le cluster annonce…
	for _, x := range b {
		if x.Source == SourceRepli {
			t.Error("le repli s'ajoute aux dépôts annoncés")
		}
	}
	// … et sert quand il n'annonce rien.
	b, err = Bases(nil, "https://miroir.lan:8843/")
	if err != nil || len(b) != 1 || b[0].URL != "https://miroir.lan:8843" || b[0].Source != SourceRepli {
		t.Fatalf("repli : %+v, %v", b, err)
	}
	if _, err := Bases(nil, ""); err == nil {
		t.Error("ni cluster ni repli : pas d'erreur")
	}
}

func TestNormaliserBase(t *testing.T) {
	for brute, attendu := range map[string]string{
		"https://nexus.lan:8843":  "https://nexus.lan:8843",
		"https://nexus.lan:8843/": "https://nexus.lan:8843",
		"http://10.0.0.5:8843":    "http://10.0.0.5:8843",
	} {
		if got, err := NormaliserBase(brute); err != nil || got != attendu {
			t.Errorf("%s : %q %v", brute, got, err)
		}
	}
	for _, mauvaise := range []string{
		"nexus.lan:8843", "ftp://nexus.lan", "https://", "https://u:p@nexus.lan",
		"https://nexus.lan/repo/vaultaire/releases", "https://nexus.lan/?x=1",
	} {
		if _, err := NormaliserBase(mauvaise); err == nil {
			t.Errorf("%s : acceptée", mauvaise)
		}
	}
}

// Les URL doivent être celles que Nexus sert (files/releases.go, server.go)
// et les noms ceux que release.yaml et le core produisent (paquetagent).
func TestURLFichier(t *testing.T) {
	base := "https://nexus.lan:8843"
	if got := URLFichier(base, "", "2.3.0", NomSignature("2.3.0", "rocky")); got !=
		"https://nexus.lan:8843/repo/vaultaire/releases/download/v2.3.0/"+
			"vaultaire_client-v2.3.0-linux-amd64.tar.gz.rocky.manifest.sig" {
		t.Errorf("%s", got)
	}
	if got := URLFichier(base+"/", "site", "v2.3.0", NomArchive("2.3.0")); got !=
		"https://nexus.lan:8843/repo/vaultaire/site/download/v2.3.0/vaultaire_client-v2.3.0-linux-amd64.tar.gz" {
		t.Errorf("%s", got)
	}
}

func TestDepotsRetombeSurLeRepli(t *testing.T) {
	avant := demanderNexus
	t.Cleanup(func() { demanderNexus = avant })
	demanderNexus = func(func() string) ([]string, error) { return nil, errors.New("core muet") }

	sauve := config.Configuration
	t.Cleanup(func() { config.Configuration = sauve })
	config.Configuration.UpdateRepository = "https://miroir.lan"

	b, err := Depots(func() string { return "CLE" })
	if err != nil || len(b) != 1 || b[0].Source != SourceRepli {
		t.Fatalf("%+v, %v", b, err)
	}
}
