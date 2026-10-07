package client

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"vaultaire/core/storage"
	"vaultaire/ducky-network/sendmessage"
)

// contenuVuDuPoste rend ce qu'un poste lit comme CONTENU d'une trame du core :
// tout ce qui suit le code, la destination et la clé d'intégrité (voir
// ParseTrames dans le SDK).
func contenuVuDuPoste(t *testing.T, trame string) []string {
	t.Helper()
	lignes := strings.Split(trame, "\n")
	if len(lignes) < 3 {
		t.Fatalf("trame de %d ligne(s) : %q", len(lignes), trame)
	}
	return strings.Split(strings.Join(lignes[3:], "\n"), "\n")
}

// UNE forme pour tous les refus — TO-DO 159.
func TestUnRefusALaFormeQueLePosteLit(t *testing.T) {
	for _, motif := range []string{
		MotifIdentifiants, MotifMotDePasseExpire, MotifDefiImpossible,
		MotifNonAuthentifie, MotifErreurInterne, MotifMachineInterdite, RefusClesTropLourdes,
	} {
		trame := Refus("CLE", "alice", motif)
		lignes := strings.Split(trame, "\n")
		if len(lignes) != 5 {
			t.Fatalf("%q : %d ligne(s), attendu 5 — %q", motif, len(lignes), lignes)
		}
		if lignes[0] != "02_07" || lignes[1] != "serveur_central" || lignes[2] != "CLE" {
			t.Errorf("%q : en-tête %q — le code, la DESTINATION, puis la clé", motif, lignes[:3])
		}
		if lignes[3] != "alice" || lignes[4] != motif {
			t.Errorf("%q : contenu %q — le compte, puis le motif", motif, lignes[3:])
		}
		if !sendmessage.TientDansUneTrame(trame) {
			t.Errorf("%q : le refus ne tient pas dans une trame", motif)
		}
		if !EstUnRefus(trame) {
			t.Errorf("%q : le refus n'est pas reconnu comme tel", motif)
		}
	}
}

// LE DÉFAUT, vu du côté qui paniquait : un agent antérieur à la 2.3 lit
// lines[0] et lines[1] du contenu sans rien vérifier. Tout refus doit donc
// porter au moins deux lignes de contenu, quoi qu'on lui passe.
func TestUnAgentAnterieurLitToutRefusSansSortirDuTableau(t *testing.T) {
	for _, c := range []struct{ compte, motif string }{
		{"alice", MotifIdentifiants},
		{"", MotifNonAuthentifie},    // compte inconnu : un défi expiré
		{"   ", MotifNonAuthentifie}, // des blancs ne font pas un compte
		{"alice", ""},                // motif oublié par un appelant
		{"ali\nce", "mo\ntif"},       // un retour à la ligne ne doit pas ajouter de champ
		{"alice\r\n", "motif\r\n"},
	} {
		contenu := contenuVuDuPoste(t, Refus("CLE", c.compte, c.motif))
		if len(contenu) != 2 {
			t.Errorf("Refus(%q, %q) : %d ligne(s) de contenu %q, attendu exactement 2",
				c.compte, c.motif, len(contenu), contenu)
			continue
		}
		if strings.TrimSpace(contenu[0]) == "" || strings.TrimSpace(contenu[1]) == "" {
			t.Errorf("Refus(%q, %q) : une ligne de contenu est vide %q — le poste la perdrait au découpage",
				c.compte, c.motif, contenu)
		}
	}
	if got := contenuVuDuPoste(t, Refus("CLE", "", MotifNonAuthentifie))[0]; got != CompteNonPrecise {
		t.Errorf("compte inconnu rendu %q, attendu %q", got, CompteNonPrecise)
	}
}

// Sentinelle : plus aucun refus n'est composé à la main dans ce paquet. C'est
// ainsi qu'il y en avait onze, de trois formes.
func TestAucunRefusNEstComposeALaMain(t *testing.T) {
	fichiers, err := filepath.Glob("*.go")
	if err != nil {
		t.Fatal(err)
	}
	vus := 0
	for _, f := range fichiers {
		if strings.HasSuffix(f, "_test.go") || f == "refus.go" {
			continue
		}
		brut, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		vus++
		for i, ligne := range strings.Split(string(brut), "\n") {
			code := ligne
			if j := strings.Index(code, "//"); j >= 0 {
				code = code[:j]
			}
			if strings.Contains(code, `"02_07`) {
				t.Errorf("%s:%d compose une 02_07 à la main — passer par Refus() : %s",
					f, i+1, strings.TrimSpace(ligne))
			}
		}
	}
	if vus < 5 {
		t.Fatalf("seulement %d fichier(s) inspecté(s) : la sentinelle ne regarde pas le paquet", vus)
	}
	source, err := os.ReadFile("CheckAuthentification.go")
	if err != nil {
		t.Fatal(err)
	}
	if n := strings.Count(string(source), "Refus(trames_content.SessionIntegritykey"); n < 10 {
		t.Errorf("CheckAuthentification.go n'appelle Refus() que %d fois : des refus ont disparu, ou sont revenus à la main", n)
	}
}

// Un défi inconnu : le seul refus de CheckAuth atteignable sans base. C'est
// aussi celui que reçoit le TUNNEL d'une machine — donc celui qui faisait
// paniquer un agent.
func TestUnDefiInconnuRendUnRefusBienForme(t *testing.T) {
	reponse := CheckAuth(storage.Trames_struct_client{
		Message_Order:       []string{"02", "03"},
		SessionIntegritykey: "CLE",
		Username:            "vaultaire",
		ClientSoftwareID:    "PC-01",
		Content:             "auth-id-que-personne-n-a-emis\nreponse",
	}, &storage.DuckySession{SessionID: "CLE"})

	if !EstUnRefus(reponse) {
		t.Fatalf("un défi inconnu n'est pas refusé : %q", reponse)
	}
	contenu := contenuVuDuPoste(t, reponse)
	if len(contenu) != 2 || contenu[0] != "vaultaire" || contenu[1] != MotifNonAuthentifie {
		t.Errorf("contenu %q — attendu le compte annoncé, puis %q", contenu, MotifNonAuthentifie)
	}
}

// Le refus ferme la session qu'il refuse, jamais une session authentifiée.
func TestDoitFermerApresRefus(t *testing.T) {
	refus := Refus("CLE", "alice", MotifIdentifiants)
	for _, c := range []struct {
		nom          string
		reponse      string
		authentifiee bool
		attendu      bool
	}{
		{"refus, session en attente", refus, false, true},
		{"refus, tunnel authentifié", refus, true, false},
		{"défi", "02_02\nserveur_central\nCLE\nid\njeton", false, false},
		{"acceptation", Acceptation("CLE", "alice", false, "empty"), false, false},
		{"refus SSH dans le tunnel", "03_03\nserveur_central\nCLE\nalice@acme.lan\npermission denied", false, false},
		{"rien", "", false, false},
	} {
		if got := DoitFermerApresRefus(c.reponse, c.authentifiee); got != c.attendu {
			t.Errorf("%s : DoitFermerApresRefus = %v, attendu %v", c.nom, got, c.attendu)
		}
	}
}
