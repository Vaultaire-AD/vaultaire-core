package decouverte

import (
	"strings"
	"sync"
	"testing"
	"time"
)

// La 04_16, côté proxy.
//
// # Ce que ces tests gardent
//
//   - une adresse inutilisable est écartée : le relais attendrait son délai
//     pour rien à chaque connexion ;
//   - une liste vide REMPLACE la précédente : garder des Nexus que le core dit
//     hors ligne ferait tenter des adresses mortes ;
//   - la demande porte le type en contenu, et rien d'autre : l'identité est
//     dans l'en-tête, où la couche de session l'a posée.

func TestLaReponseSeLitEtFiltre(t *testing.T) {
	typ, adr, err := AnalyserServices("vaultaire_nexus\n3\nnexus-a:8843\nnexus-sans-port\n[2001:db8::8]:443\n")
	if err != nil {
		t.Fatal(err)
	}
	if typ != "vaultaire_nexus" {
		t.Fatalf("type = %q", typ)
	}
	if strings.Join(adr, ",") != "nexus-a:8843,[2001:db8::8]:443" {
		t.Fatalf("adresses = %v : l'ordre du core doit être gardé, les lignes sans port écartées", adr)
	}
}

func TestUneReponseMalFormeeEstRefusee(t *testing.T) {
	for _, c := range []string{"", "vaultaire_nexus", "vaultaire_nexus\ndeux"} {
		if _, _, err := AnalyserServices(c); err == nil {
			t.Errorf("%q accepté", c)
		}
	}
}

func TestUneListeVideRemplaceLaPrecedente(t *testing.T) {
	traiterServices("vaultaire_nexus\n1\nnexus-a:8843")
	if got := AdressesService("vaultaire_nexus"); len(got) != 1 {
		t.Fatalf("après une liste d'un service : %v", got)
	}
	traiterServices("vaultaire_nexus\n0")
	if got := AdressesService("vaultaire_nexus"); len(got) != 0 {
		t.Fatalf("après une liste vide : %v — le relais tenterait un Nexus que le core dit hors ligne", got)
	}
}

func TestLaDemandePorteLeType(t *testing.T) {
	d := ConstruireDemandeServices("cle", "proxy-01", "vaultaire_nexus")
	lignes := strings.Split(d, "\n")
	if lignes[0] != "04_15" || lignes[len(lignes)-1] != "vaultaire_nexus" || len(lignes) != 6 {
		t.Fatalf("demande = %q", d)
	}
}

// Le suivi des services s'étend en cours de route (TO-DO 141) : un relais
// HTTPS posé par le core peut nommer un type qu'aucun relais du fichier ne
// suivait, sur un proxy démarré sans aucun type à suivre.
func TestLeSuiviDesServicesSEtend(t *testing.T) {
	var mu sync.Mutex
	demandes := map[string]int{}
	Configure(func(trame string) {
		lignes := strings.Split(trame, "\n")
		if lignes[0] == "04_15" {
			mu.Lock()
			demandes[lignes[len(lignes)-1]]++
			mu.Unlock()
		}
	}, "proxy-1")
	t.Cleanup(func() { Configure(nil, "") })

	// Démarrage sans aucun type : rien n'est émis, mais le fournisseur de clé
	// est retenu.
	SuivreServices(nil, func() string { return "CLE" })
	SuivreServicesEnPlus([]string{"vaultaire_nexus"})
	SuivreServicesEnPlus([]string{"vaultaire_nexus", " "}) // déjà suivi : pas de doublon

	attendre := time.Now().Add(2 * time.Second)
	for {
		mu.Lock()
		n := demandes["vaultaire_nexus"]
		mu.Unlock()
		if n >= 1 {
			break
		}
		if time.Now().After(attendre) {
			t.Fatal("le type ajouté après le démarrage n'a jamais été demandé au core")
		}
		time.Sleep(10 * time.Millisecond)
	}
	if got := TypesSuivis(); len(got) != 1 || got[0] != "vaultaire_nexus" {
		t.Fatalf("types suivis : %v, attendu [vaultaire_nexus]", got)
	}
}
