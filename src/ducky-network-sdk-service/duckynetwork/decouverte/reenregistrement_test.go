package decouverte

import (
	"encoding/pem"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"duckynetworkclient/V1/duckynetwork/storage"
)

// Un nœud que le core ne connaît plus doit se réenregistrer (TO-DO 109).
//
// Le core purge un nœud resté hors ligne vingt-quatre heures. À son retour, ce
// nœud bat — et le core ne trouve aucune ligne à rafraîchir. Avant ce point,
// rien ne le lui disait : il battait dans le vide, invisible du cluster, en se
// croyant enregistré, jusqu'à ce que quelqu'un le redémarre.

// faireUnNoeudDEssai pose une clé publique sur le disque — 04_01 porte son
// empreinte, et sans elle l'enregistrement n'est pas émis — et branche un
// émetteur qui retient les trames. `surTrame` joue le core.
func faireUnNoeudDEssai(t *testing.T, surTrame func(code string)) (trames func() []string) {
	t.Helper()

	dossier := t.TempDir()
	clePEM := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: []byte("cle publique d'essai")})
	if err := os.WriteFile(filepath.Join(dossier, "public.pem"), clePEM, 0o600); err != nil {
		t.Fatal(err)
	}
	ancienChemin, ancienDelai := storage.KeyPath, DelaiAccuseEnregistrement
	storage.KeyPath = dossier
	DelaiAccuseEnregistrement = 2 * time.Second

	var mu sync.Mutex
	var envoyees []string
	Configure(func(trame string) {
		code := strings.SplitN(trame, "\n", 2)[0]
		mu.Lock()
		envoyees = append(envoyees, code)
		mu.Unlock()
		if surTrame != nil {
			// Dans une goroutine, comme le core répond : sur le fil de
			// lecture, pas dans celui qui émet.
			go surTrame(code)
		}
	}, "machine-42")
	battementRefuse.Store(false)

	t.Cleanup(func() {
		Configure(nil, "")
		storage.KeyPath = ancienChemin
		DelaiAccuseEnregistrement = ancienDelai
		battementRefuse.Store(false)
	})

	return func() []string {
		mu.Lock()
		defer mu.Unlock()
		return append([]string(nil), envoyees...)
	}
}

func recevoir(sous, contenu string) {
	HandleTrame(storage.Trames_struct_client{Message_Order: []string{"04", sous}, Content: contenu}, nil)
}

var noeudDEssai = InfosNoeud{Hostname: "proxy1", FQDN: "proxy1", IP: "10.0.0.2", Role: "proxy", Port: 7070}

func cleDEssai() string { return "CLE" }

// Le cas du constat, de bout en bout : enregistré, il bat ; le core refuse le
// battement ; au tour suivant il rejoue 04_01 au lieu de battre.
func TestUnBattementRefuseFaitReenregistrer(t *testing.T) {
	trames := faireUnNoeudDEssai(t, func(code string) {
		if code == "04_01" {
			recevoir("02", "ok")
		}
	})

	// Tour 1 : enregistré, il bat.
	enregistre, continuer := tourDeBattement(cleDEssai, noeudDEssai, time.Second, true)
	if !enregistre || !continuer {
		t.Fatalf("tour ordinaire : enregistre=%v continuer=%v", enregistre, continuer)
	}
	if got := trames(); len(got) != 1 || got[0] != "04_07" {
		t.Fatalf("un nœud enregistré doit battre : trames émises %v", got)
	}

	// Le core ne le connaît plus.
	recevoir("08", "refus\nnœud non enregistré dans le cluster : rejouez 04_01")

	// Tour 2 : il ne bat pas, il se réenregistre — et le core l'accepte.
	enregistre, continuer = tourDeBattement(cleDEssai, noeudDEssai, time.Second, enregistre)
	if !continuer {
		t.Fatal("la boucle s'est arrêtée")
	}
	if got := trames(); len(got) != 2 || got[1] != "04_01" {
		t.Fatalf("après un battement refusé, le tour suivant doit rejouer 04_01 — "+
			"c'est le défaut du point 109 : trames émises %v", got)
	}
	if !enregistre {
		t.Fatal("le core a accusé le 04_01, le nœud doit se savoir réenregistré")
	}

	// Tour 3 : il bat de nouveau, et ne se réenregistre pas une seconde fois.
	enregistre, _ = tourDeBattement(cleDEssai, noeudDEssai, time.Second, enregistre)
	if got := trames(); len(got) != 3 || got[2] != "04_07" {
		t.Fatalf("une fois réenregistré, le nœud doit reprendre son battement : %v", got)
	}
	if !enregistre {
		t.Fatal("le battement ordinaire a fait perdre l'enregistrement")
	}
}

// Un accusé ordinaire — « ack », ou vide comme le rendent les cores d'avant la
// 2.2 — ne doit RIEN déclencher : sinon tout le parc de proxies se
// réenregistrerait à chaque battement.
func TestUnAccuseDeBattementOrdinaireNeFaitRien(t *testing.T) {
	trames := faireUnNoeudDEssai(t, nil)

	for _, contenu := range []string{"ack", "", "ok", "  ack  \n"} {
		recevoir("08", contenu)
		if battementRefuse.Load() {
			t.Fatalf("accusé %q pris pour un refus", contenu)
		}
	}
	if enregistre, _ := tourDeBattement(cleDEssai, noeudDEssai, time.Second, true); !enregistre {
		t.Fatal("un accusé ordinaire a fait perdre l'enregistrement")
	}
	if got := trames(); len(got) != 1 || got[0] != "04_07" {
		t.Fatalf("attendu un seul battement, émis %v", got)
	}
}

// Si le core refuse AUSSI le réenregistrement, le nœud reste non enregistré et
// retente au tour suivant, sans battre entre-temps.
func TestUnReenregistrementRefuseEstRetente(t *testing.T) {
	trames := faireUnNoeudDEssai(t, func(code string) {
		if code == "04_01" {
			recevoir("02", "refus\nce nom de nœud appartient déjà à un autre client")
		}
	})

	recevoir("08", "refus\nnœud non enregistré")
	enregistre, _ := tourDeBattement(cleDEssai, noeudDEssai, time.Second, true)
	if enregistre {
		t.Fatal("réenregistrement refusé par le core, le nœud se croit enregistré")
	}
	enregistre, _ = tourDeBattement(cleDEssai, noeudDEssai, time.Second, enregistre)
	if enregistre {
		t.Fatal("second refus pris pour une acceptation")
	}
	if got := trames(); len(got) != 2 || got[0] != "04_01" || got[1] != "04_01" {
		t.Fatalf("attendu deux 04_01 et aucun battement, émis %v", got)
	}
}

// Deux refus avant le tour suivant ne demandent qu'un réenregistrement.
func TestDeuxRefusNeFontQuUnReenregistrement(t *testing.T) {
	trames := faireUnNoeudDEssai(t, func(code string) {
		if code == "04_01" {
			recevoir("02", "ok")
		}
	})

	recevoir("08", "refus\nnœud non enregistré")
	recevoir("08", "refus\nnœud non enregistré")
	enregistre, _ := tourDeBattement(cleDEssai, noeudDEssai, time.Second, true)
	enregistre, _ = tourDeBattement(cleDEssai, noeudDEssai, time.Second, enregistre)
	if got := trames(); len(got) != 2 || got[0] != "04_01" || got[1] != "04_07" {
		t.Fatalf("attendu un 04_01 puis un battement, émis %v", got)
	}
}
