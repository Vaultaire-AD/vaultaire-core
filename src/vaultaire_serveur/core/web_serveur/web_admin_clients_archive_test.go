package webserveur

import (
	"testing"
	"time"
)

// Les jetons de téléchargement.
//
// Éprouvés ici parce qu'ils gardent une CLÉ PRIVÉE et qu'ils sont du code pur :
// une carte, une horloge, rien d'autre. Chacune des trois propriétés ci-dessous
// est ce qui distingue un lien éphémère d'une adresse rejouable indéfiniment, et
// aucune ne se voit à la lecture d'une page.

func viderLesJetons(t *testing.T) {
	t.Helper()
	jetonsMu.Lock()
	jetonsArchive = map[string]jetonArchive{}
	jetonsMu.Unlock()
}

func TestUnJetonNeSertQuUneFois(t *testing.T) {
	viderLesJetons(t)

	jeton, err := EmettreJetonArchive("alice", "ABC-30-09-2026", "windows")
	if err != nil {
		t.Fatal(err)
	}

	v, ok := consommerJetonArchive(jeton)
	if !ok {
		t.Fatal("le jeton fraîchement émis a été refusé")
	}
	if v.computeurID != "ABC-30-09-2026" || v.systeme != "windows" || v.username != "alice" {
		t.Errorf("le jeton ne porte pas ce qu'on y a mis : %+v", v)
	}

	// LA propriété : rejouer ne doit rien donner. Sans elle, l'adresse reste
	// valide dans l'historique du navigateur, un marque-page, un message.
	if _, ok := consommerJetonArchive(jeton); ok {
		t.Error("le jeton a servi deux fois")
	}
}

func TestUnJetonExpireEstRefuseEtRetire(t *testing.T) {
	viderLesJetons(t)

	jeton, err := EmettreJetonArchive("alice", "ABC", "linux")
	if err != nil {
		t.Fatal(err)
	}

	jetonsMu.Lock()
	v := jetonsArchive[jeton]
	v.expire = time.Now().Add(-time.Second)
	jetonsArchive[jeton] = v
	jetonsMu.Unlock()

	if _, ok := consommerJetonArchive(jeton); ok {
		t.Fatal("un jeton expiré a été accepté")
	}

	// Retiré MÊME expiré : le garder pour distinguer « expiré » de « inconnu »
	// donnerait un oracle à qui essaie des jetons au hasard.
	jetonsMu.Lock()
	_, present := jetonsArchive[jeton]
	jetonsMu.Unlock()
	if present {
		t.Error("le jeton expiré est resté dans la carte")
	}
}

func TestUnJetonInconnuEstRefuse(t *testing.T) {
	viderLesJetons(t)
	if _, ok := consommerJetonArchive("00000000000000000000000000000000"); ok {
		t.Error("un jeton jamais émis a été accepté")
	}
	if _, ok := consommerJetonArchive(""); ok {
		t.Error("le jeton vide a été accepté")
	}
}

func TestDeuxEmissionsNeDonnentPasLeMemeJeton(t *testing.T) {
	viderLesJetons(t)

	vus := map[string]bool{}
	for i := 0; i < 50; i++ {
		jeton, err := EmettreJetonArchive("alice", "ABC", "linux")
		if err != nil {
			t.Fatal(err)
		}
		if vus[jeton] {
			t.Fatalf("jeton répété : %s", jeton)
		}
		// 16 octets en hexadécimal. Un jeton court se devine ; celui-ci garde
		// une clé privée.
		if len(jeton) != 32 {
			t.Fatalf("jeton de %d caractères, attendu 32", len(jeton))
		}
		vus[jeton] = true
	}
}

// Les jetons périmés ne s'accumulent pas.
//
// La purge a lieu à l'ÉMISSION : sans elle, un administrateur qui scripte des
// POST ferait croître la carte sans plafond, et chaque entrée y garde le nom
// d'une machine.
func TestLesJetonsPerimesSontPurgesALEmission(t *testing.T) {
	viderLesJetons(t)

	for i := 0; i < 10; i++ {
		jeton, err := EmettreJetonArchive("alice", "ABC", "linux")
		if err != nil {
			t.Fatal(err)
		}
		jetonsMu.Lock()
		v := jetonsArchive[jeton]
		v.expire = time.Now().Add(-time.Hour)
		jetonsArchive[jeton] = v
		jetonsMu.Unlock()
	}

	if _, err := EmettreJetonArchive("alice", "DEF", "linux"); err != nil {
		t.Fatal(err)
	}

	jetonsMu.Lock()
	restants := len(jetonsArchive)
	jetonsMu.Unlock()
	if restants != 1 {
		t.Errorf("%d jetons en mémoire, attendu 1 (les périmés doivent partir)", restants)
	}
}
