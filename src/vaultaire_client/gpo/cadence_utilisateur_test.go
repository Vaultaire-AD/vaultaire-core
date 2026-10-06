package gpo

import (
	"testing"
	"time"
)

// TO-DO 142 — la vérification du scope utilisateur a sa propre cadence.

func remettreCadenceUtilisateur(t *testing.T) {
	t.Helper()
	cadenceMu.Lock()
	ancienne := cadenceUtilisateur
	cadenceUtilisateur = VerifUtilisateurParDefaut
	cadenceMu.Unlock()
	t.Cleanup(func() {
		cadenceMu.Lock()
		cadenceUtilisateur = ancienne
		cadenceMu.Unlock()
	})
}

// LA demande de la recette : quelqu'un qui se reconnecte dix minutes plus tard
// retrouve sa politique. Avec la borne d'avant — la cadence machine, une heure
// par défaut — ce second passage ne scannait pas.
func TestUneReconnexionApresCinqMinutesVerifie(t *testing.T) {
	avecMemoireDesScansVide(t)
	remettreCadence(t)
	remettreCadenceUtilisateur(t)

	base := time.Now()
	if !scanDuADeja("alice", base) {
		t.Fatal("la premiere connexion doit verifier")
	}
	if scanDuADeja("alice", base.Add(2*time.Minute)) {
		t.Error("une reconnexion deux minutes apres a reverifie : c'est le « pas avant cinq minutes »")
	}
	if !scanDuADeja("alice", base.Add(10*time.Minute)) {
		t.Errorf("une reconnexion dix minutes apres n'a PAS verifie alors que la cadence machine "+
			"vaut %s : la verification utilisateur suit encore la cadence du parc", CadenceActuelle())
	}
}

// Les deux cadences sont indépendantes : resserrer ou relâcher celle du parc
// ne change rien à celle des dossiers personnels, et l'inverse.
func TestLesDeuxCadencesSontIndependantes(t *testing.T) {
	remettreCadence(t)
	remettreCadenceUtilisateur(t)

	appliquerCadence([]string{"empreinte", PrefixeCadence + "240", PrefixeVerifUtilisateur + "7"})
	appliquerCadenceUtilisateur([]string{"empreinte", PrefixeCadence + "240", PrefixeVerifUtilisateur + "7"})
	if got := CadenceActuelle(); got != 240*time.Minute {
		t.Errorf("cadence machine %s, attendu 4h", got)
	}
	if got := intervalleScanUtilisateur(); got != 7*time.Minute {
		t.Errorf("verification utilisateur toutes les %s, attendu 7m", got)
	}

	// Une réponse qui ne porte que la cadence machine laisse l'autre en place.
	appliquerCadence([]string{"empreinte", PrefixeCadence + "30"})
	appliquerCadenceUtilisateur([]string{"empreinte", PrefixeCadence + "30"})
	if got := intervalleScanUtilisateur(); got != 7*time.Minute {
		t.Errorf("verification utilisateur passee a %s sur une reponse qui ne l'annonce pas", got)
	}
}

// La ligne se lit dans les QUATRE réponses, à quelque rang qu'elle soit : les
// réponses du scope utilisateur commencent par le nom du compte.
func TestLaCadenceUtilisateurEstLueDansLesQuatreReponses(t *testing.T) {
	cas := map[string][]string{
		"05_02": {"3", "empreinte", "2", "4096", "7", "somme", PrefixeCadence + "60", PrefixeVerifUtilisateur + "9", "sig:abc"},
		"05_03": {"empreinte", PrefixeCadence + "60", PrefixeVerifUtilisateur + "9"},
		"05_06": {"alice", "3", "empreinte", "2", "4096", "7", "somme", PrefixeVerifUtilisateur + "9", "sig:abc"},
		"05_07": {"alice", "empreinte", PrefixeVerifUtilisateur + "9"},
	}
	for nom, lignes := range cas {
		remettreCadenceUtilisateur(t)
		appliquerCadenceUtilisateur(lignes)
		if got := CadenceUtilisateur(); got != 9*time.Minute {
			t.Errorf("%s : %s, attendu 9m", nom, got)
		}
	}
}

// Un core antérieur n'annonce rien : l'agent garde son défaut, cinq minutes.
func TestSansAnnonceLAgentGardeCinqMinutes(t *testing.T) {
	remettreCadenceUtilisateur(t)
	appliquerCadenceUtilisateur([]string{"alice", "empreinte"})
	if got := CadenceUtilisateur(); got != 5*time.Minute {
		t.Errorf("%s, attendu 5m", got)
	}
}

// Elle vient du réseau : bornée à la réception, comme l'autre. Sous la minute,
// un écran verrouillé puis déverrouillé ferait hacher l'inventaire à chaque fois.
func TestUneCadenceUtilisateurAbsurdeEstBornee(t *testing.T) {
	cas := []struct {
		ligne   string
		attendu time.Duration
	}{
		{PrefixeVerifUtilisateur + "0", VerifUtilisateurMinimum},
		{PrefixeVerifUtilisateur + "-5", VerifUtilisateurMinimum},
		{PrefixeVerifUtilisateur + "100000", VerifUtilisateurMaximum},
		{PrefixeVerifUtilisateur + "cinq", VerifUtilisateurParDefaut}, // illisible : rien ne change
	}
	for _, c := range cas {
		remettreCadenceUtilisateur(t)
		appliquerCadenceUtilisateur([]string{"empreinte", c.ligne})
		if got := CadenceUtilisateur(); got != c.attendu {
			t.Errorf("%q : %s, attendu %s", c.ligne, got, c.attendu)
		}
	}
}

// Le préfixe de l'une ne doit pas être lu comme l'autre : « usercheck: » ne
// commence pas par « refresh: », mais le garde-fou coûte une ligne et protège
// d'un renommage malheureux.
func TestLaCadenceUtilisateurNeDeplacePasCelleDeLaMachine(t *testing.T) {
	remettreCadence(t)
	remettreCadenceUtilisateur(t)
	appliquerCadence([]string{"empreinte", PrefixeVerifUtilisateur + "7"})
	if got := CadenceActuelle(); got != MachineRefreshInterval {
		t.Errorf("la cadence machine est passee a %s sur une ligne qui ne la concerne pas", got)
	}
}
