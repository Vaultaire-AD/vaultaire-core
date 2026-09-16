package trame

import (
	"strings"
	"testing"
)

// L'en-tête des réponses au client.
//
// # Ce que ces tests gardent
//
// Le NOMBRE de lignes d'en-tête, et rien d'autre. C'est peu, et c'est ce qui a
// coûté : les quatre trames de cluster avaient été écrites avec l'en-tête des
// requêtes — cinq lignes au lieu de trois — et l'agent lisait « vaultaire »
// comme première ligne de contenu.
//
// Une erreur de contenu se voit à la lecture de la trame. Une erreur d'en-tête
// décale tout ce qui suit et se manifeste très loin de sa cause : ici, dans un
// analyseur de liste de nœuds qui avait l'air fautif.

// LignesEnTeteClient est le nombre de lignes que l'agent saute.
//
// Doit correspondre à `lines[3:]` dans ParseTrames du SDK
// (ducky-network-sdk-service/duckynetwork/trames_manager/ReadMessageContent.go).
// Les deux vivent dans des modules Go distincts qui ne se voient pas : la
// constante est ici, le test la confronte à ce que produit la fonction.
const LignesEnTeteClient = 3

// TestLEnTeteFaitExactementTroisLignes.
//
// LE test. Une quatrième ligne d'en-tête décale le contenu d'un cran, et le
// symptôme apparaît chez l'analyseur du client — pas ici.
func TestLEnTeteFaitExactementTroisLignes(t *testing.T) {
	cas := []struct {
		quoi    string
		trame   string
		contenu string
	}{
		{"sans contenu",
			ReponseClient("04_13", "serveur_central", "cle"), ""},
		{"une ligne",
			ReponseClient("04_06", "serveur_central", "cle", "ack"), "ack"},
		{"deux lignes",
			ReponseClient("04_02", "serveur_central", "cle", "ok", "hote"), "ok\nhote"},
		{"contenu portant lui-meme des sauts de ligne",
			ReponseClient("04_04", "serveur_central", "cle", "2", "a|1|2|core|0|SHA256:x\nb|3|4|proxy|1|SHA256:y"),
			"2\na|1|2|core|0|SHA256:x\nb|3|4|proxy|1|SHA256:y"},
	}

	for _, c := range cas {
		lignes := strings.Split(c.trame, "\n")
		if len(lignes) < LignesEnTeteClient {
			t.Errorf("%s : %d ligne(s), l'en-tete en exige %d", c.quoi, len(lignes), LignesEnTeteClient)
			continue
		}
		if lignes[0] != strings.Split(c.trame, "\n")[0] {
			t.Errorf("%s : code de trame deplace", c.quoi)
		}

		// La lecture est faite EXACTEMENT comme le SDK la fait.
		reste := strings.Join(lignes[LignesEnTeteClient:], "\n")
		if reste != c.contenu {
			t.Errorf("%s : l'agent lirait %q, attendu %q", c.quoi, reste, c.contenu)
		}
	}
}

// TestUneDestinationVideNeDecalePasLEnTete.
//
// Une deuxième ligne vide compterait quand même comme une ligne — donc rien ne
// casserait — mais un client qui journalise la destination afficherait du vide.
// Le repli évite surtout qu'une future concaténation « oublie » la ligne.
func TestUneDestinationVideNeDecalePasLEnTete(t *testing.T) {
	for _, vide := range []string{"", "   ", "\t"} {
		trame := ReponseClient("04_02", vide, "cle", "ok")
		lignes := strings.Split(trame, "\n")
		if len(lignes) != 4 {
			t.Fatalf("destination %q : %d lignes, attendu 4", vide, len(lignes))
		}
		if lignes[1] != DestinationParDefaut {
			t.Errorf("destination %q : ligne 2 = %q, attendu %q", vide, lignes[1], DestinationParDefaut)
		}
	}
}

// TestLaDestinationEstRenvoyeeTelleQuelle.
//
// Les deux orthographes coexistent dans le code existant — « serveur_central »
// côté SSH, « server_central » côté cluster. Trancher ici ferait répondre à un
// client autre chose que ce qu'il a écrit ; ce n'est pas le rôle de cette
// fonction, et ce champ n'est vérifié par personne.
func TestLaDestinationEstRenvoyeeTelleQuelle(t *testing.T) {
	for _, dest := range []string{"serveur_central", "server_central", "autre_chose"} {
		lignes := strings.Split(ReponseClient("04_02", dest, "cle"), "\n")
		if lignes[1] != dest {
			t.Errorf("destination %q rendue %q", dest, lignes[1])
		}
	}
}

// TestUneReponseSansContenuNaPasDeLigneVideFinale.
//
// Un « \n » final ferait une quatrième ligne, vide. L'agent la lirait comme un
// contenu — et `AnalyserListe` traite une première ligne vide comme une trame
// vide, donc comme une erreur.
func TestUneReponseSansContenuNaPasDeLigneVideFinale(t *testing.T) {
	trame := ReponseClient("04_13", "serveur_central", "cle")
	if strings.HasSuffix(trame, "\n") {
		t.Errorf("trame %q se termine par un saut de ligne", trame)
	}
	if n := len(strings.Split(trame, "\n")); n != LignesEnTeteClient {
		t.Errorf("%d lignes, attendu %d", n, LignesEnTeteClient)
	}
}
