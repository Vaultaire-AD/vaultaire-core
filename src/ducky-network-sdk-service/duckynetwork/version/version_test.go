package version

import (
	"strings"
	"testing"
)

// La mise en forme d'une version.
//
// # Ce que ces tests gardent
//
// Une chose surtout : que la version ne puisse pas CASSER LA TRAME qui la
// transporte. Elle voyage dans l'inventaire 02_12 et dans l'enregistrement
// 04_01, deux trames dont les champs sont séparés par des sauts de ligne. Un
// retour à la ligne dans une version décalerait tous les champs suivants — et
// le core lirait la version du socle comme celle du programme, ou pire.
//
// La seconde : qu'un binaire construit hors du script de build se RECONNAISSE.
// C'est la première chose qu'on veut savoir devant une machine qui se comporte
// mal, et c'est exactement ce qu'un affichage « propre » aurait masqué.

func TestUneVersionNeContientJamaisDeSautDeLigne(t *testing.T) {
	// Les valeurs viennent de -ldflags, donc d'un script. Une variable
	// d'environnement mal remplie y mettrait n'importe quoi.
	sales := []string{
		"g1939a3b\n",
		"\ng1939a3b",
		"g1939\r\na3b",
		"g1939a3b\r",
	}

	for _, sale := range sales {
		i := Info{Composant: "essai", Semantique: "2.1.0", Commit: sale, Date: sale}
		rendu := i.Complete()
		if strings.ContainsAny(rendu, "\n\r") {
			t.Errorf("commit %q rendu %q : un saut de ligne décalerait tous les "+
				"champs de la trame qui transporte cette valeur", sale, rendu)
		}
	}
}

// TestUnBuildLocalSeReconnait.
//
// Le repli est AFFICHÉ, jamais masqué. Un binaire compilé à la main sur un
// poste de développement doit se distinguer dans l'inventaire du parc — sinon
// il s'y confond avec les autres, et c'est justement celui qu'on cherche.
func TestUnBuildLocalSeReconnait(t *testing.T) {
	i := Info{Composant: "essai", Semantique: "2.1.0", Commit: "dev", Date: "inconnue"}
	rendu := i.Complete()

	if !strings.Contains(rendu, "2.1.0") {
		t.Errorf("rendu %q : la version sémantique doit toujours y figurer", rendu)
	}
	if !strings.Contains(rendu, "local") {
		t.Errorf("rendu %q : un build hors script doit se reconnaître, pas se "+
			"confondre avec un build de production", rendu)
	}
	if strings.Contains(rendu, "+dev") {
		t.Errorf("rendu %q : « dev » ne doit pas passer pour un commit", rendu)
	}
}

func TestUneVersionCompleteSeLit(t *testing.T) {
	i := Info{Composant: "essai", Semantique: "2.1.0", Commit: "g1939a3b", Date: "2026-08-14"}
	rendu := i.Complete()

	attendu := "2.1.0+g1939a3b (2026-08-14)"
	if rendu != attendu {
		t.Errorf("rendu %q, attendu %q", rendu, attendu)
	}
}

// TestLaVersionSemantiqueEstToujoursEnTete.
//
// Le « + » suit la convention SemVer : ce qui le suit n'entre dans aucune
// comparaison d'ordre. C'est le statut qu'on veut donner au commit — informatif,
// jamais décisionnel — et il faut que la partie comparable reste devant.
func TestLaVersionSemantiqueEstToujoursEnTete(t *testing.T) {
	cas := []Info{
		{Semantique: "2.1.0", Commit: "g1939a3b", Date: "2026-08-14"},
		{Semantique: "2.1.0", Commit: "dev", Date: "inconnue"},
		{Semantique: "2.1.0", Commit: "", Date: ""},
	}
	for _, i := range cas {
		if !strings.HasPrefix(i.Complete(), "2.1.0") {
			t.Errorf("rendu %q ne commence pas par la version sémantique", i.Complete())
		}
	}
}

// TestLeSDKSeDeclare : la version du socle est disponible sans configuration.
func TestLeSDKSeDeclare(t *testing.T) {
	i := SDK()
	if i.Semantique != Version {
		t.Errorf("SDK().Semantique = %q, attendu %q", i.Semantique, Version)
	}
	if i.Composant == "" {
		t.Error("SDK() rend un composant sans nom : la valeur serait illisible " +
			"dans un journal")
	}
	if i.Complete() == "" {
		t.Error("SDK().Complete() est vide")
	}
}

// TestLaVersionTientDansLaColonne.
//
// La base la range dans un VARCHAR(64). Une valeur plus longue serait tronquée
// par MySQL — silencieusement en mode non strict — et on lirait une version
// coupée au milieu sans jamais savoir qu'elle l'a été.
//
// Le core tronque lui-même à la réception ; ce test garde l'autre bout, pour
// que le cas normal ne s'en approche jamais.
func TestLaVersionTientDansLaColonne(t *testing.T) {
	const largeurColonne = 64

	i := Info{Semantique: Version, Commit: "g99.9.9-999-gabcdef0-dirty", Date: "2026-08-14"}
	if n := len(i.Complete()); n > largeurColonne {
		t.Errorf("une version réaliste fait %d caractères, la colonne en accepte %d : %q",
			n, largeurColonne, i.Complete())
	}
}
