package display

import (
	"strings"
	"testing"

	"github.com/fatih/color"
)

// TestLargeurVisibleIgnoreLesCodesCouleur est le test du défaut d'origine.
//
// `%-15s` appliqué à une chaîne colorée compte les séquences d'échappement dans
// la largeur. « ID » coloré vaut deux caractères à l'écran mais quinze octets :
// le rembourrage est calculé sur une longueur que personne ne voit, et la
// colonne suivante démarre treize caractères trop tôt.
func TestLargeurVisibleIgnoreLesCodesCouleur(t *testing.T) {
	// color désactive ses séquences quand la sortie n'est pas un terminal ; on
	// force l'inverse pour que le test mesure ce qu'il prétend mesurer.
	ancien := color.NoColor
	color.NoColor = false
	defer func() { color.NoColor = ancien }()

	colore := color.New(color.FgYellow, color.Bold).Sprint("ID")

	if len(colore) <= 2 {
		t.Skip("la coloration est inactive dans cet environnement")
	}
	if got := LargeurVisible(colore); got != 2 {
		t.Fatalf("LargeurVisible = %d, attendu 2 — la chaîne fait %d octets, "+
			"et c'est cette valeur qui faussait le rembourrage", got, len(colore))
	}
}

// TestLargeurVisibleCompteLesRunes.
//
// « é » occupe deux octets pour un seul caractère à l'écran. Compter les octets
// décalerait la colonne d'un cran par accent — un défaut qui ne se voit que sur
// les données réelles, jamais sur un jeu de test anglophone.
func TestLargeurVisibleCompteLesRunes(t *testing.T) {
	if got := LargeurVisible("créé"); got != 4 {
		t.Fatalf("LargeurVisible(\"créé\") = %d, attendu 4 (len vaut %d)", got, len("créé"))
	}
}

// TestColonnesAlignees : le cœur du module.
func TestColonnesAlignees(t *testing.T) {
	tb := NouvelleTable("Nom", "Domaine")
	tb.SansCouleur = true
	tb.Ajouter("alice", "paris")
	tb.Ajouter("jean-baptiste-de-la-tour", "lyon")
	tb.Ajouter("bob", "marseille")

	lignes := strings.Split(strings.TrimRight(tb.String(), "\n"), "\n")
	if len(lignes) != 5 { // en-têtes + filet + 3 lignes
		t.Fatalf("%d lignes, attendu 5 :\n%s", len(lignes), tb.String())
	}

	// La colonne « Domaine » doit commencer au même endroit sur toutes les
	// lignes de données.
	positions := map[int]bool{}
	for _, l := range lignes[2:] {
		positions[strings.Index(l, strings.Fields(l)[len(strings.Fields(l))-1])] = true
	}
	if len(positions) != 1 {
		t.Fatalf("la seconde colonne démarre à %d positions différentes :\n%s",
			len(positions), tb.String())
	}
}

// TestLargeurSuitLeContenu.
//
// `%-25s` suppose qu'aucune valeur ne dépasse vingt-cinq caractères. La
// première qui dépasse pousse sa ligne, et la colonne perd son alignement sur
// cette ligne seulement — plus déroutant qu'un décalage franc.
func TestLargeurSuitLeContenu(t *testing.T) {
	court := NouvelleTable("Nom")
	court.SansCouleur = true
	court.Ajouter("bob")

	long := NouvelleTable("Nom")
	long.SansCouleur = true
	long.Ajouter(strings.Repeat("x", 60))

	largeurCourt := len(strings.Split(court.String(), "\n")[1])
	largeurLong := len(strings.Split(long.String(), "\n")[1])

	if largeurCourt >= largeurLong {
		t.Fatalf("le filet ne suit pas le contenu : %d vs %d", largeurCourt, largeurLong)
	}
	if largeurLong < 60 {
		t.Fatalf("la colonne fait %d, le contenu 60 : la valeur déborderait", largeurLong)
	}
}

// TestLigneIncompleteNePaniquePas.
//
// Un affichage est le dernier endroit où un décompte erroné doit arrêter le
// programme.
func TestLigneIncompleteNePaniquePas(t *testing.T) {
	tb := NouvelleTable("A", "B", "C")
	tb.SansCouleur = true
	tb.Ajouter("1")                // trop court
	tb.Ajouter("1", "2", "3", "4") // trop long

	out := tb.String()
	if out == "" {
		t.Fatal("sortie vide")
	}
	if strings.Count(strings.TrimRight(out, "\n"), "\n") != 3 {
		t.Fatalf("nombre de lignes inattendu :\n%s", out)
	}
}

// TestPasDEspacesEnFinDeLigne.
//
// La dernière colonne n'a rien à aligner après elle. La rembourrer produit des
// espaces invisibles que tout copier-coller de la sortie emporte avec lui — et
// qui font échouer une comparaison de sortie attendue pour une raison qu'on ne
// voit pas à l'écran.
func TestPasDEspacesEnFinDeLigne(t *testing.T) {
	tb := NouvelleTable("Nom", "État")
	tb.SansCouleur = true
	tb.Ajouter("alice", "actif")
	tb.Ajouter("jean-baptiste-de-la-tour", "révoqué")

	for i, l := range strings.Split(strings.TrimRight(tb.String(), "\n"), "\n") {
		if l != strings.TrimRight(l, " ") {
			t.Errorf("ligne %d terminée par des espaces : %q", i, l)
		}
	}
}

// TestValeurVideEstLisible.
//
// Une case blanche se confond avec un défaut d'affichage ; le tiret dit que la
// valeur est absente, ce qui est une information.
func TestValeurVideEstLisible(t *testing.T) {
	if Valeur("") != "—" {
		t.Errorf("valeur vide rendue %q", Valeur(""))
	}
	if Valeur("   ") != "—" {
		t.Errorf("valeur d'espaces rendue %q", Valeur("   "))
	}
	if Valeur("paris") != "paris" {
		t.Errorf("valeur pleine altérée : %q", Valeur("paris"))
	}
}

func TestListeVide(t *testing.T) {
	if Liste(nil) != "aucun" {
		t.Errorf("liste vide rendue %q", Liste(nil))
	}
	if Liste([]string{"a", "b"}) != "a, b" {
		t.Errorf("liste rendue %q", Liste([]string{"a", "b"}))
	}
}

// TestFicheAligneLesLibelles.
func TestFicheAligneLesLibelles(t *testing.T) {
	f := NouvelleFiche("Permission lecture")
	f.SansCouleur = true
	f.Ajouter("ID", "3")
	f.Ajouter("Description très longue", "texte")
	f.AjouterSection("Actions RBAC")
	f.Ajouter("read:get:user", "all")

	out := f.String()

	// Position de chaque valeur, mesurée en CARACTÈRES VISIBLES.
	//
	// Une première version découpait la ligne sur « deux espaces » — ce qui se
	// trompe dès qu'une valeur en contient — et mesurait en octets, ce qui
	// décale d'un cran par accent. Elle déclarait la fiche mal alignée alors
	// qu'elle l'était parfaitement.
	//
	// La mesure porte donc sur le préfixe qui précède la valeur, en runes.
	valeurs := map[string]string{
		"ID":                      "3",
		"Description très longue": "texte",
		"read:get:user":           "all",
	}

	var positions []int
	for libelle, valeur := range valeurs {
		ligne := ""
		for _, l := range strings.Split(out, "\n") {
			if strings.Contains(l, libelle) && strings.HasSuffix(l, valeur) {
				ligne = l
				break
			}
		}
		if ligne == "" {
			t.Fatalf("champ %q absent de la fiche :\n%s", libelle, out)
		}
		prefixe := strings.TrimSuffix(ligne, valeur)
		positions = append(positions, LargeurVisible(prefixe))
	}

	if len(positions) < 2 {
		t.Fatalf("fiche illisible :\n%s", out)
	}
	for i := 1; i < len(positions); i++ {
		if positions[i] != positions[0] {
			t.Fatalf("les valeurs démarrent aux colonnes %v, elles devraient être identiques :\n%s",
				positions, out)
		}
	}
}

// TestFicheSectionSansValeur : une section est un intertitre, pas un champ.
func TestFicheSectionSansValeur(t *testing.T) {
	f := NouvelleFiche("Titre")
	f.SansCouleur = true
	f.AjouterSection("Actions RBAC")

	out := f.String()
	if !strings.Contains(out, "Actions RBAC") {
		t.Fatal("section absente de la sortie")
	}
	if strings.Contains(out, "Actions RBAC  —") {
		t.Fatal("la section est rendue comme un champ vide")
	}
}
