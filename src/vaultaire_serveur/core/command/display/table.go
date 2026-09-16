package display

import (
	"fmt"
	"regexp"
	"strings"
	"unicode/utf8"

	"github.com/fatih/color"
)

// Affichage tabulaire du CLI.
//
// # Pourquoi les colonnes ne s'alignaient pas
//
// Le motif employé partout était :
//
//	fmt.Fprintf(w, "%-15s %-25s\n", header("ID"), header("Username"))
//
// Deux mécanismes d'alignement s'y contredisent, et un troisième défaut s'y
// ajoute.
//
//  1. `%-15s` COMPTE LES CODES COULEUR. `header("ID")` ne vaut pas « ID » mais
//     « \033[33;1mID\033[0m » — deux caractères visibles, quinze octets. Le
//     rembourrage est donc calculé sur une longueur que personne ne voit, et la
//     colonne suivante démarre treize caractères trop tôt.
//
//     C'est pourquoi les en-têtes colorés sont décalés et les valeurs, non
//     colorées, correctement alignées : le défaut ne se manifeste que sur les
//     chaînes qui portent de la couleur.
//
//  2. `tabwriter` et `%-15s` visent le même but par des moyens incompatibles.
//     Le premier aligne sur des tabulations qu'il faut écrire, le second impose
//     une largeur fixe. Employer les deux revient à n'employer ni l'un ni
//     l'autre.
//
//  3. LA LARGEUR EST DEVINÉE. `%-25s` sur un nom d'utilisateur suppose qu'aucun
//     ne dépasse vingt-cinq caractères. Le premier qui dépasse pousse toute sa
//     ligne, et la colonne perd son alignement sur cette ligne seulement — ce
//     qui est plus déroutant qu'un décalage franc.
//
// Ce fichier mesure la largeur VISIBLE, calcule les colonnes sur le contenu
// réel, et n'applique la couleur qu'après le calcul.

// codesANSI reconnaît les séquences d'échappement de couleur.
//
// Employé pour les retirer avant de mesurer, jamais pour les retirer de la
// sortie : la couleur reste, elle cesse simplement de fausser le compte.
var codesANSI = regexp.MustCompile(`\x1b\[[0-9;]*m`)

// LargeurVisible rend le nombre de caractères réellement affichés.
//
// Compte les RUNES et non les octets : « é » occupe deux octets pour un seul
// caractère à l'écran, et un nom accentué décalerait sa colonne d'autant.
func LargeurVisible(s string) int {
	return utf8.RuneCountInString(codesANSI.ReplaceAllString(s, ""))
}

// Table accumule des lignes et les rend alignées.
//
// La largeur de chaque colonne est celle de son contenu le plus long, calculée
// à l'affichage. Aucune largeur n'est donc à deviner à l'écriture, et une
// valeur inhabituellement longue élargit sa colonne au lieu de pousser sa
// ligne.
type Table struct {
	entetes []string
	lignes  [][]string

	// SansCouleur désactive la coloration. Utile pour les tests, qui
	// compareraient sinon des chaînes truffées de séquences d'échappement, et
	// pour une sortie redirigée vers un fichier.
	SansCouleur bool
}

// NouvelleTable crée une table avec ses en-têtes.
func NouvelleTable(entetes ...string) *Table {
	return &Table{entetes: entetes}
}

// Ajouter ajoute une ligne.
//
// Une ligne plus courte que les en-têtes est complétée par des cellules vides,
// une ligne plus longue est tronquée. Les deux plutôt qu'une panique : un
// affichage est le dernier endroit où l'on veut qu'un décompte erroné arrête le
// programme, et la sortie tronquée se voit immédiatement.
func (t *Table) Ajouter(cellules ...string) {
	ligne := make([]string, len(t.entetes))
	for i := range ligne {
		if i < len(cellules) {
			ligne[i] = cellules[i]
		}
	}
	t.lignes = append(t.lignes, ligne)
}

// Vide indique qu'aucune ligne n'a été ajoutée.
func (t *Table) Vide() bool { return len(t.lignes) == 0 }

// String rend la table alignée.
func (t *Table) String() string {
	if len(t.entetes) == 0 {
		return ""
	}

	// Largeurs : le maximum entre l'en-tête et toutes les valeurs.
	largeurs := make([]int, len(t.entetes))
	for i, e := range t.entetes {
		largeurs[i] = LargeurVisible(e)
	}
	for _, ligne := range t.lignes {
		for i, c := range ligne {
			if l := LargeurVisible(c); l > largeurs[i] {
				largeurs[i] = l
			}
		}
	}

	entete := color.New(color.FgYellow, color.Bold).SprintFunc()
	if t.SansCouleur {
		entete = func(a ...any) string { return fmt.Sprint(a...) }
	}

	var sb strings.Builder

	// En-têtes. Le dernier n'est pas rembourré, pour la même raison que les
	// cellules de la dernière colonne.
	for i, e := range t.entetes {
		if i == len(t.entetes)-1 {
			sb.WriteString(entete(e))
			break
		}
		sb.WriteString(remplir(entete(e), LargeurVisible(e), largeurs[i]))
		sb.WriteString("  ")
	}
	sb.WriteString("\n")

	// Filet sous les en-têtes, à la largeur exacte du tableau.
	//
	// Calculé et non écrit en dur : une ligne de tirets d'une longueur fixe
	// dépasse ou s'arrête court dès que le contenu change, ce qui se remarque
	// plus qu'une absence de filet.
	total := 0
	for i, l := range largeurs {
		total += l
		if i < len(largeurs)-1 {
			total += 2
		}
	}
	sb.WriteString(strings.Repeat("─", total) + "\n")

	for _, ligne := range t.lignes {
		for i, c := range ligne {
			// La dernière colonne n'est pas rembourrée : rien ne la suit à
			// aligner, et les espaces de fin se retrouvent dans tout
			// copier-coller de la sortie.
			if i == len(ligne)-1 {
				sb.WriteString(c)
				break
			}
			sb.WriteString(remplir(c, LargeurVisible(c), largeurs[i]))
			sb.WriteString("  ")
		}
		sb.WriteString("\n")
	}

	return sb.String()
}

// remplir complète une cellule jusqu'à la largeur voulue.
//
// Le rembourrage est calculé sur la largeur VISIBLE passée en paramètre, et
// non sur len(contenu) : c'est tout l'objet de ce fichier.
func remplir(contenu string, visible, largeur int) string {
	if visible >= largeur {
		return contenu
	}
	return contenu + strings.Repeat(" ", largeur-visible)
}

// --- rendu des valeurs ------------------------------------------------------

// Valeur rend une chaîne, ou un marqueur lisible si elle est vide.
//
// « — » plutôt qu'une cellule blanche. Une case vide se confond avec un défaut
// d'affichage ; le tiret dit que la valeur est absente, ce qui est une
// information.
func Valeur(s string) string {
	if strings.TrimSpace(s) == "" {
		return "—"
	}
	return s
}

// Liste rend une liste sur une ligne, ou « aucun » si elle est vide.
func Liste(elements []string) string {
	if len(elements) == 0 {
		return "aucun"
	}
	return strings.Join(elements, ", ")
}

// OuiNon rend un booléen en français.
func OuiNon(v bool) string {
	if v {
		return "oui"
	}
	return "non"
}

// --- fiches -----------------------------------------------------------------

// Fiche affiche des couples libellé/valeur alignés.
//
// Pour le détail d'une entité, là où une table à une seule ligne serait
// illisible — vingt colonnes ne tiennent pas dans un terminal.
type Fiche struct {
	titre       string
	champs      [][2]string
	SansCouleur bool
}

// NouvelleFiche crée une fiche avec son titre.
func NouvelleFiche(titre string) *Fiche {
	return &Fiche{titre: titre}
}

// Ajouter ajoute un couple libellé/valeur.
func (f *Fiche) Ajouter(libelle, valeur string) {
	f.champs = append(f.champs, [2]string{libelle, valeur})
}

// AjouterSection insère un intertitre.
//
// Un libellé vide marque la section : elle s'affiche sans valeur, et sépare
// visuellement des groupes de champs qui n'ont pas le même sujet.
func (f *Fiche) AjouterSection(titre string) {
	f.champs = append(f.champs, [2]string{"", titre})
}

// marqueurElement distingue un élément de liste d'un couple libellé/valeur.
//
// Une chaîne qui ne peut pas apparaître dans une valeur réelle, plutôt qu'un
// troisième champ dans la structure : celle-ci est un tableau de deux chaînes,
// et l'élargir obligerait à toucher tous les appelants pour un cas particulier.
const marqueurElement = "\x00élément"

// AjouterElement ajoute une entrée de liste, sans valeur.
//
// # Pourquoi ce n'est pas Ajouter(nom, "")
//
// Un champ à valeur vide s'affiche « — », ce qui est juste : la valeur est
// absente. Mais un MEMBRE de groupe n'a pas de valeur du tout — écrire
// « alice — » laisse chercher ce qui manque, alors que rien ne manque.
//
// La distinction est celle entre « cette donnée est vide » et « cette ligne
// n'est pas un couple ».
func (f *Fiche) AjouterElement(nom string) {
	f.champs = append(f.champs, [2]string{nom, marqueurElement})
}

func (f *Fiche) String() string {
	titre := color.New(color.FgHiBlue, color.Bold).SprintFunc()
	libelle := color.New(color.FgYellow).SprintFunc()
	section := color.New(color.FgHiWhite, color.Bold).SprintFunc()
	if f.SansCouleur {
		nu := func(a ...any) string { return fmt.Sprint(a...) }
		titre, libelle, section = nu, nu, nu
	}

	// Largeur des libellés : celle du plus long, sections et éléments de liste
	// exclus.
	//
	// Les éléments sont exclus parce qu'ils n'ont pas de valeur à aligner : un
	// nom de groupe de quarante caractères élargirait la colonne des libellés
	// pour tous les champs de la fiche, sans qu'aucune valeur ne s'y trouve.
	largeur := 0
	for _, c := range f.champs {
		if c[0] == "" || c[1] == marqueurElement {
			continue
		}
		if l := LargeurVisible(c[0]); l > largeur {
			largeur = l
		}
	}

	var sb strings.Builder
	sb.WriteString(titre(f.titre) + "\n")
	sb.WriteString(strings.Repeat("─", LargeurVisible(f.titre)) + "\n")

	for _, c := range f.champs {
		if c[0] == "" {
			sb.WriteString("\n" + section(c[1]) + "\n")
			continue
		}
		if c[1] == marqueurElement {
			// Élément de liste : un tiret d'énumération, pas un couple.
			sb.WriteString("  - " + c[0] + "\n")
			continue
		}
		sb.WriteString("  " + remplir(libelle(c[0]), LargeurVisible(c[0]), largeur))
		sb.WriteString("  " + Valeur(c[1]) + "\n")
	}
	return sb.String()
}
