// Package version porte l'identité de version du SDK Ducky, et la forme
// commune à tous les composants qui l'emploient.
//
// # Deux sources, et pourquoi
//
// La version SÉMANTIQUE est une constante : elle dit ce que le composant
// PROMET — compatibilité, rupture — et c'est une décision humaine. La déduire
// du dépôt donnerait un numéro qui change à chaque correction de faute de
// frappe.
//
// Le COMMIT et la DATE sont injectés à la compilation. Ils disent ce qui a
// réellement été construit, et personne ne peut oublier de les monter.
//
// Ni l'un ni l'autre ne suffit seul. Une constante seule finit toujours par
// mentir — elle se monte à la main, donc un jour elle ne le sera pas. Un commit
// seul ne dit rien à qui lit un journal d'incident : « g1939a3b » n'annonce
// aucune compatibilité.
//
// # Ce que la version N'EST PAS
//
// Une décision. Le core l'AFFICHE et ne l'interprète jamais : aucun refus,
// aucun seuil, aucune comparaison. Un agent périmé se voit dans l'inventaire,
// il n'est pas coupé.
//
// C'est délibéré. Une règle de comparaison de versions se trompe sur les cas
// limites — et ici, se tromper veut dire fermer la porte à un parc dont le seul
// outil de réparation est celui qu'on vient de fermer.
package version

import "strings"

// Version du SDK Ducky. Constante, décidée par un humain.
//
// Elle répond à « avec quel socle réseau ce binaire a-t-il été construit »,
// question que Lorens pose explicitement au point 39 : un agent et un proxy
// peuvent porter des versions différentes tout en partageant le même SDK, ou
// l'inverse.
const Version = "2.1.0"

// Commit et Date sont posés à la compilation par auto-compil.sh :
//
//	go build -ldflags "-X duckynetworkclient/V1/duckynetwork/version.Commit=..."
//
// # Pourquoi « dev » et non une chaîne vide
//
// Un `go build` lancé à la main hors du script ne les pose pas. La valeur de
// repli est AFFICHÉE telle quelle, jamais masquée : un binaire construit à la
// main sur un poste de développement doit se reconnaître dans l'inventaire du
// parc. C'est même la première chose qu'on veut savoir devant une machine qui
// se comporte mal.
var (
	Commit = "dev"
	Date   = "inconnue"
)

// Info décrit la version d'un composant.
//
// Un TYPE et non quatre chaînes libres : la mise en forme est alors écrite une
// fois, et l'agent comme le proxy la rendent à l'identique. Deux composants qui
// annonceraient leur version dans deux formats différents obligeraient le core
// à savoir lire les deux.
type Info struct {
	// Composant : « vaultaire_client », « vaultaire_proxy »…
	Composant string
	// Semantique : la constante du composant.
	Semantique string
	// Commit et Date : ce qui a été compilé.
	Commit string
	Date   string
}

// Complete rend « 2.1.0+g1939a3b (2026-08-14) ».
//
// Le « + » suit la convention SemVer des métadonnées de build : ce qui le suit
// n'entre dans aucune comparaison d'ordre. C'est exactement le statut qu'on
// veut donner au commit — informatif, jamais décisionnel.
//
// # Une seule ligne, et sans séparateur ambigu
//
// La valeur voyage dans l'inventaire 02_12, dont les champs sont séparés par
// des sauts de ligne. Un retour à la ligne dans la version décalerait tous les
// champs suivants ; les espaces et parenthèses, eux, ne gênent personne.
func (i Info) Complete() string {
	base := i.Semantique
	if c := nettoyer(i.Commit); c != "" && c != "dev" {
		base += "+" + c
	}
	if d := nettoyer(i.Date); d != "" && d != "inconnue" {
		base += " (" + d + ")"
	}
	if i.Commit == "dev" {
		// DIT, et non masqué. Un binaire compilé hors du script de build est
		// une information, pas un détail à cacher.
		base += " (build local)"
	}
	return base
}

// SDK rend la version du socle réseau lui-même.
func SDK() Info {
	return Info{
		Composant:  "ducky-network-sdk",
		Semantique: Version,
		Commit:     Commit,
		Date:       Date,
	}
}

// nettoyer écarte ce qui casserait le format de l'inventaire.
//
// Les valeurs viennent de `-ldflags`, donc du script de build, donc en principe
// d'un `git describe` — mais une variable d'environnement mal remplie y
// mettrait n'importe quoi, et cette chaîne traverse une trame à champs séparés
// par des sauts de ligne.
func nettoyer(v string) string {
	v = strings.TrimSpace(v)
	v = strings.ReplaceAll(v, "\n", "")
	v = strings.ReplaceAll(v, "\r", "")
	return v
}
