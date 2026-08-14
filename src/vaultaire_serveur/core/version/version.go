// Package version porte l'identité de version du core.
//
// # Pourquoi ce paquet redit ce que fait celui du SDK
//
// `vaultaire` et `duckynetworkclient/V1` sont deux modules Go, et le serveur
// n'importe PAS le SDK — c'est lui qui juge les clients, il ne partage pas leur
// socle. Le type et la mise en forme sont donc écrits deux fois.
//
// La duplication est bornée et sans conséquence de protocole : le core ne
// PARSE jamais la version d'un agent, il la stocke et l'affiche. Les deux
// formats peuvent diverger sans rien casser — au pire une colonne se lit
// différemment selon la ligne, ce qui se voit.
//
// C'est ce qui distingue ce cas de `PrefixeGroupes` ou de la règle de calcul du
// GID, où une divergence d'un caractère casse en silence : là, des tests
// jumeaux figent la valeur. Ici, il n'y a rien à figer.
//
// # Le core n'interprète aucune version
//
// Aucun refus, aucun seuil, aucune comparaison — arbitrage retenu au point 39.
// La version est une donnée d'INVENTAIRE : elle répond à « qui est en retard »,
// question du point 40, sans jamais décider de fermer une porte.
//
// Une règle de comparaison de versions se trompe sur les cas limites, et se
// tromper ici veut dire couper un parc dont le seul outil de réparation est
// l'agent qu'on vient de refuser.
package version

import "strings"

// Version du core Vaultaire. Constante, décidée par un humain.
const Version = "2.1.0"

// Commit et Date sont posés à la compilation par auto-compil.sh.
//
// Repli affiché tel quel : un core construit à la main doit se reconnaître.
var (
	Commit = "dev"
	Date   = "inconnue"
)

// Complete rend « 2.1.0+g1939a3b (2026-08-14) ».
//
// Même forme que celle du SDK, volontairement : les deux apparaissent dans les
// mêmes vues, et deux mises en forme différentes se liraient comme deux natures
// de donnée différentes.
func Complete() string {
	base := Version
	if c := nettoyer(Commit); c != "" && c != "dev" {
		base += "+" + c
	}
	if d := nettoyer(Date); d != "" && d != "inconnue" {
		base += " (" + d + ")"
	}
	if Commit == "dev" {
		base += " (build local)"
	}
	return base
}

func nettoyer(v string) string {
	v = strings.TrimSpace(v)
	v = strings.ReplaceAll(v, "\n", "")
	v = strings.ReplaceAll(v, "\r", "")
	return v
}
