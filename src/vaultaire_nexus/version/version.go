// Package version porte l'identité de ce binaire.
//
// Même contrat que les paquets version du core, de l'agent et du proxy :
// Version est remplacée à la compilation d'une release (-ldflags -X), Commit et
// Date par auto-compil.sh. Les valeurs écrites ici ne servent qu'aux builds
// locaux.
package version

import "fmt"

// Version du dépôt Vaultaire Nexus.
var Version = "2.2.0"

var (
	Commit = "dev"
	Date   = "inconnue"
)

// Complete rend « 2.1.0+gabc1234 (2026-09-17) », ou « (build local) ».
func Complete() string {
	s := Version
	if Commit != "" && Commit != "dev" {
		s += "+" + Commit
	}
	if Date != "" && Date != "inconnue" {
		s += fmt.Sprintf(" (%s)", Date)
	}
	if Commit == "dev" {
		s += " (build local)"
	}
	return s
}
