//go:build !linux

package gpo

import (
	"errors"
	"fmt"
	"os"
)

// La traversée sûre du scope utilisateur n'existe que sur Linux — TO-DO 97.
//
// # Pourquoi un fichier de repli plutôt qu'aucun
//
// L'agent est un programme Linux : il pose des comptes locaux, écrit dans
// `/etc/shadow` et parle à PAM. Mais le paquet `gpo` COMPILAIT jusqu'ici pour
// tous les systèmes, et plusieurs outils de développement — `go vet` croisé,
// une analyse depuis un poste macOS — s'appuient sur ce fait.
//
// Le repli rend donc une erreur explicite plutôt que de faire échouer la
// compilation. Ce qu'il ne fait SURTOUT pas, c'est retomber sur `os.MkdirAll` et
// `os.Chown` : ce serait rétablir exactement la faille ailleurs, dans un chemin
// que personne ne relit parce qu'il ne tourne nulle part.
var ErrCheminSuspect = errors.New("chemin suspect sous le repertoire personnel")

const indisponible = "l'ecriture sure du scope utilisateur demande les appels " +
	"openat/renameat de Linux ; ce systeme n'est pas pris en charge"

func ecrireFichierUtilisateur(_, chemin, _ string, _ os.FileMode, _, _ int) error {
	return fmt.Errorf("%s (%s)", indisponible, chemin)
}

func preparerRepertoireUtilisateur(_, chemin string, _ os.FileMode, _, _ int) error {
	return fmt.Errorf("%s (%s)", indisponible, chemin)
}
