package logs

import (
	"io"
	"os"
	"sync/atomic"
)

// Où vont les lignes de journal : la sortie standard, sauf pour une commande
// d'exploitation hors ligne (TO-DO 235).
//
// `vaultaire_serveur --publish-package` lit la configuration du core, qui
// journalise (« ldap.limites : bornes en vigueur … ») : la ligne arrivait en
// tête de la SORTIE de la commande, mêlée au compte rendu qu'on lit ou qu'on
// filtre. Une commande rend son résultat sur la sortie standard ; le journal
// qu'elle déclenche au passage va sur l'erreur standard.
var dest atomic.Pointer[io.Writer]

// VersErreurStandard envoie les lignes de journal sur l'erreur standard.
func VersErreurStandard() { RedirigerVers(os.Stderr) }

// RedirigerVers envoie les lignes de journal vers w ; nil rend la sortie
// standard.
func RedirigerVers(w io.Writer) {
	if w == nil {
		dest.Store(nil)
		return
	}
	dest.Store(&w)
}

func destination() io.Writer {
	if p := dest.Load(); p != nil {
		return *p
	}
	return os.Stdout
}
