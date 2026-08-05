// Package logs est le point de sortie des journaux du dossier.
//
// # Pourquoi une indirection plutôt qu'un appel direct
//
// Ce dossier est copié dans des programmes qui ont chacun leur journalisation :
// l'agent écrit dans /var/log/vaultaire_client, le proxy sur la sortie standard,
// un futur service ailleurs. Écrire en dur dans l'un d'eux obligerait à modifier
// le dossier à chaque copie — donc à le faire diverger, donc à perdre l'intérêt
// de la copie.
//
// Par défaut le dossier est MUET. Un programme qui veut voir quelque chose
// appelle SetWriter au démarrage.
package logs

import "sync"

// Writer reçoit un niveau et un message.
type Writer func(level, message string)

var (
	mu     sync.RWMutex
	writer Writer
)

// SetWriter branche la journalisation du programme hôte.
func SetWriter(w Writer) {
	mu.Lock()
	defer mu.Unlock()
	writer = w
}

// Write émet un événement, s'il y a quelqu'un pour l'écouter.
func Write(level, message string) {
	mu.RLock()
	w := writer
	mu.RUnlock()
	if w != nil {
		w(level, message)
	}
}
