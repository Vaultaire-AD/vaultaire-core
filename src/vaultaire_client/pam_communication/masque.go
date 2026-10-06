package pamcommunication

import (
	"net"
	"sync"
	"syscall"
)

// Ouvrir un socket Unix sous un masque de création choisi — TO-DO 165.
//
// # Le défaut
//
// L'agent ouvre DEUX sockets au démarrage, et chacun veut naître avec son
// mode : 0600 pour le canal PAM, 0666 pour le service d'allocation d'uid. Les
// deux écrivaient donc, chacun de son côté :
//
//	ancien := syscall.Umask(voulu)
//	ln, err := net.Listen("unix", chemin)
//	syscall.Umask(ancien)
//
// Le masque est celui du PROCESSUS, pas de la goroutine. Et les deux ouvertures
// sont concurrentes : le service d'uid part dans sa goroutine juste avant que
// `main` n'ouvre le canal PAM. Entrelacées, elles donnent :
//
//	PAM : ancien = Umask(0177)    → rend 022, le masque du service
//	UID : ancien = Umask(0)       → rend 0177, celui que PAM vient de poser
//	PAM : Umask(022)              → remet 022
//	UID : Umask(0177)             → « remet » 0177
//
// et le processus garde 0177 jusqu'à son arrêt. Tout ce que l'agent crée ensuite
// en hérite, lui et les commandes qu'il lance : un répertoire demandé en 0700
// naît en 0600 — sans le bit de traversée, donc inutilisable par son
// propriétaire —, et `useradd` crée le dossier personnel de même. Selon
// l'entrelacement, le masque final vaut aussi bien 0, et l'agent crée alors ce
// qu'il crée sans aucune retenue.
//
// Relevé le 06/10 en lançant pour la première fois un agent réel sur le banc :
// son /proc/<pid>/status portait « Umask: 0177 », et les dossiers posés par une
// GPO utilisateur sortaient en `drw-------`.
//
// # La correction
//
// Les deux ouvertures passent par cette fonction, qui tient un verrou le temps
// de poser le masque, d'ouvrir et de le remettre. Deux sections ne peuvent plus
// se croiser, donc aucune ne peut « remettre » le masque de l'autre.
//
// Il reste que le masque du processus change pendant quelques microsecondes au
// démarrage, pour tout le monde. Aucune écriture de l'agent ne tombe dans cette
// fenêtre — le tunnel n'est pas encore monté — et celles qui comptent posent
// leur mode elles-mêmes, sur le descripteur.
var masqueMu sync.Mutex

// ecouterSousMasque ouvre un socket Unix qui naît avec le mode que laisse
// `masque`, puis rend au processus le masque qu'il avait.
func ecouterSousMasque(chemin string, masque int) (net.Listener, error) {
	masqueMu.Lock()
	defer masqueMu.Unlock()

	ancien := syscall.Umask(masque)
	defer syscall.Umask(ancien)

	return net.Listen("unix", chemin)
}
