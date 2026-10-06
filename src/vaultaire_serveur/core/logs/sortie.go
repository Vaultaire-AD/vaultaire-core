package logs

import "sync/atomic"

// Sortie supplémentaire : le journal centralisé en base (TO-DO 91).
//
// # Pourquoi une fonction branchée, et pas un appel direct à la base
//
// Ce paquet est importé par TOUT le serveur, base de données comprise : la
// couche `core/database` journalise ses erreurs par lui. Importer la base d'ici
// créerait un cycle. C'est `main`, qui voit les deux, qui fait la liaison —
// même motif que permission.SetRevokedChecker.
//
// # Ce que la sortie a le droit de faire
//
// Elle est appelée depuis `writeEntry`, c'est-à-dire depuis n'importe quelle
// goroutine du serveur, à chaque ligne. Elle ne doit donc JAMAIS bloquer ni
// écrire en base elle-même : une base lente ralentirait alors chaque requête
// qui journalise, et une base arrêtée figerait le core entier au premier
// `Write_Log`. Celle de la base se contente de poser l'entrée dans une file
// bornée (voir dbjournaux.Ecrivain).

// Sortie reçoit chaque entrée émise, après la sortie standard et la mémoire.
type Sortie func(LogEntry)

// sortie est lue sans verrou à chaque ligne de journal : un pointeur atomique
// plutôt qu'un mutex, pour que brancher la sortie au démarrage ne coûte rien
// aux lignes qui suivent.
var sortie atomic.Pointer[Sortie]

// BrancherSortie installe la sortie supplémentaire. Nil la retire.
//
// Les lignes émises AVANT le branchement ne lui sont pas rejouées : elles
// restent sur la sortie standard et en mémoire. Le branchement a lieu dès que
// la table existe, donc seules les toutes premières lignes du démarrage —
// lecture de la configuration, ouverture de la base — manquent en base.
func BrancherSortie(s Sortie) {
	if s == nil {
		sortie.Store(nil)
		return
	}
	sortie.Store(&s)
}

// transmettre passe une entrée à la sortie branchée, s'il y en a une.
func transmettre(e LogEntry) {
	if p := sortie.Load(); p != nil {
		(*p)(e)
	}
}
