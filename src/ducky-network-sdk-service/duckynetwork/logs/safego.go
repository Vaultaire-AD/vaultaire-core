package logs

import (
	"fmt"
	"runtime/debug"
)

// Go lance une goroutine dont une panique ne tue pas le programme.
//
// # Le défaut que cela corrige
//
// L'agent lance une dizaine de goroutines et ne contenait qu'un seul recover().
// En Go, une panique dans une goroutine non protégée **termine tout le
// processus** — pas seulement la goroutine.
//
// Sur l'agent, cela veut dire : plus de GPO, plus de révocation, plus de canal
// PAM, plus de service d'allocation d'identifiants. Une trame malformée reçue
// du réseau suffisait donc à couper l'authentification de la machine entière.
//
// Ce n'est pas théorique : c'est exactement le défaut qui avait été trouvé côté
// core, où parseTrames rendait une structure vide et Split_Action indexait
// Message_Order[0] dessus.
//
// # Pourquoi rattraper plutôt que laisser tomber
//
// Une panique signale un état que le programme n'avait pas prévu, et l'école
// dit qu'il vaut mieux s'arrêter que continuer dans le doute. C'est vrai d'un
// programme qui fait UNE chose.
//
// L'agent en fait plusieurs, indépendantes. Qu'un cycle GPO échoue n'est pas une
// raison pour que la machine cesse d'authentifier ses utilisateurs — et un agent
// mort laisse le poste sans aucun recours, y compris pour l'administrateur venu
// réparer. Le raisonnement vaut pour tout service qui tient plusieurs fils : un
// proxy qui meurt d'une trame malformée coupe le réseau qu'il relaie.
//
// La pile est journalisée en CRITICAL : on rattrape, mais on ne cache pas.
func Go(nom string, f func()) {
	go func() {
		defer func() {
			if r := recover(); r != nil {
				Write_log("CRITICAL", fmt.Sprintf(
					"PANIQUE dans %s : %v\n%s", nom, r, debug.Stack()))
			}
		}()
		f()
	}()
}

// Recover protège une goroutine déjà lancée par un « go » ordinaire.
//
//	go func() {
//		defer logs.Recover("cycle GPO")
//		...
//	}()
//
// Pour les cas où la goroutine ne peut pas passer par Go — capture de variables,
// signature particulière.
func Recover(nom string) {
	if r := recover(); r != nil {
		Write_log("CRITICAL", fmt.Sprintf(
			"PANIQUE dans %s : %v\n%s", nom, r, debug.Stack()))
	}
}
