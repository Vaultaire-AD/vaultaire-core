package main

import (
	"fmt"
	"time"

	"duckynetworkclient/V1/ducky"
)

// Le raccordement au core, en fond — TO-DO 158.
//
// # Le défaut
//
// main attendait une session authentifiée — trente secondes au plus — AVANT
// d'ouvrir le moindre relais. Sans core joignable, le proxy s'arrêtait sur
// « aucune session authentifiée après 30s », sans avoir ouvert un port.
//
// Le TO-DO 141 l'avait rendu plus visible sans le corriger : le proxy garde
// sur disque la dernière liste de relais reçue du core, précisément pour
// repartir sans lui — et, à froid, cette copie n'était jamais lue. Un site
// dont le proxy redémarre pendant une coupure du lien perdait donc aussi ses
// relais vers des cibles LOCALES, qui n'ont pas besoin du core. En conteneur,
// la politique de redémarrage le relançait toutes les trente secondes, pour
// rien.
//
// # La règle
//
// Les relais s'ouvrent d'abord, depuis la copie locale ou le fichier. Ce qui a
// besoin d'une session — s'annoncer au cluster, apprendre les cores et les
// services, rendre compte des relais — l'attend ici, sans limite.
//
// # L'absence de core n'arrête plus le proxy : elle se lit
//
// L'arrêt servait d'alarme. Il est remplacé par une ligne ERROR au bout du
// délai qui faisait s'arrêter le proxy, puis par un rappel périodique tant que
// rien n'a abouti : un proxy sans core relaie ce qu'il peut, mais il n'est
// annoncé à aucun agent et ne reçoit plus rien du cluster — c'est un incident,
// et le journal doit le dire aussi longtemps qu'il dure.
//
// # Ce que cela ne change pas
//
// Un proxy SANS IDENTITÉ doit s'enrôler, et l'enrôlement demande un core : un
// premier démarrage sans core échoue toujours, avant d'arriver ici. Et le
// relais Ducky sans core n'a rien vers quoi relayer : il écoute, et refuse
// franchement — l'agent passe au nœud suivant, ce qui est le comportement
// voulu.

const (
	// PremiereAlarme : le temps laissé à la session avant la première ligne
	// ERROR. C'est le délai au bout duquel le proxy s'arrêtait.
	PremiereAlarme = ducky.DefaultTimeout
	// RappelSansCore espace les lignes suivantes. Celui du bilan des relais :
	// les deux se lisent ensemble.
	RappelSansCore = PeriodeBilan
)

// raccordement réunit ce dont l'attente du core a besoin. Des fonctions, pour
// qu'un test la joue sans core ni réseau.
type raccordement struct {
	// attendre rend l'identifiant de la session dès qu'elle est authentifiée,
	// ou une erreur passé le délai — sans que la connexion soit abandonnée.
	attendre func(delai time.Duration) (string, error)
	// rejoindre annonce le proxy au cluster. Une erreur n'arrête rien.
	rejoindre func() error
	// ensuite est lancé une fois le proxy raccordé : le compte rendu des relais.
	ensuite func()
	// relaisActifs compte les relais qui écoutent, pour le dire dans l'alarme.
	relaisActifs func() int

	journal          func(niveau, message string)
	premiere, rappel time.Duration
	maintenant       func() time.Time
}

// executer attend le core sans limite, puis raccorde le proxy. Ne rend la main
// qu'une fois le proxy raccordé : à lancer dans une goroutine.
func (r raccordement) executer() {
	debut := r.maintenant()
	delai := r.premiere
	for {
		session, err := r.attendre(delai)
		if err == nil {
			depuis := r.maintenant().Sub(debut).Round(time.Second)
			r.journal("INFO", fmt.Sprintf("proxy en ligne, session %s (obtenue après %s)", session, depuis))
			break
		}
		r.journal("ERROR", fmt.Sprintf(
			"aucun core joint depuis %s : %d relais reste(nt) ouvert(s), la connexion est retentée sans fin. "+
				"Tant qu'elle n'aboutit pas, ce proxy n'est PAS annoncé aux agents, n'apprend ni cores ni services, "+
				"et ne reçoit pas ses relais du core. Dernier constat : %v",
			r.maintenant().Sub(debut).Round(time.Second), r.relaisActifs(), err))
		delai = r.rappel
	}

	// Un échec ici n'arrête PAS le proxy. Il est connecté et authentifié ; ce
	// qu'il perd est sa visibilité dans le cluster. Le traiter comme fatal
	// ferait qu'un défaut de déclaration — nom d'hôte introuvable, aucune
	// adresse non locale — coupe un service qui fonctionne par ailleurs.
	if err := r.rejoindre(); err != nil {
		r.journal("ERROR", fmt.Sprintf(
			"raccordement au cluster impossible : %v — le proxy reste connecté et ses relais ouverts, "+
				"mais il n'apparaîtra pas dans la liste des nœuds joignables", err))
	}
	r.ensuite()
}
