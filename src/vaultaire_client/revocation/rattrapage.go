package revocation

import (
	"time"

	"duckynetworkclient/V1/duckynetwork/logs"
)

// Réclamer les ordres en attente : quand, et à quel rythme — TO-DO 134.
//
// # Ce qui était écrit, et ce qui était fait
//
// Trois commentaires de ce paquet et la documentation de conception disaient :
// « la demande 06_04 part à chaque démarrage ET à chaque reconnexion du
// tunnel ». Elle ne partait qu'une fois, d'une goroutine lancée à l'amorçage de
// l'agent. Un ordre émis pendant que le tunnel était tombé restait donc en
// attente jusqu'au REDÉMARRAGE DU SERVICE — sur un poste qui ne redémarre pas,
// cela veut dire jamais. Couper le réseau d'une machine une minute au bon
// moment suffisait à la soustraire à une révocation.
//
// # Deux déclencheurs
//
//   - une session NEUVE : la clé de session a changé, donc le tunnel est tombé
//     puis revenu, pour une durée qu'on ne connaît pas. C'est le rattrapage
//     promis ;
//   - un RAPPEL périodique tant que la session tient. Il sert le cas que la
//     reconnexion ne couvre pas : un ordre que le core a tenté de pousser à une
//     machine connectée, et qui n'est pas arrivé — ou qui est arrivé, a échoué,
//     et attend d'être rejoué. Depuis le point 133 un ordre peut ÉCHOUER pour de
//     bon (des processus qui ne meurent pas) : sans rappel, « sera rejoué »
//     voulait dire « à la prochaine coupure du tunnel ».
//
// # Pourquoi une scrutation
//
// Même raison que `gpo.surveillerReconnexion` : le tunnel est remonté par un
// paquet qui n'expose aucune notification, la clé de session se lit en mémoire,
// et câbler un signal pour ce seul consommateur ferait dépendre la couche de
// transport de ce paquet.

const (
	// RappelDesOrdres est l'intervalle du rappel périodique.
	//
	// Dix minutes : une trame 06_04 et une lecture indexée côté core, par
	// machine. C'est le délai maximal pendant lequel un ordre poussé en vain à
	// une machine connectée reste sans effet. Une constante, et non un réglage :
	// c'est une borne de sûreté, pas une préférence d'exploitation — celui qui
	// l'allongerait pour économiser du trafic allongerait exactement la durée
	// pendant laquelle un compte coupé reste ouvert quelque part.
	RappelDesOrdres = 10 * time.Minute

	// pasDeSurveillance est l'intervalle de scrutation de la session.
	pasDeSurveillance = 2 * time.Second
)

// suiviDesDemandes retient ce qui a déjà été demandé.
type suiviDesDemandes struct {
	derniereCle     string
	derniereDemande time.Time
}

// doitDemander dit si une demande 06_04 est due, et pourquoi.
//
// Pure, avec l'instant en paramètre : la décision s'éprouve sans attendre dix
// minutes ni monter de tunnel.
func (s *suiviDesDemandes) doitDemander(cle string, maintenant time.Time) (bool, string) {
	switch {
	case cle == "":
		// Pas de session : rien à qui demander. La demande partira dès qu'une
		// clé apparaîtra — elle sera forcément différente de la dernière.
		return false, ""
	case s.derniereCle == "":
		return true, "demarrage"
	case cle != s.derniereCle:
		return true, "tunnel retabli"
	case maintenant.Sub(s.derniereDemande) >= RappelDesOrdres:
		return true, "rappel"
	}
	return false, ""
}

// noter retient qu'une demande vient de partir pour cette session.
func (s *suiviDesDemandes) noter(cle string, maintenant time.Time) {
	s.derniereCle, s.derniereDemande = cle, maintenant
}

// SurveillerLesOrdres réclame les ordres en attente au démarrage, à chaque
// tunnel rétabli, puis périodiquement. Ne rend jamais la main : à lancer dans
// sa propre goroutine.
//
// cleDeSession est réévaluée à chaque tour : la clé change à chaque
// reconnexion, et c'est justement ce changement qu'on guette.
func SurveillerLesOrdres(cleDeSession func() string) {
	var suivi suiviDesDemandes
	for {
		cle := cleDeSession()
		if due, motif := suivi.doitDemander(cle, time.Now()); due {
			if motif != "rappel" {
				// Le rappel reste en DEBUG (celui d'AskPending) : dix lignes à
				// l'heure par machine noieraient les deux qui comptent.
				logs.Write_log("INFO", "revocation: ordres en attente reclames ("+motif+")")
			}
			AskPending(cle)
			// Notée même si l'envoi n'a pas abouti : `AskPending` attend lui-même
			// une session valide, et une demande perdue sera refaite au rappel —
			// ou tout de suite, si le tunnel retombe et revient.
			suivi.noter(cle, time.Now())
		}
		time.Sleep(pasDeSurveillance)
	}
}
