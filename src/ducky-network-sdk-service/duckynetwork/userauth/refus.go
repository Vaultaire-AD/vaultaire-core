package userauth

import (
	"fmt"
	"strings"
	"time"

	"duckynetworkclient/V1/backoff"
	"duckynetworkclient/V1/duckynetwork/logs"
	"duckynetworkclient/V1/duckynetwork/storage"
	"duckynetworkclient/V1/duckynetwork/storage/stosession"
	"duckynetworkclient/V1/sessionmgr"
)

// Le refus d'authentification (trame 02_07) — TO-DO 159.
//
// # Le défaut
//
// Le gestionnaire lisait le contenu ainsi :
//
//	lines := strings.Split(trames_content.Content, "\n")
//	… lines[0], lines[1]
//
// Il attendait donc DEUX lignes : le compte, puis le motif. Neuf des onze
// refus du core n'en portaient qu'une — « Wrong login Data », « You are not
// authentificate », « Password expired… ». `lines[1]` sortait du tableau, le
// traitement de la trame paniquait, et la panique était récupérée par la
// boucle de réception, qui fermait la connexion.
//
// Deux conséquences. Le journal portait « Panic récupéré dans handleConnection
// … index out of range » là où il devait porter le MOTIF. Et la fermeture de
// la session refusée n'était décidée nulle part : c'était un effet de bord de
// la panique. Les deux refus qui portaient bien deux lignes ne paniquaient
// pas — donc ne fermaient rien, et laissaient une session ouverte, jamais
// authentifiée, jusqu'à ce que le core la balaie une minute plus tard.
//
// # La règle
//
// Un refus se LIT quelle que soit sa forme, et il FERME la session qu'il
// refuse — par décision, plus par accident.
//
// # Seulement la session qu'il refuse
//
// 02_07 répond à une demande d'authentification (02_01, 02_03) : la session
// qui le reçoit n'est pas authentifiée, et n'a plus rien à attendre. Mais un
// core antérieur à la 2.3 émet aussi un 02_07 DANS LE TUNNEL d'une machine,
// quand une demande d'ouverture de session (03_01) est malformée. Ce tunnel-là
// est authentifié, il porte les GPO, la révocation et les connexions de tous
// les comptes du poste : le fermer pour une requête mal écrite couperait la
// machine. Une session déjà authentifiée journalise donc le refus, et reste.

// CompteNonPrecise est ce que le core écrit à la place du compte quand il ne
// le connaît pas (un défi inconnu, par exemple). Une ligne vide ne voyagerait
// pas : elle disparaîtrait au découpage, et le motif prendrait sa place.
const CompteNonPrecise = "-"

// MotifNonPrecise est le motif retenu quand le core n'en a donné aucun.
const MotifNonPrecise = "motif non precise par le core"

// LireRefus rend le compte et le motif d'un refus 02_07, quelle que soit la
// forme de son contenu.
//
//	deux lignes ou plus   compte, puis motif (les lignes suivantes s'y ajoutent)
//	une ligne             c'est le MOTIF ; le compte est inconnu
//	rien                  ni l'un ni l'autre
//
// Une seule ligne est le motif et non le compte : c'est la forme qu'émet un
// core antérieur à la 2.3, et le compte est de toute façon connu de qui a
// demandé — le motif, lui, ne se lit nulle part ailleurs.
//
// Le compte rendu vaut « » quand il est inconnu. Le motif n'est jamais vide.
func LireRefus(contenu string) (compte, motif string) {
	var lignes []string
	for _, l := range strings.Split(contenu, "\n") {
		if l = strings.TrimSpace(l); l != "" {
			lignes = append(lignes, l)
		}
	}
	switch len(lignes) {
	case 0:
		return "", MotifNonPrecise
	case 1:
		return "", lignes[0]
	}
	compte = lignes[0]
	if compte == CompteNonPrecise {
		compte = ""
	}
	return compte, strings.Join(lignes[1:], " ")
}

// statutDe est remplaçable par les tests : le registre des sessions est global.
var statutDe = func(sessionID string) (sessionmgr.SessionStatus, bool) {
	return stosession.SessionsUser.GetStatus(sessionID)
}

// marquerEnEchec est remplaçable par les tests, pour la même raison.
var marquerEnEchec = func(sessionID string) {
	stosession.SessionsUser.SetStatus(sessionID, sessionmgr.SessionFailed)
}

// traiterRefus journalise un refus et, si la session n'est pas authentifiée,
// la marque refusée — ce qui la ferme.
//
// Rend vrai quand la session est marquée.
func traiterRefus(contenu string, duckysession *storage.DuckySession) bool {
	compte, motif := LireRefus(contenu)
	qui := "compte non precise"
	if compte != "" {
		qui = "compte " + compte
	}

	if duckysession == nil {
		logs.Write_log("WARNING", fmt.Sprintf("Authentification refusee par le core (%s) : %s", qui, motif))
		return false
	}

	if statut, connue := statutDe(duckysession.SessionID); connue && statut == sessionmgr.SessionAuthenticated {
		// Le tunnel est authentifié : ce refus ne peut pas être le sien.
		logs.Write_log("WARNING", fmt.Sprintf(
			"Refus 02_07 recu sur une session deja authentifiee (id=%s, %s) : %s — la session est conservee",
			duckysession.SessionID, qui, motif))
		return false
	}

	logs.Write_log("WARNING", fmt.Sprintf(
		"Authentification refusee par le core (session id=%s, %s) : %s — session fermee",
		duckysession.SessionID, qui, motif))
	duckysession.Refus = motif
	marquerEnEchec(duckysession.SessionID)
	return true
}

// DelaiDeReprise rend le temps à attendre avant de rouvrir une session qui
// vient de se terminer, et dit si elle avait été refusée.
//
// # Pourquoi le refus ne remet pas le délai à zéro
//
// La boucle de reconnexion repart du délai le plus court dès qu'une CONNEXION
// aboutit — c'est-à-dire avant de savoir si le core acceptera l'authentification.
// Un programme refusé à chaque essai revenait donc toutes les deux secondes,
// indéfiniment, chaque essai coûtant au core une poignée de main RSA. Le délai
// n'est remis à zéro que par une session qui n'a PAS été refusée ; après un
// refus il continue de doubler, jusqu'à son plafond.
func DelaiDeReprise(attente *backoff.Backoff, duckysession *storage.DuckySession) (time.Duration, bool) {
	refusee := duckysession != nil && duckysession.Refus != ""
	if !refusee {
		attente.Reset()
	}
	return attente.Prochain(), refusee
}
