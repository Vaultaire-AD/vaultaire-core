package client

import "strings"

// Le refus d'authentification — trame 02_07 (TO-DO 159).
//
// # Une seule forme
//
//	02_07
//	serveur_central
//	<clé d'intégrité>
//	<compte>
//	<motif>
//
// Onze refus étaient composés à la main, et ils ne se ressemblaient pas :
//
//   - neuf ne portaient qu'UNE ligne de contenu, le motif. Le poste en lisait
//     deux — le compte, puis le motif —, sortait du tableau et paniquait : son
//     journal portait « index out of range » là où il devait porter « mot de
//     passe expiré » ;
//   - un dixième n'avait pas sa ligne de destination : tous ses champs étaient
//     décalés d'un rang ;
//   - le dernier, ajouté par le TO-DO 138, avait la bonne forme. C'est elle qui
//     devient la règle.
//
// Un agent antérieur à la 2.3 lit donc correctement TOUS les refus d'un core à
// jour — sans rien changer chez lui.
//
// # Le compte est celui que la trame annonçait
//
// Ce n'est pas un oracle : le core ne fait que renvoyer au demandeur le nom
// qu'il vient lui-même d'écrire. Le motif reste « Wrong login Data » pour un
// compte inconnu, un mot de passe faux, un compte révoqué ou trop de
// tentatives : rien ne distingue ces cas vus du réseau.

// CompteNonPrecise tient lieu de compte quand le core n'en connaît aucun. Une
// ligne vide ne voyagerait pas comme telle : le poste la perdrait au découpage,
// et prendrait le motif pour le compte.
const CompteNonPrecise = "-"

// Les motifs. Leur texte est celui qu'émettait déjà le core : des journaux, et
// peut-être des outils, le reconnaissent.
const (
	// MotifIdentifiants : compte inconnu, mot de passe faux, compte révoqué,
	// trop de tentatives, ou lecture impossible. Volontairement indistincts.
	MotifIdentifiants = "Wrong login Data"
	// MotifMotDePasseExpire n'est rendu qu'APRÈS un mot de passe prouvé : qui
	// le lit connaît déjà le mot de passe du compte.
	MotifMotDePasseExpire = "Password expired, change it on the web interface"
	// MotifDefiImpossible : le core n'a pas pu composer le défi.
	MotifDefiImpossible = "Auth Failed please retry"
	// MotifNonAuthentifie : défi inconnu, expiré, ou réponse fausse.
	MotifNonAuthentifie = "You are not authentificate"
	// MotifErreurInterne : le droit de connexion n'a pas pu être lu.
	MotifErreurInterne = "Something go wrong contact you administrator"
	// MotifMachineInterdite : le compte est authentifié, pas autorisé ici.
	MotifMachineInterdite = "you have not the authorisation for acces to this computeur"
)

const enTeteRefus = "02_07\n"

// Refus compose une 02_07.
//
// Le compte et le motif tiennent chacun sur UNE ligne, quoi qu'on y mette : un
// retour à la ligne glissé dans un nom de compte ajouterait une ligne au
// contenu, et le poste lirait autre chose que ce que le core a écrit.
func Refus(cleIntegrite, compte, motif string) string {
	compte = surUneLigne(compte)
	if compte == "" {
		compte = CompteNonPrecise
	}
	motif = surUneLigne(motif)
	if motif == "" {
		motif = MotifNonAuthentifie
	}
	return enTeteRefus + "serveur_central\n" + cleIntegrite + "\n" + compte + "\n" + motif
}

func surUneLigne(s string) string {
	s = strings.NewReplacer("\r", " ", "\n", " ").Replace(s)
	return strings.TrimSpace(s)
}

// EstUnRefus dit si une réponse composée par ce paquet est une 02_07.
func EstUnRefus(reponse string) bool {
	return strings.HasPrefix(reponse, enTeteRefus)
}

// DoitFermerApresRefus dit si la connexion doit être fermée une fois la
// réponse partie.
//
// # Le refus ferme la session qu'il refuse
//
// Une authentification refusée n'a plus rien à faire de sa connexion. Elle
// restait pourtant ouverte, côté core, jusqu'au balayage des poignées de main
// — une minute —, et c'est le POSTE qui la fermait, par accident : il
// paniquait en lisant le refus. Le core à jour émet des refus que tous les
// agents savent lire ; un agent antérieur ne panique donc plus, et ne
// fermerait plus rien. C'est au core de le faire, quelle que soit la version
// d'en face.
//
// Au passage : un essai refusé ne peut plus être suivi d'un autre sur la même
// connexion. Chaque essai repaie sa poignée de main.
//
// # Jamais une session authentifiée
//
// Un refus ne concerne que la session qui demandait à s'authentifier. Si elle
// l'est déjà — un tunnel machine —, la trame est une erreur de protocole, pas
// une raison de couper une machine du core.
func DoitFermerApresRefus(reponse string, sessionAuthentifiee bool) bool {
	return EstUnRefus(reponse) && !sessionAuthentifiee
}
