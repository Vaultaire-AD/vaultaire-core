package reglages

import (
	"strconv"
	"time"
)

// Les durées DÉRIVÉES de la vérification en ligne (TO-DO 110).
//
// # Le défaut
//
// `check_online_minutes` se règle de une à soixante minutes. Trois durées en
// dépendaient et n'en dépendaient pas dans le code : la tolérance de silence du
// balayage (cinq minutes), la validité d'une session en base (dix minutes), et
// — sur l'agent — le délai après lequel il ferme lui-même son tunnel (dix
// minutes). Toutes trois étaient des constantes, justifiées dans leurs
// commentaires « par rapport à la valeur par défaut de deux minutes ».
//
// Porter la cadence à six minutes faisait donc couper par le balayage toutes
// les sessions authentifiées avant leur battement suivant. À onze, les lignes
// en base expiraient entre deux battements et les agents fermaient leur
// tunnel. Rien ne l'interdisait, rien ne le signalait, et le symptôme — « le
// parc se déconnecte en boucle » — ne désignait pas le réglage qu'on venait de
// changer.
//
// Une QUATRIÈME s'y ajoutait, hors de ce paquet : l'échéance de lecture posée
// sur chaque connexion authentifiée (netguard.SessionReadTimeout, dix minutes).
// Elle fermait le socket d'une session saine dès que la cadence dépassait dix
// minutes, quoi que tolère le balayage. Elle est bornée par la tolérance
// calculée ici — voir echeanceDeLecture, dans le paquet duckynetwork.
//
// # La règle
//
// Chaque durée est CALCULÉE depuis la cadence, avec un plancher qui est sa
// valeur d'avant : à la cadence par défaut, rien ne change. C'est le geste de
// dbgpo.ToleranceRapport, où « trois cycles » se calcule depuis le réglage au
// lieu de s'écrire en dur.
//
// Ces fonctions sont PURES, à côté de leurs versions qui lisent le réglage :
// le test qui parcourt toutes les cadences admises n'a besoin d'aucune base.

const (
	// PlancherToleranceDeSilence est la tolérance de silence aux cadences
	// courtes — la valeur fixe d'avant le TO-DO 110.
	PlancherToleranceDeSilence = 5 * time.Minute

	// PlancherValiditeDeSession est la validité d'une ligne de session aux
	// cadences courtes — la valeur fixe d'avant le TO-DO 110.
	PlancherValiditeDeSession = 10 * time.Minute

	// PrefixeCadenceEnLigne ouvre la ligne qui annonce la cadence à l'agent,
	// en queue de la 02_11. Écrit aussi dans le SDK (paquet enligne) : rien ne
	// lie les deux à la compilation, comme pour les autres lignes préfixées
	// (« refresh: », « disco: »).
	PrefixeCadenceEnLigne = "online:"
)

// ToleranceDeSilencePour rend le silence au-delà duquel une session
// AUTHENTIFIÉE est fermée par le balayage, pour une cadence donnée.
//
// Deux cadences plus une minute : le core envoie un 02_11 par cadence, et le
// balayage passe dans le même tour, juste après. Une session saine a donc, à
// ce moment, UNE cadence de silence — sa réponse au battement qui vient de
// partir n'est pas encore arrivée. Deux cadences laissent passer un battement
// perdu ; la minute couvre le temps de réponse et le décalage du tour.
//
// C'est la même formule que sessionmgr.FraicheurTunnel, à dessein : un tunnel
// cesse d'être préféré exactement quand il devient coupable.
func ToleranceDeSilencePour(cadence time.Duration) time.Duration {
	t := 2*cadence + time.Minute
	if t < PlancherToleranceDeSilence {
		return PlancherToleranceDeSilence
	}
	return t
}

// ValiditeDeSessionPour rend la durée de vie d'une ligne de session en base
// (did_login, user_sessions), pour une cadence donnée.
//
// La tolérance de silence, plus une cadence. L'invariant est celui-ci : une
// ligne en base ne doit JAMAIS expirer avant la session en mémoire qu'elle
// décrit. Tant que le balayage tolère une session, sa ligne doit exister —
// sinon `status -c` perd une machine que le core tient encore pour connectée.
// La cadence de plus couvre le battement qui la rafraîchira.
func ValiditeDeSessionPour(cadence time.Duration) time.Duration {
	v := ToleranceDeSilencePour(cadence) + cadence
	if v < PlancherValiditeDeSession {
		return PlancherValiditeDeSession
	}
	return v
}

// ToleranceDeSilence lit le réglage. Relue à chaque appel : « settings set
// check_online_minutes » prend effet au tour suivant, sans redémarrage.
func ToleranceDeSilence() time.Duration {
	return ToleranceDeSilencePour(Duree(CleVerificationEnLigne))
}

// ValiditeDeSession lit le réglage.
func ValiditeDeSession() time.Duration {
	return ValiditeDeSessionPour(Duree(CleVerificationEnLigne))
}

// LigneCadenceEnLigne rend la ligne « online:<minutes> » que le core place en
// queue de chaque 02_11.
//
// # Pourquoi l'agent doit la connaître
//
// L'agent ferme lui-même un tunnel resté dix minutes sans trafic — c'est ce
// qui lui fait quitter un core mort. Or, entre deux cycles de GPO, le SEUL
// trafic d'un tunnel est le 02_11 du core. À une cadence de dix minutes ou
// plus, chaque agent fermait donc son tunnel entre deux battements, quoi que
// le core calcule de son côté.
//
// En queue et préfixée : un agent antérieur à la 2.2 ne lit pas le contenu de
// la 02_11, et l'ignore.
func LigneCadenceEnLigne() string {
	return PrefixeCadenceEnLigne + strconv.Itoa(Valeur(CleVerificationEnLigne))
}
