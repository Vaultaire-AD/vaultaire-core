package filter

import (
	"math/big"
	"strings"
	"time"

	ldapinterface "vaultaire/core/ldap/LDAP_SEARCH-REQUEST/newmodule/candidate/ldap_interface"
)

// evalOrdre applique `>=` et `<=` — RFC 4511 §4.5.1, filtres greaterOrEqual (5)
// et lessOrEqual (6).
//
// # Ce qui se passait avant
//
// Rien. Les deux types étaient correctement DÉCODÉS par le parseur, puis
// tombaient dans le `default` du switch d'évaluation, qui rendait `false` sans
// journaliser — sa ligne d'avertissement était commentée.
//
// Le client recevait donc `success` avec zéro entrée. Pas d'erreur de son côté,
// pas de trace du nôtre : le pire mode de panne possible, puisque rien n'a l'air
// cassé. `(uidNumber>=1000)` et `(whenCreated>=20260101000000Z)` ne rendaient
// jamais rien, et un `>=` sur une date est la première chose qu'essaie un outil
// de synchronisation incrémentale.
//
// # La sémantique
//
// Un attribut est multivalué : l'assertion est vraie si AU MOINS une valeur la
// satisfait. C'est la règle de la RFC, et l'inverse — exiger que toutes la
// satisfassent — rendrait `(memberOf>=x)` faux dès qu'un groupe ne convient pas.
func evalOrdre(entry ldapinterface.LDAPEntry, attr, assertion string, superieur bool) bool {
	attr = strings.ToLower(strings.TrimSpace(attr))
	assertion = strings.TrimSpace(assertion)

	// Une assertion vide n'ordonne rien. La comparer ferait passer toute valeur
	// pour « supérieure », donc `(cn>=)` rendrait l'annuaire entier.
	if assertion == "" {
		return false
	}

	for _, valeur := range entry.GetAttribute(attr) {
		c, comparable := comparer(strings.TrimSpace(valeur), assertion)
		if !comparable {
			// Valeur INCOMPARABLE à l'assertion : on passe, on ne devine pas.
			//
			// C'est le cas d'un `(employeeNumber>=9)` face à une valeur « 10 bis ».
			// La comparer comme du texte donnerait « 1 » avant « 9 », donc un refus —
			// un résultat FAUX, et faux en silence, exactement le mode de panne que
			// ce point corrige. Ne rien dire d'une valeur qu'on ne sait pas ordonner
			// est la seule réponse honnête.
			continue
		}
		if superieur && c >= 0 {
			return true
		}
		if !superieur && c <= 0 {
			return true
		}
	}
	return false
}

// comparer ordonne deux valeurs d'attribut, et dit si elles sont comparables.
//
// # Le mode est choisi par l'ASSERTION, pas par la valeur
//
// Une première version le choisissait par valeur : deux entrées du même ordre de
// grandeur recevaient alors des verdicts opposés dans la même recherche, parce
// que « 10 » se comparait en nombre et « 10 bis » en texte — où « 1 » vient avant
// « 9 ». Le résultat était faux, pas absent.
//
// C'est le client qui dit ce qu'il compare, en écrivant son assertion. Une valeur
// qui n'entre pas dans ce moule est déclarée INCOMPARABLE, et l'appelant la passe.
//
// # Trois modes, dans cet ordre
//
//  1. Horodatage, si l'assertion en est un. Comparer du GeneralizedTime comme du
//     texte n'est juste que pour la forme `Z` : « 20260315120000+0200 » placé
//     face à « 20260315120000Z » donne « + » (0x2B) avant « Z », donc un instant
//     déclaré antérieur à un instant qu'il suit.
//  2. Numérique, si l'assertion est un entier. `big.Int` et non `int64` : une
//     valeur qui déborde ne se lirait plus comme un nombre, et « dix milliards de
//     milliards » passerait pour inférieur à « 999 ».
//  3. Texte, sinon. Insensible à la casse, ce qui APPROCHE
//     `caseIgnoreOrderingMatch` sans l'égaler : au-delà de l'ASCII, c'est un ordre
//     d'octets et non un ordre de collation.
func comparer(valeur, assertion string) (int, bool) {
	if tb, ok := horodatage(assertion); ok {
		ta, ok := horodatage(valeur)
		if !ok {
			return 0, false
		}
		return ta.Compare(tb), true
	}

	if b, ok := new(big.Int).SetString(assertion, 10); ok {
		a, ok := new(big.Int).SetString(valeur, 10)
		if !ok {
			return 0, false
		}
		return a.Cmp(b), true
	}

	return strings.Compare(strings.ToLower(valeur), strings.ToLower(assertion)), true
}

// horodatage lit un GeneralizedTime — RFC 4517 §3.3.13.
//
// Les deux formes que les clients emploient : « Z » pour UTC, et un décalage
// explicite. La seconde est celle qui rendait la comparaison de texte fausse.
func horodatage(v string) (time.Time, bool) {
	for _, forme := range []string{"20060102150405Z", "20060102150405-0700"} {
		if t, err := time.Parse(forme, v); err == nil {
			return t, true
		}
	}
	return time.Time{}, false
}

// evalApproche applique `~=` — RFC 4511 §4.5.1, filtre approxMatch (8).
//
// # Ce qu'il fait, et ce qu'il ne fait pas
//
// Une égalité insensible à la casse, et rien de plus. Ce n'est PAS une vraie
// correspondance approchée : il n'y a ni soundex ni distance d'édition.
//
// C'est un choix, pas un oubli. Un client qui écrit `~=` accepte l'à-peu-près ;
// ce qu'il n'accepte pas, c'est zéro résultat là où il en attendait. Rendre un
// SOUS-ENSEMBLE de ce qu'une vraie correspondance approchée rendrait est sans
// danger — on ne montre rien de plus que ce qu'une égalité montrerait — alors
// que l'inverse divulguerait des entrées que le client n'a pas demandées.
//
// Le jour où une vraie correspondance approchée sera écrite, ce point d'entrée
// est le seul à changer.
func evalApproche(entry ldapinterface.LDAPEntry, attr, assertion string) bool {
	return evalEquality(entry, attr, assertion)
}
