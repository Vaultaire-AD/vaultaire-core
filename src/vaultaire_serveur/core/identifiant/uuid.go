// Package identifiant fabrique les identifiants STABLES des entrées de
// l'annuaire.
//
// # Pourquoi un paquet à part
//
// Trois endroits en ont besoin — la création d'un compte, celle d'un groupe, et
// la migration des lignes d'avant le point 129 — et aucun des trois ne doit
// dépendre des deux autres. Le paquet n'importe que la bibliothèque standard :
// il reste importable partout, sans cycle.
package identifiant

import (
	"crypto/rand"
	"fmt"
	"regexp"
)

// LongueurUUID est la longueur d'un UUID en texte : 32 chiffres hexadécimaux et
// quatre tirets.
const LongueurUUID = 36

// formeUUID est la représentation canonique de la RFC 4122, en minuscules.
var formeUUID = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)

// NouvelUUID tire un UUID de version 4 — aléatoire — et le rend en texte.
//
// # Aléatoire, et surtout pas dérivé du nom
//
// Un identifiant d'entrée sert à reconnaître une entrée APRÈS un renommage :
// c'est toute sa raison d'être (RFC 4530). Le dériver du nom — un UUID de
// version 5, ou le nom lui-même comme c'était le cas — le ferait changer
// exactement au moment où l'on a besoin qu'il ne change pas. Un client
// comme Keycloak voyait alors un compte renommé comme un compte neuf, et en
// créait un second.
//
// Une erreur ne peut venir que du générateur du système. Elle est rendue plutôt
// qu'avalée : un identifiant prévisible serait pire qu'un compte non créé.
func NouvelUUID() (string, error) {
	var o [16]byte
	if _, err := rand.Read(o[:]); err != nil {
		return "", fmt.Errorf("tirage d'un UUID : %w", err)
	}
	o[6] = (o[6] & 0x0f) | 0x40 // version 4
	o[8] = (o[8] & 0x3f) | 0x80 // variante RFC 4122
	return fmt.Sprintf("%x-%x-%x-%x-%x", o[0:4], o[4:6], o[6:8], o[8:10], o[10:16]), nil
}

// EstUnUUID dit si s est un UUID sous sa forme canonique, en minuscules.
//
// C'est la forme que la syntaxe UUID de la RFC 4530 attend d'un `entryUUID`.
// Une valeur qui ne la respecte pas n'est PAS servie : un client strict
// rejetterait l'entrée entière, et un identifiant faux est pire qu'un
// identifiant absent.
func EstUnUUID(s string) bool {
	return len(s) == LongueurUUID && formeUUID.MatchString(s)
}
