package ldaptools

import (
	"strings"
	"time"
)

// AttrCreeLe et AttrModifieLe sont les deux attributs opérationnels
// d'horodatage, en minuscules — la forme sous laquelle les entrées rangent leurs
// attributs.
const (
	AttrCreeLe    = "createtimestamp"
	AttrModifieLe = "modifytimestamp"
)

// VersGeneralizedTime met une date lue en base au format LDAP — RFC 4517 §3.3.13.
//
// # Pourquoi ce format et pas un autre
//
// `YYYYMMDDHHMMSSZ`, en UTC. C'est ce qu'attendent les clients, et c'est ce qui
// rend la comparaison de texte juste : le format est conçu pour que l'ordre des
// caractères soit l'ordre du temps. Servir l'heure locale, ou le format SQL
// `2026-03-15 12:00:00`, donnerait des dates qu'un client range dans le désordre
// sans rien signaler.
//
// # Ce qu'une date illisible devient
//
// RIEN — la chaîne vide, et l'attribut n'est pas servi. Un attribut sans valeur
// n'existe pas en LDAP (RFC 4512 §2.5), et surtout : une date fausse est pire
// qu'une date absente sur ce chemin précis. Un client incrémental qui lit une
// date aberrante saute des entrées ou les relit toutes, sans qu'aucune erreur ne
// le dise.
func VersGeneralizedTime(valeurSQL string) string {
	valeurSQL = strings.TrimSpace(valeurSQL)
	if valeurSQL == "" {
		return ""
	}

	// Les formes que le pilote MySQL rend selon la colonne et la configuration de
	// connexion. `DATETIME` arrive en texte, `parseTime` le rendrait en
	// time.Time — les deux passent par ici sous forme de chaîne.
	formes := []string{
		"2006-01-02 15:04:05",
		"2006-01-02T15:04:05Z",
		"2006-01-02 15:04:05.999999",
		"2006-01-02T15:04:05.999999Z",
		"2006-01-02T15:04:05-07:00",
		"2006-01-02",
	}
	for _, forme := range formes {
		if t, err := time.Parse(forme, valeurSQL); err == nil {
			return t.UTC().Format("20060102150405Z")
		}
	}
	return ""
}
