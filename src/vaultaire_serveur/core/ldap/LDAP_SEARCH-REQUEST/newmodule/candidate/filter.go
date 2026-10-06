package candidate

import (
	ldapinterface "vaultaire/core/ldap/LDAP_SEARCH-REQUEST/newmodule/candidate/ldap_interface"
	"vaultaire/core/ldap/LDAP_SEARCH-REQUEST/newmodule/filter"
	ldapstorage "vaultaire/core/ldap/LDAP_Storage"
)

// Filtre applique un filtre LDAP à une liste d'entrées.
//
// # Elle n'écrit plus rien au journal — TO-DO 145
//
// Elle en écrivait jusqu'à trois lignes PAR ENTRÉE candidate : « vérification
// de… », puis « correspond » ou « ne correspond pas ». Sur un annuaire de dix
// mille comptes, une seule recherche produisait trente mille lignes — et les
// messages étaient formatés à chaque fois, debug actif ou non, pour être jetés
// ensuite par le journal.
//
// Le filtre figure désormais sur la ligne de l'opération, sous sa forme de
// chaîne (ldapstorage.LDAPFilter.Texte), avec le nombre de candidats et
// d'entrées rendues. Le verdict entrée par entrée est écrit par le
// gestionnaire, en TRACE, sous l'identifiant de la connexion — que ce paquet
// ne voit pas.
func Filtre(entries []ldapinterface.LDAPEntry, f *ldapstorage.LDAPFilter, baseDN string, scope int) []ldapinterface.LDAPEntry {
	if f == nil {
		return entries
	}
	var result []ldapinterface.LDAPEntry
	for _, e := range entries {
		if filter.Evaluate(e, f, baseDN, scope) {
			result = append(result, e)
		}
	}
	return result
}
