package filter

import (
	"strings"

	ldapinterface "vaultaire/core/ldap/LDAP_SEARCH-REQUEST/newmodule/candidate/ldap_interface"
	ldapstorage "vaultaire/core/ldap/LDAP_Storage"
)

// evalSubstring applique un filtre de sous-chaîne — RFC 4511 §4.5.1.
//
// # Ce qui se passait avant
//
// Le filtre de sous-chaîne était traité comme une ÉGALITÉ sur la concaténation
// de ses morceaux. `(cn=jo*)` cherchait donc une entrée dont le cn vaut
// exactement « jo » : aucune recherche par préfixe ne rendait quoi que ce soit,
// et le symptôme côté client était une réponse vide parfaitement valide — le cas
// le plus difficile à diagnostiquer, puisque rien n'a l'air en panne.
//
// Pire, dans le cas dégénéré : `(cn=a*c)` cherchait « ac » et pouvait donc
// répondre pour une entrée sans rapport avec la recherche demandée.
//
// # La sémantique, dans l'ordre
//
//	initial   doit être un PRÉFIXE
//	any       doivent apparaître dans l'ORDRE, après initial et avant final
//	final     doit être un SUFFIXE
//
// L'ordre compte : « jo*n*doe » ne doit pas être satisfait par « jodoen ». Un
// simple `Contains` par morceau, sans avancer le curseur, l'accepterait.
//
// # Comparaison insensible à la casse
//
// Comme le reste du paquet, et comme le veut la règle de correspondance par
// défaut de `cn`, `uid` et `mail` (caseIgnoreMatch / caseIgnoreIA5Match).
func evalSubstring(entry ldapinterface.LDAPEntry, f *ldapstorage.LDAPFilter) bool {
	if f == nil {
		return false
	}
	attr := strings.ToLower(strings.TrimSpace(f.Attribute))

	// Un filtre sans aucun morceau, c'est-à-dire `(cn=*)`, est une assertion de
	// PRÉSENCE : le client demande les entrées qui portent l'attribut.
	if f.SubInitial == "" && f.SubFinal == "" && len(f.SubAny) == 0 {
		return evalPresent(entry, attr)
	}

	for _, brut := range entry.GetAttribute(attr) {
		if substringMatch(strings.ToLower(strings.TrimSpace(brut)), f) {
			return true
		}
	}
	return false
}

// substringMatch décide pour UNE valeur.
func substringMatch(valeur string, f *ldapstorage.LDAPFilter) bool {
	initial := strings.ToLower(f.SubInitial)
	final := strings.ToLower(f.SubFinal)

	if initial != "" {
		if !strings.HasPrefix(valeur, initial) {
			return false
		}
		valeur = valeur[len(initial):]
	}

	if final != "" {
		if !strings.HasSuffix(valeur, final) {
			return false
		}
		// Le suffixe est retiré AVANT d'examiner les morceaux intermédiaires :
		// sans cela, `(cn=a*b)` serait satisfait par « ab » en laissant « b »
		// jouer à la fois le rôle de final et celui d'un « any ».
		valeur = valeur[:len(valeur)-len(final)]
	}

	// Les morceaux intermédiaires, dans l'ordre, sans chevauchement : le curseur
	// avance après chaque trouvaille.
	for _, morceau := range f.SubAny {
		morceau = strings.ToLower(morceau)
		if morceau == "" {
			continue
		}
		i := strings.Index(valeur, morceau)
		if i < 0 {
			return false
		}
		valeur = valeur[i+len(morceau):]
	}

	return true
}
