package filter

import (
	"fmt"
	ldapinterface "vaultaire/core/ldap/LDAP_SEARCH-REQUEST/newmodule/candidate/ldap_interface"
	ldapstorage "vaultaire/core/ldap/LDAP_Storage"
	"vaultaire/core/logs"
)

// Evaluate applique un filtre LDAP à une entrée
func Evaluate(entry ldapinterface.LDAPEntry, f *ldapstorage.LDAPFilter, baseDN string, scope int) bool {
	if f == nil {
		return true
	}

	switch f.Type {

	case ldapstorage.FilterAnd:
		for _, c := range f.SubFilters {
			if !Evaluate(entry, c, baseDN, scope) {
				// fmt.Printf("[DEBUG] AND fail sur DN=%s pour sous-filtre %+v\n", entry.DN(), c)
				return false
			} else {
				// fmt.Printf("[DEBUG] AND success sur DN=%s pour sous-filtre %+v\n", entry.DN(), c)
			}
		}
		return true

	case ldapstorage.FilterOr:
		for _, c := range f.SubFilters {
			if Evaluate(entry, c, baseDN, scope) {
				// fmt.Printf("[DEBUG] OR success sur DN=%s pour sous-filtre %+v\n", entry.DN(), c)
				return true
			} else {
				// fmt.Printf("[DEBUG] OR fail sur DN=%s pour sous-filtre %+v\n", entry.DN(), c)
			}
		}
		return false

	case ldapstorage.FilterNot:
		if len(f.SubFilters) != 1 {
			// fmt.Printf("[WARN] NOT filter avec != 1 subfilter sur DN=%s\n", entry.DN())
			return false
		}
		res := !Evaluate(entry, f.SubFilters[0], baseDN, scope)
		// fmt.Printf("[DEBUG] NOT filter sur DN=%s => %v\n", entry.DN(), res)
		return res

	case ldapstorage.FilterSubstring:
		return evalSubstring(entry, f)

	case ldapstorage.FilterEquality:
		res := evalEquality(entry, f.Attribute, f.Value)
		// fmt.Printf("[DEBUG] Equality filter DN=%s attr=%s val=%s => %v (entry values=%v)\n",
		// 	entry.DN(), f.Attribute, f.Value, res, entry.GetAttribute(f.Attribute))
		return res

	case ldapstorage.FilterPresent:
		res := evalPresent(entry, f.Attribute)
		// fmt.Printf("[DEBUG] Present filter DN=%s attr=%s => %v (entry values=%v)\n",
		// 	entry.DN(), f.Attribute, res, entry.GetAttribute(f.Attribute))
		return res

	case ldapstorage.FilterGreaterOrEqual:
		return evalOrdre(entry, f.Attribute, f.Value, true)

	case ldapstorage.FilterLessOrEqual:
		return evalOrdre(entry, f.Attribute, f.Value, false)

	case ldapstorage.FilterApprox:
		return evalApproche(entry, f.Attribute, f.Value)

	default:
		// ATTEINT seulement si Verifier a ACCEPTÉ un type sans cas ici.
		//
		// Ce `default` rendait `false` en silence — sa ligne d'avertissement était
		// commentée — pour `greaterOrEqual`, `lessOrEqual` et `approxMatch`, que le
		// parseur décode pourtant correctement. Le client recevait « success » et
		// zéro entrée, sans qu'aucun des deux côtés ne voie quoi que ce soit
		// d'anormal.
		//
		// Les types sont nommés et non numérotés à dessein : la numérotation
		// INTERNE de LDAPFilterType n'est pas celle des étiquettes de la RFC 4511,
		// et un numéro dans un commentaire ou un message enverrait lire la mauvaise
		// ligne de la norme.
		//
		// Le refus est désormais prononcé UNE fois par recherche, par Verifier, qui
		// rend le code de résultat qui convient. Un type qu'il refuse n'arrive jamais
		// ici. Si l'on y passe malgré tout, c'est qu'il en a accepté un sans qu'un cas
		// existe pour lui : un défaut de programmation, qui mérite une ligne à lui —
		// et qu'un test interdit.
		logs.Write_Log("WARNING", fmt.Sprintf(
			"ldap: type de filtre %d non évalué sur %s — Verifier et Evaluate ont divergé",
			f.Type, entry.DN()))
		return false
	}
}
