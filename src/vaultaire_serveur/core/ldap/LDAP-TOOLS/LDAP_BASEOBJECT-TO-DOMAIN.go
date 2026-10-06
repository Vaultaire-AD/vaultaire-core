package ldaptools

import "strings"

// ConvertLDAPBaseToDomainName extrait le domaine à partir d'un BaseObject LDAP.
//
// # Le défaut corrigé
//
// La reconnaissance du préfixe se faisait sur la forme minuscule, mais le
// retrait sur la forme d'ORIGINE : `strings.TrimPrefix("DC=Enov", "dc=")` ne
// retire rien. Un client qui écrivait `DC=Enov,DC=Local` — ce que tape la moitié
// des utilisateurs de `ldapsearch`, et ce que produisent plusieurs outils AD —
// obtenait donc le domaine « DC=Enov.DC=Local », qui ne correspond à rien.
//
// La suite en découlait sans rien dire : le contrôle d'accès refusait, et la
// recherche rendait un succès sans entrée. Le client voyait un annuaire vide et
// cherchait du côté de ses droits.
//
// Les descriptions d'attributs d'un DN sont insensibles à la casse (RFC 4514
// §3) : `DC=`, `dc=` et `Dc=` désignent le même attribut, et le serveur doit les
// traiter pareil.
//
// La VALEUR, elle, garde la casse que le client a envoyée — c'est sa donnée, pas
// à nous de la réécrire. Les comparaisons de domaines la normalisent chacune de
// leur côté (voir domain.NormaliserDomaine).
func ConvertLDAPBaseToDomainName(base string) string {
	parts := strings.Split(base, ",")
	var domainParts []string

	// On parcourt les parties de droite à gauche pour reconstruire le domaine
	for i := len(parts) - 1; i >= 0; i-- {
		part := strings.TrimSpace(parts[i])
		if len(part) > 3 && strings.EqualFold(part[:3], "dc=") {
			domainParts = append([]string{part[3:]}, domainParts...)
		}
	}

	return strings.Join(domainParts, ".")
}
