package ldaptools

import (
	"strings"
)

// ExtractUsernameAndDomain analyse un nom LDAP ou UPN et renvoie le username, le domaine et éventuellement l'OU.
// Exemples acceptés :
//   - "uid=jdupont,ou=IT,dc=example,dc=com"
//   - "cn=Admin,dc=ynov,dc=local"
//   - "jdupont@ldap.domain.com"
//   - "jdupont"
func ExtractUsernameAndDomain(ldapName string) (username, domain, ou string) {
	ldapName = strings.TrimSpace(ldapName)

	// 🔹 Cas 1 : format username@domain
	if strings.Contains(ldapName, "@") && !strings.Contains(ldapName, "=") {
		parts := strings.SplitN(ldapName, "@", 2)
		username = parts[0]
		domain = parts[1]
		return username, domain, ""
	}

	// 🔹 Cas 2 : pas de DN, juste un nom d’utilisateur simple
	if !strings.Contains(ldapName, "=") {
		return ldapName, "", ""
	}

	// 🔹 Cas 3 : format LDAP DN (uid=...,ou=...,dc=...)
	parts := strings.Split(ldapName, ",")

	var cn string
	var dcParts []string

	for _, part := range parts {
		part = strings.TrimSpace(part)
		partLower := strings.ToLower(part)

		// Le test porte sur la version minuscule, mais la découpe DOIT porter
		// sur la version d'origine — sinon la VALEUR perdrait sa casse.
		//
		// La version précédente testait `partLower` puis tranchait `part` avec
		// `TrimPrefix(part, "uid=")` : sur « UID=jdupont », le préfixe minuscule
		// ne s'y trouve pas, rien n'est retiré, et l'utilisateur devenait
		// littéralement « UID=jdupont ». Le domaine, lui, devenait
		// « DC=example.DC=com ».
		//
		// RFC 4514 §3 : le NOM du type d'attribut n'est pas sensible à la casse.
		// Un client qui écrit UID= est aussi conforme qu'un qui écrit uid=, et
		// les outils Microsoft écrivent volontiers en majuscules.
		switch {
		case strings.HasPrefix(partLower, "uid="):
			cn = part[len("uid="):]
		case strings.HasPrefix(partLower, "cn="):
			cn = part[len("cn="):]
		case strings.HasPrefix(partLower, "ou="):
			ou = part[len("ou="):]
		case strings.HasPrefix(partLower, "dc="):
			dcParts = append(dcParts, part[len("dc="):])
		}
	}

	domain = strings.Join(dcParts, ".")
	return cn, domain, ou
}
