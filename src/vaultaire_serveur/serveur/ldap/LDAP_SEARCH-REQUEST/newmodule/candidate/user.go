package candidate

import (
	ldaptools "DUCKY/serveur/ldap/LDAP-TOOLS"
	ldapstorage "DUCKY/serveur/ldap/LDAP_Storage"
	"fmt"
	"strings"
)

type UserEntry struct {
	User   ldapstorage.User
	BaseDN string
	Groups []string
	// Nouveaux champs pour compatibilité Nextcloud
	DisplayName string   // Firstname + Lastname
	GivenName   string   // Firstname
	Sn          string   // Lastname
	Uid         string   // Username
	MemberOf    []string // Groupes
}

func (u UserEntry) DN() string {
	return fmt.Sprintf("uid=%s,ou=users,%s", u.User.Username, ldaptools.DomainToDC(u.BaseDN))
}

func (u UserEntry) ObjectClasses() []string {
	return []string{"inetOrgPerson", "posixAccount", "organizationalPerson", "person", "user"}
}

func (u UserEntry) GetAttributes(requested []string, typesOnly bool) map[string][]string {
	// Tous les attributs possibles pour l'utilisateur
	all := map[string][]string{
		"uid":            {u.User.Username},
		"samaccountname": {u.User.Username},
		"cn":             {u.User.Firstname + " " + u.User.Lastname},
		"displayname":    {u.User.Firstname + " " + u.User.Lastname},
		"givenname":      {u.User.Firstname},
		"sn":             {u.User.Lastname},
		"mail":           {u.User.Email},
		"memberof":       u.Groups,
		"dn":             {u.DN()},
		// "ou":             {"users"},
		"objectclass": {"inetOrgPerson", "posixAccount"},
		"entryuuid":   {fmt.Sprintf("vaultaire-%s", u.User.Username)},
		"nsuniqueid":  {fmt.Sprintf("vaultaire-%s", u.User.Username)},
		"objectguid":  {fmt.Sprintf("vaultaire-%s", u.User.Username)},
		"guid":        {fmt.Sprintf("vaultaire-%s", u.User.Username)},
		"ipauniqueid": {fmt.Sprintf("vaultaire-%s", u.User.Username)},
	}

	result := make(map[string][]string)
	includeAll := len(requested) == 0 || contains(requested, "*")
	includeOperational := contains(requested, "+")

	for k, v := range all {
		// Si opérationnel et non demandé → skip
		if isOperational(k) && !includeOperational {
			// Ne pas skip si on a une vraie valeur
			if len(v) > 0 {
				result[k] = v
			}
			continue
		}

		// Si demandé ou tout (*) → ajouter
		if includeAll || contains(requested, k) {
			if typesOnly {
				result[k] = []string{}
			} else {
				result[k] = v
			}
		}
	}

	return result
}

func (u UserEntry) GetAttribute(attr string) []string {
	attr = strings.ToLower(attr)
	res := u.GetAttributes([]string{attr}, false)
	return res[attr]
}

// helpers
func contains(list []string, s string) bool {
	for _, item := range list {
		if strings.EqualFold(item, s) {
			return true
		}
	}
	return false
}

func isOperational(attr string) bool {
	switch strings.ToLower(attr) {
	case "entryuuid", "nsuniqueid", "objectguid", "guid", "ipauniqueid":
		return true
	default:
		return false
	}
}
