package ldapstorage

import "fmt"

type User struct {
	ID          int
	Username    string
	GroupDomain string // nom de domaine via le groupe
	Firstname   string
	Lastname    string
	Email       string
	Created_at  string
}

type LDAPUserResponse struct {
	Username  string
	Firstname string
	Lastname  string
	Email     string
	Enable    string
	Expire    string
	Keys      string
	Comment   string // ici = GroupDomain, jamais vide car user remonte via groupe
}

type Group struct {
	GroupName  string
	DomainName string
	Users      []string // liste des usernames ou DN selon ton usage
}

//	func GetGroupAttrs(group Group) map[string][]string {
//		return map[string][]string{
//			"dn":          {fmt.Sprintf("cn=%s,dc=%s", group.GroupName, group.DomainName)},
//			"cn":          {group.GroupName},
//			"groupName":   {group.GroupName},
//			"member":      group.Users,
//			"description": {"Groupe LDAP"},
//			"objectclass": {"groupOfNames"},
//		}
//	}
func GetGroupAttrs(group Group) map[string][]string {
	attrs := make(map[string][]string, 6) // Pre-allocate map for 6 elements
	attrs["dn"] = []string{fmt.Sprintf("cn=%s,dc=%s", group.GroupName, group.DomainName)}
	attrs["cn"] = []string{group.GroupName}
	attrs["groupName"] = []string{group.GroupName}
	attrs["member"] = group.Users
	attrs["description"] = []string{"Groupe LDAP"}
	attrs["objectclass"] = []string{"groupOfNames"}
	return attrs
}

// LDAPFilterType représente les types RFC 4511
type LDAPFilterType int

const (
	FilterAnd LDAPFilterType = iota
	FilterOr
	FilterNot
	FilterEquality
	FilterSubstring
	FilterPresent
	FilterGreaterOrEqual
	FilterLessOrEqual
	FilterApprox
)

// LDAPFilter est un nœud de filtre LDAP
type LDAPFilter struct {
	Type       LDAPFilterType
	Attribute  string
	Value      string
	SubFilters []*LDAPFilter
}
