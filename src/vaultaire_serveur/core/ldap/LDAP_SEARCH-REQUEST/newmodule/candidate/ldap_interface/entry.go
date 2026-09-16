package ldapinterface

type LDAPEntry interface {
	DN() string
	GetAttribute(attr string) []string
	GetAttributes(attrs []string, typesOnly bool) map[string][]string
	ObjectClasses() []string
}
