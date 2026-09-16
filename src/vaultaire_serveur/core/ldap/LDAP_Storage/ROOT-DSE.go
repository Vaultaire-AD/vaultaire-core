package ldapstorage

type RootDSE struct {
	NamingContexts          []string
	RootDomainNamingContext []string
	SupportedLDAPVersion    []string
	SupportedSASLMechanisms []string
	SupportedControl        []string
	SupportedExtension      []string
	ForestFunctionality     []string
	DomainFunctionality     []string
	DSAName                 []string
	VendorName              string
	VendorVersion           string
}
