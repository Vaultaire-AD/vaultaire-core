package ldapstorage

type User struct {
	ID          int
	Username    string
	GroupDomain string // nom de domaine via le groupe
	Firstname   string
	Lastname    string
	Email       string
	// Created_at et Modified_at portent les dates telles que la BASE les rend.
	// La mise au format LDAP est faite au moment de servir l'attribut, par
	// ldaptools.VersGeneralizedTime — pas ici, pour que ces champs restent ce
	// qu'ils sont : des valeurs de colonnes.
	Created_at  string
	Modified_at string
	// EntryUUID est l'identifiant STABLE du compte (point 129) : la colonne
	// `entry_uuid`, posée à la création et jamais réattribuée. Vide si la base
	// n'en porte pas — l'attribut n'est alors pas servi.
	EntryUUID string
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
	// Dates telles que la base les rend — voir User.
	Created_at  string
	Modified_at string
	// EntryUUID : identifiant stable du groupe — voir User.
	EntryUUID string
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
	FilterExtensible
)

// LDAPFilter est un nœud de filtre LDAP
type LDAPFilter struct {
	Type       LDAPFilterType
	Attribute  string
	Value      string
	SubFilters []*LDAPFilter

	// Morceaux d'un filtre de sous-chaîne — RFC 4511 §4.5.1.
	//
	// Un SubstringFilter n'est PAS une chaîne : c'est un initial facultatif, une
	// suite de « any » dans l'ordre, et un final facultatif. « jo*n*doe » donne
	// SubInitial=jo, SubAny=[n], SubFinal=doe.
	//
	// Les concaténer en « jondoe » perd l'information de position et transforme
	// la recherche en égalité stricte : le filtre ne trouve alors plus rien, sauf
	// à tomber sur une entrée nommée littéralement « jondoe ».
	SubInitial string
	SubAny     []string
	SubFinal   string
}
