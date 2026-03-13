package ldapstorage

type LDAPParsedReceivedMessage struct {
	MessageID  int                   // messageID : INTEGER (Tag 2)
	ProtocolOp LDAPProtocolOperation // protocolOp : CHOICE (BindRequest, SearchRequest, etc.)
	Controls   []LDAPControl         `asn1:"optional,tag:0,explicit"` // controls : [0] (optionnel)
}

// LDAPProtocolOperation est une interface que chaque type de requête implémente
type LDAPProtocolOperation interface {
	OpType() string
}

// LDAPControl représente un contrôle LDAP (dans le champ controls)
type LDAPControl struct {
	ControlType  string
	Criticality  bool   //`asn1:"optional"`
	ControlValue []byte //`asn1:"optional"`
}

type BindRequest struct {
	Version        int
	Name           string
	Authentication []byte // pour simplifier ici, peut être struct plus complexe
}

func (b BindRequest) OpType() string {
	return "BindRequest"
}

type UnbindRequest struct{}

func (u UnbindRequest) OpType() string {
	return "UnbindRequest"
}

type ExtendedRequest struct {
	RequestName  string
	RequestValue []byte // optionnel
}

func (b ExtendedRequest) OpType() string {
	return "ExtendedRequest"
}

type SearchRequest struct {
	BaseObject   string
	Scope        int
	DerefAliases int
	SizeLimit    int
	TimeLimit    int
	TypesOnly    bool
	Filter       *LDAPFilter // brut pour l’instant
	Attributes   []string
}

func (s SearchRequest) OpType() string {
	return "SearchRequest"
}

type EqualityFilter struct {
	Attribute string
	Value     string
}
