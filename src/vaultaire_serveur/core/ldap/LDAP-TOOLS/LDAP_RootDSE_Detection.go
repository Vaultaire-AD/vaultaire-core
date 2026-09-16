package ldaptools

import "strings"

// Bases spéciales définies par la RFC 4512.
//
// Elles ne désignent aucune entrée de l'annuaire : le DN vide est le RootDSE,
// « cn=schema » et son synonyme « cn=subschema » sont le sous-schéma. Un client
// les interroge AVANT de s'authentifier, pour découvrir ce que le serveur sait
// faire.
const (
	SchemaDN    = "cn=schema"
	SubschemaDN = "cn=subschema"
)

// IsRootDSEBase dit si un baseObject désigne une base spéciale.
//
// # Pourquoi une seule fonction pour tout le paquet
//
// La détection était écrite à trois endroits, avec trois règles différentes :
//
//	LDAP-Operation-Parser.go  baseObject == "" || baseObject == "cn=schema"
//	handler.go                idem, puis strings.EqualFold juste après
//	scope/resolver.go         EqualFold sur cn=schema ET cn=subschema
//
// Les écarts n'étaient pas cosmétiques. « CN=Schema » passait le contrôle
// exigeant un bind — comparaison sensible à la casse — mais échappait au
// contrôle d'autorisation qui suivait, lui insensible. Et « cn=subschema » était
// traité comme une base ordinaire par le dispatcheur alors que le résolveur lui
// renvoyait le schéma.
//
// Les DN LDAP sont insensibles à la casse (RFC 4514) : la comparaison l'est
// donc aussi, partout, une seule fois.
func IsRootDSEBase(baseObject string) bool {
	trimmed := strings.TrimSpace(baseObject)
	if trimmed == "" {
		return true
	}
	return strings.EqualFold(trimmed, SchemaDN) || strings.EqualFold(trimmed, SubschemaDN)
}
