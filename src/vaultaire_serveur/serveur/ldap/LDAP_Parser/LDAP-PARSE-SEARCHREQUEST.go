package ldapparser

import (
	ldapstorage "DUCKY/serveur/ldap/LDAP_Storage"
	"fmt"

	ber "github.com/go-asn1-ber/asn1-ber"
)

func parseSearchRequest(p *ber.Packet) (ldapstorage.SearchRequest, error) {
	if len(p.Children) < 8 {
		return ldapstorage.SearchRequest{}, fmt.Errorf("SearchRequest has too few children")
	}

	baseObject, ok := p.Children[0].Value.(string)
	if !ok {
		return ldapstorage.SearchRequest{}, fmt.Errorf("baseObject is not string")
	}

	scope, ok := p.Children[1].Value.(int64)
	if !ok {
		return ldapstorage.SearchRequest{}, fmt.Errorf("scope is not int64")
	}

	derefAliases, ok := p.Children[2].Value.(int64)
	if !ok {
		return ldapstorage.SearchRequest{}, fmt.Errorf("derefAliases is not int64")
	}

	sizeLimit, ok := p.Children[3].Value.(int64)
	if !ok {
		return ldapstorage.SearchRequest{}, fmt.Errorf("sizeLimit is not int64")
	}

	timeLimit, ok := p.Children[4].Value.(int64)
	if !ok {
		return ldapstorage.SearchRequest{}, fmt.Errorf("timeLimit is not int64")
	}

	typesOnly, ok := p.Children[5].Value.(bool)
	if !ok {
		return ldapstorage.SearchRequest{}, fmt.Errorf("typesOnly is not bool")
	}

	filter := p.Children[6] // Ce sera un arbre, à parser plus tard
	attributesPacket := p.Children[7]

	var attributes []string
	for _, attr := range attributesPacket.Children {
		if str, ok := attr.Value.(string); ok {
			attributes = append(attributes, str)
		}
	}

	return ldapstorage.SearchRequest{
		BaseObject:   baseObject,
		Scope:        int(scope),
		DerefAliases: int(derefAliases),
		SizeLimit:    int(sizeLimit),
		TimeLimit:    int(timeLimit),
		TypesOnly:    typesOnly,
		Filter:       filter,
		Attributes:   attributes,
	}, nil
}
