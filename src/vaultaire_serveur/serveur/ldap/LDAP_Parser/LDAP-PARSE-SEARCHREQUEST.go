package ldapparser

import (
	ldapstorage "DUCKY/serveur/ldap/LDAP_Storage"
	"fmt"

	ber "github.com/go-asn1-ber/asn1-ber"
)

// parseSearchRequest reste inchangé
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

	filter, err := DecodeLDAPFilter(p.Children[6])
	if err != nil {
		return ldapstorage.SearchRequest{}, err
	}

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

// DecodeLDAPFilter construit récursivement un arbre LDAPFilter conforme RFC 4511
func DecodeLDAPFilter(p *ber.Packet) (*ldapstorage.LDAPFilter, error) {
	if p == nil {
		return nil, fmt.Errorf("nil LDAP filter packet")
	}

	// LDAP filters MUST be context-specific
	if p.ClassType != ber.ClassContext {
		return nil, fmt.Errorf("invalid filter class %d (expected context-specific)", p.ClassType)
	}

	switch p.Tag {

	// (& ...)
	case 0: // AND
		return decodeLogicalFilter(ldapstorage.FilterAnd, p)

	// (| ...)
	case 1: // OR
		return decodeLogicalFilter(ldapstorage.FilterOr, p)

	// (! ...)
	case 2: // NOT
		if len(p.Children) != 1 {
			return nil, fmt.Errorf("NOT filter must have exactly one child")
		}
		child, err := DecodeLDAPFilter(p.Children[0])
		if err != nil {
			return nil, err
		}
		return &ldapstorage.LDAPFilter{
			Type:       ldapstorage.FilterNot,
			SubFilters: []*ldapstorage.LDAPFilter{child},
		}, nil

	// (attr=value)
	case 3: // equalityMatch
		return decodeAttributeValueFilter(ldapstorage.FilterEquality, p)

	// (attr~=value)
	case 8: // approxMatch
		return decodeAttributeValueFilter(ldapstorage.FilterApprox, p)

	// (attr>=value)
	case 5: // greaterOrEqual
		return decodeAttributeValueFilter(ldapstorage.FilterGreaterOrEqual, p)

	// (attr<=value)
	case 6: // lessOrEqual
		return decodeAttributeValueFilter(ldapstorage.FilterLessOrEqual, p)

		// (attr=*)
	case 7: // present
		var attr string

		// Source la plus fiable (toujours présente)
		if p.Data != nil && len(p.Data.Bytes()) > 0 {
			attr = string(p.Data.Bytes())
		} else if v, ok := p.Value.(string); ok {
			attr = v
		} else if len(p.ByteValue) > 0 {
			attr = string(p.ByteValue)
		} else if len(p.Children) == 1 {
			attr = string(p.Children[0].ByteValue)
		}

		if attr == "" {
			return nil, fmt.Errorf(
				"present filter missing attribute (tag=%d class=%d)",
				p.Tag, p.ClassType,
			)
		}

		return &ldapstorage.LDAPFilter{
			Type:      ldapstorage.FilterPresent,
			Attribute: attr,
		}, nil
	case 4: // substrings
		return decodeSubstringFilter(p)

	default:
		return nil, fmt.Errorf("unsupported LDAP filter tag %d", p.Tag)
	}
}

func decodeLogicalFilter(t ldapstorage.LDAPFilterType, p *ber.Packet) (*ldapstorage.LDAPFilter, error) {
	if len(p.Children) == 0 {
		return nil, fmt.Errorf("logical filter has no children")
	}

	filter := &ldapstorage.LDAPFilter{
		Type: t,
	}

	for _, child := range p.Children {
		sub, err := DecodeLDAPFilter(child)
		if err != nil {
			return nil, err
		}
		filter.SubFilters = append(filter.SubFilters, sub)
	}

	return filter, nil
}
func decodeAttributeValueFilter(
	t ldapstorage.LDAPFilterType,
	p *ber.Packet,
) (*ldapstorage.LDAPFilter, error) {

	if len(p.Children) != 2 {
		return nil, fmt.Errorf("attribute-value filter must have 2 children")
	}

	attr := string(p.Children[0].ByteValue)
	val := string(p.Children[1].ByteValue)

	if attr == "" {
		return nil, fmt.Errorf("empty attribute in filter")
	}

	return &ldapstorage.LDAPFilter{
		Type:      t,
		Attribute: attr,
		Value:     val,
	}, nil
}

func decodePresentFilter(p *ber.Packet) (*ldapstorage.LDAPFilter, error) {
	var attr string
	if len(p.Children) > 0 {
		attr = string(p.Children[0].ByteValue)
	} else if len(p.ByteValue) > 0 {
		attr = string(p.ByteValue)
	} else {
		attr = "" // "any attribute"
	}

	return &ldapstorage.LDAPFilter{
		Type:      ldapstorage.FilterPresent,
		Attribute: attr,
	}, nil
}

func decodeSubstringFilter(p *ber.Packet) (*ldapstorage.LDAPFilter, error) {
	if len(p.Children) < 2 {
		return nil, fmt.Errorf("invalid substring filter")
	}

	attr := string(p.Children[0].ByteValue)
	if attr == "" {
		return nil, fmt.Errorf("substring filter missing attribute")
	}

	filter := &ldapstorage.LDAPFilter{
		Type:      ldapstorage.FilterSubstring,
		Attribute: attr,
	}

	for _, part := range p.Children[1].Children {
		filter.SubFilters = append(filter.SubFilters, &ldapstorage.LDAPFilter{
			Type:  ldapstorage.FilterSubstring,
			Value: string(part.ByteValue),
		})
	}

	return filter, nil
}
