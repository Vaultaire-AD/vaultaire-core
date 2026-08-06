package ldapparser

import (
	"fmt"
	"strings"
	ldapstorage "vaultaire/core/ldap/LDAP_Storage"
	"vaultaire/core/logs"

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

	// (attr:oid:=value) or (attr:dn:oid:=value)
	case 9: // extensibleMatch
		return decodeExtensibleMatchFilter(p)

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

	// Extraction de l'attribut (uid, mail...)
	attr := string(p.Children[0].ByteValue)
	if attr == "" {
		attr = fmt.Sprintf("%v", p.Children[0].Value)
	}

	filter := &ldapstorage.LDAPFilter{
		Type:      ldapstorage.FilterSubstring,
		Attribute: attr,
	}

	var fullValue strings.Builder
	// p.Children[1] est la séquence des morceaux
	for _, part := range p.Children[1].Children {
		// TEST 1: ByteValue
		val := string(part.ByteValue)

		// TEST 2: Si vide, on regarde Value
		if val == "" && part.Value != nil {
			val = fmt.Sprintf("%s", part.Value)
		}

		// TEST 3: Si toujours vide, on prend les Data brutes du paquet BER
		if val == "" && part.Data != nil {
			val = string(part.Data.Bytes())
		}

		fullValue.WriteString(val)
	}

	filter.Value = fullValue.String()

	return filter, nil
}

// decodeExtensibleMatchFilter handles extensibleMatch filters (RFC 4511 tag 9)
// Format: SEQUENCE { matchingRule [0] OBJECT IDENTIFIER OPTIONAL,
//
//	type [1] AttributeDescription OPTIONAL,
//	matchValue [2] AssertionValue,
//	dnAttributes [3] BOOLEAN DEFAULT FALSE }
func decodeExtensibleMatchFilter(p *ber.Packet) (*ldapstorage.LDAPFilter, error) {
	if len(p.Children) == 0 {
		return nil, fmt.Errorf("extensibleMatch filter has no children")
	}

	filter := &ldapstorage.LDAPFilter{
		Type: ldapstorage.FilterExtensible,
	}

	var matchValue string
	var attribute string

	// Process each child element
	for _, child := range p.Children {
		// Extract value - try Value, ByteValue, then Data
		val := ""
		if child.Value != nil {
			val = fmt.Sprintf("%s", child.Value)
		} else if len(child.ByteValue) > 0 {
			val = string(child.ByteValue)
		} else if child.Data != nil && child.Data.Len() > 0 {
			// Use Data when ByteValue is empty
			val = child.Data.String()
		}

		logs.Write_Log("DEBUG", fmt.Sprintf("extensibleMatch child tag=%d: value='%s'", child.Tag, val))

		switch child.Tag {
		case 0: // matchingRule [0] OBJECT IDENTIFIER
			// OID for matching rule
			matchValue = val
		case 1: // type [1] AttributeDescription
			// The attribute name to match against
			attribute = val
		case 2: // matchValue [2] AssertionValue
			// In this packet structure: tag 2 = attribute name
			if attribute == "" {
				attribute = val
			}
		case 3: // dnAttributes [3] or value [3]
			// In this packet structure: tag 3 = the DN value to match
			if matchValue == "" {
				matchValue = val
			}
		}
	}

	filter.Attribute = attribute
	filter.Value = matchValue

	logs.Write_Log("DEBUG", fmt.Sprintf("Decoded extensibleMatch: attribute=%s, value=%s", attribute, matchValue))

	return filter, nil
}

// func decodeSubstringFilter(p *ber.Packet) (*ldapstorage.LDAPFilter, error) {
// 	if len(p.Children) < 2 {
// 		return nil, fmt.Errorf("invalid substring filter")
// 	}

// 	attr := string(p.Children[0].ByteValue)
// 	if attr == "" {
// 		attr = p.Children[0].Value.(string)
// 	}

// 	filter := &ldapstorage.LDAPFilter{
// 		Type:      ldapstorage.FilterSubstring,
// 		Attribute: attr,
// 	}

// 	for _, part := range p.Children[1].Children {
// 		filter.SubFilters = append(filter.SubFilters, &ldapstorage.LDAPFilter{
// 			Type:  ldapstorage.FilterSubstring,
// 			Value: string(part.ByteValue),
// 		})
// 	}

// 	return filter, nil
// }
