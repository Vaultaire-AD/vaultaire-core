package ldapsearchrequest

import (
	ldapstorage "DUCKY/serveur/ldap/LDAP_Storage"
	"fmt"

	ber "github.com/go-asn1-ber/asn1-ber"
)

func ExtractEqualityFilters(packet *ber.Packet) ([]ldapstorage.EqualityFilter, error) {
	var filters []ldapstorage.EqualityFilter

	var walk func(p *ber.Packet)
	walk = func(p *ber.Packet) {
		// Si c’est un EqualityMatch
		if p.Tag == 3 && p.ClassType == ber.ClassContext && len(p.Children) == 2 {
			attrPacket := p.Children[0]
			valPacket := p.Children[1]

			attr, ok1 := attrPacket.Value.(string)
			val, ok2 := valPacket.Value.(string)

			if ok1 && ok2 {
				filters = append(filters, ldapstorage.EqualityFilter{
					Attribute: attr,
					Value:     val,
				})
			}
		} else {
			// Si c’est un filtre composé (AND, OR, etc.), on traverse ses enfants
			for _, child := range p.Children {
				walk(child)
			}
		}
	}

	if packet == nil {
		return nil, fmt.Errorf("nil packet")
	}

	walk(packet)
	return filters, nil
}
