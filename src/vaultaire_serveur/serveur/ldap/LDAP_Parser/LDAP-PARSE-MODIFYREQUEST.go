package ldapparser

import (
	ldapstorage "DUCKY/serveur/ldap/LDAP_Storage"
	"fmt"

	ber "github.com/go-asn1-ber/asn1-ber"
)

func parseExtendedRequest(p *ber.Packet) (ldapstorage.ExtendedRequest, error) {
	var req ldapstorage.ExtendedRequest

	if len(p.Children) == 0 {
		return req, fmt.Errorf("ExtendedRequest has no children")
	}

	// RequestName est un OCTET STRING obligatoire (tag 0)
	if p.Children[0].Tag != 0 {
		return req, fmt.Errorf("expected requestName tag 0, got %d", p.Children[0].Tag)
	}
	req.RequestName = string(p.Children[0].Data.String())

	// RequestValue est optionnel (tag 1)
	if len(p.Children) > 1 && p.Children[1].Tag == 1 {
		req.RequestValue = p.Children[1].Data.Bytes()
	}

	return req, nil
}
