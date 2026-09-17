package ldapclient

import (
	"encoding/hex"
	"errors"
	"fmt"
	"strings"

	ber "github.com/go-asn1-ber/asn1-ber"
)

// Contextes des filtres (RFC 4511 §4.5.1).
const (
	filterAnd      = 0
	filterOr       = 1
	filterNot      = 2
	filterEquality = 3
	filterPresent  = 7
)

// CompileFilter encode un filtre. Sont pris en charge : &, |, !, l'égalité et
// la présence (attr=*) — ce qu'il faut pour trouver un compte et ses groupes.
func CompileFilter(s string) (*ber.Packet, error) {
	s = strings.TrimSpace(s)
	p, rest, err := compile(s)
	if err != nil {
		return nil, fmt.Errorf("filtre LDAP %q : %w", s, err)
	}
	if strings.TrimSpace(rest) != "" {
		return nil, fmt.Errorf("filtre LDAP %q : texte en trop", s)
	}
	return p, nil
}

func compile(s string) (*ber.Packet, string, error) {
	if !strings.HasPrefix(s, "(") {
		return nil, "", errors.New("parenthèse ouvrante attendue")
	}
	s = s[1:]
	if s == "" {
		return nil, "", errors.New("filtre tronqué")
	}
	switch s[0] {
	case '&', '|':
		tag := ber.Tag(filterAnd)
		if s[0] == '|' {
			tag = filterOr
		}
		p := ber.Encode(ber.ClassContext, ber.TypeConstructed, tag, nil, "set")
		s = s[1:]
		for strings.HasPrefix(s, "(") {
			child, rest, err := compile(s)
			if err != nil {
				return nil, "", err
			}
			p.AppendChild(child)
			s = rest
		}
		if !strings.HasPrefix(s, ")") {
			return nil, "", errors.New("parenthèse fermante attendue")
		}
		return p, s[1:], nil
	case '!':
		child, rest, err := compile(s[1:])
		if err != nil {
			return nil, "", err
		}
		if !strings.HasPrefix(rest, ")") {
			return nil, "", errors.New("parenthèse fermante attendue")
		}
		p := ber.Encode(ber.ClassContext, ber.TypeConstructed, filterNot, nil, "not")
		p.AppendChild(child)
		return p, rest[1:], nil
	}
	end := strings.IndexByte(s, ')')
	if end < 0 {
		return nil, "", errors.New("parenthèse fermante attendue")
	}
	item := s[:end]
	eq := strings.IndexByte(item, '=')
	if eq <= 0 {
		return nil, "", errors.New("attribut=valeur attendu")
	}
	attr, val := item[:eq], item[eq+1:]
	if strings.ContainsAny(attr, "<>~:") {
		return nil, "", errors.New("seule l'égalité est prise en charge")
	}
	if val == "*" {
		return ber.NewString(ber.ClassContext, ber.TypePrimitive, filterPresent, attr, "present"), s[end+1:], nil
	}
	if strings.Contains(val, "*") {
		return nil, "", errors.New("les jokers ne sont pas pris en charge")
	}
	raw, err := unescape(val)
	if err != nil {
		return nil, "", err
	}
	p := ber.Encode(ber.ClassContext, ber.TypeConstructed, filterEquality, nil, "equality")
	p.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, attr, "attr"))
	p.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, raw, "value"))
	return p, s[end+1:], nil
}

func unescape(v string) (string, error) {
	if !strings.Contains(v, `\`) {
		return v, nil
	}
	var b strings.Builder
	for i := 0; i < len(v); i++ {
		if v[i] != '\\' {
			b.WriteByte(v[i])
			continue
		}
		if i+3 > len(v) {
			return "", errors.New("échappement tronqué")
		}
		h, err := hex.DecodeString(v[i+1 : i+3])
		if err != nil {
			return "", errors.New("échappement invalide")
		}
		b.Write(h)
		i += 2
	}
	return b.String(), nil
}
