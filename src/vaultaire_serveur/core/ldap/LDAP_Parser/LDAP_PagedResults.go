package ldapparser

import (
	"fmt"
	"math"

	ldapstorage "vaultaire/core/ldap/LDAP_Storage"

	ber "github.com/go-asn1-ber/asn1-ber"
)

// decoderPagedResults lit la valeur du contrôle de pagination — RFC 2696 §2 :
//
//	realSearchControlValue ::= SEQUENCE {
//	        size    INTEGER (0..maxInt),
//	        cookie  OCTET STRING }
//
// La valeur vient du réseau, d'un client qui n'est pas forcément bienveillant :
// DecodePacketErr et non DecodePacket, qui panique sur une entrée forgée, et
// chaque champ est vérifié avant d'être lu.
func decoderPagedResults(valeur []byte) (ldapstorage.PagedResults, error) {
	if len(valeur) == 0 {
		return ldapstorage.PagedResults{}, fmt.Errorf("contrôle de pagination sans valeur")
	}
	p, err := ber.DecodePacketErr(valeur)
	if err != nil {
		return ldapstorage.PagedResults{}, fmt.Errorf("contrôle de pagination illisible : %w", err)
	}
	if p == nil || p.ClassType != ber.ClassUniversal || p.Tag != ber.TagSequence || len(p.Children) != 2 {
		return ldapstorage.PagedResults{}, fmt.Errorf("contrôle de pagination : une séquence de deux éléments est attendue")
	}

	taille, ok := p.Children[0].Value.(int64)
	if !ok || p.Children[0].Tag != ber.TagInteger {
		return ldapstorage.PagedResults{}, fmt.Errorf("contrôle de pagination : la taille n'est pas un entier")
	}
	if taille < 0 || taille > math.MaxInt32 {
		return ldapstorage.PagedResults{}, fmt.Errorf("contrôle de pagination : taille %d hors de [0, maxInt]", taille)
	}

	if p.Children[1].Tag != ber.TagOctetString || p.Children[1].ClassType != ber.ClassUniversal {
		return ldapstorage.PagedResults{}, fmt.Errorf("contrôle de pagination : le cookie n'est pas une chaîne d'octets")
	}
	// Copié : ByteValue pointe dans le tampon du paquet reçu.
	cookie := append([]byte(nil), p.Children[1].Data.Bytes()...)

	return ldapstorage.PagedResults{Size: int(taille), Cookie: cookie}, nil
}

// extrairePagination cherche le contrôle de pagination parmi ceux du message.
//
// Rend nil, nil quand il n'y en a pas. Deux exemplaires du même contrôle sont
// une erreur de protocole : il n'existe aucune façon correcte de choisir lequel
// suivre.
func extrairePagination(controles []ldapstorage.LDAPControl) (*ldapstorage.PagedResults, error) {
	var trouve *ldapstorage.PagedResults
	for _, c := range controles {
		if c.ControlType != ldapstorage.OIDPagedResults {
			continue
		}
		if trouve != nil {
			return nil, fmt.Errorf("contrôle de pagination présent deux fois")
		}
		page, err := decoderPagedResults(c.ControlValue)
		if err != nil {
			return nil, err
		}
		trouve = &page
	}
	return trouve, nil
}
