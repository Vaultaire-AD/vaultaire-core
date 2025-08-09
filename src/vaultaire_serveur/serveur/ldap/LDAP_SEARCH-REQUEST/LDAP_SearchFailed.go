package ldapsearchrequest

import (
	"encoding/asn1"
	"fmt"
	"io"
	"net"
)

// Code d'échec typique (peut être ajusté)
const LDAPResultOperationsError = 1

// SendLDAPSearchFailure répond à une requête LDAP Search avec un message d'erreur.
func SendLDAPSearchFailure(conn net.Conn, messageID int, errMsg string) error {
	// Structure ASN.1 du SearchResultDone avec code d’erreur
	result := []any{
		messageID, // MessageID
		asn1.RawValue{
			Class:      asn1.ClassApplication,
			Tag:        5, // SearchResultDone
			IsCompound: true,
			Bytes: mustMarshal([]any{
				LDAPResultOperationsError, // resultCode
				"",                        // matchedDN
				errMsg,                    // diagnosticMessage
			}),
		},
	}

	packet, err := asn1.Marshal(result)
	if err != nil {
		return fmt.Errorf("ASN.1 marshal failed: %v", err)
	}

	// Wrap with outer SEQUENCE
	finalPacket, err := asn1.Marshal(asn1.RawValue{
		Class:      asn1.ClassUniversal,
		Tag:        asn1.TagSequence,
		IsCompound: true,
		Bytes:      packet,
	})
	if err != nil {
		return fmt.Errorf("final packet marshal failed: %v", err)
	}

	_, err = conn.Write(finalPacket)
	if err != nil && err != io.EOF {
		return fmt.Errorf("failed to send LDAP failure: %v", err)
	}

	return nil
}

// Helper pour gérer l’ASN.1 proprement (panic en cas d'erreur fatale interne)
func mustMarshal(v any) []byte {
	b, err := asn1.Marshal(v)
	if err != nil {
		panic(fmt.Sprintf("ASN.1 marshal error: %v", err))
	}
	return b
}
