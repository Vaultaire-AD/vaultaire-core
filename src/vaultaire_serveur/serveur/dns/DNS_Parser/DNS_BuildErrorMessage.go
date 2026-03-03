package dnsparser

import (
	dnsstorage "vaultaire/serveur/dns/DNS_Storage"
)

// Construit une réponse DNS d'erreur (ex: NXDOMAIN)
func BuildErrorDNSResponse(req *dnsstorage.DNSMessage, rcode uint8) ([]byte, error) {
	resp := &dnsstorage.DNSMessage{
		Header: dnsstorage.DNSHeader{
			ID:      req.Header.ID,
			QR:      true,              // Réponse
			Opcode:  req.Header.Opcode, // Même opcode que la requête
			AA:      true,              // Autoritative
			RD:      req.Header.RD,     // Recursion desired : conserver
			RA:      false,             // Pas de recursion disponible
			RCode:   rcode,             // Code d'erreur : 3 = NXDOMAIN, 2 = SERVFAIL, etc.
			QDCount: uint16(len(req.Questions)),
			ANCount: 0,
			NSCount: 0,
			ARCount: 0,
		},
		Questions: req.Questions,
		Answers:   nil,
	}

	return BuildDNSMessage(resp)
}
