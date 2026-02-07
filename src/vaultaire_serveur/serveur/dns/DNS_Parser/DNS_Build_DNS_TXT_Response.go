package dnsparser

import (
	dnsstorage "vaultaire/serveur/dns/DNS_Storage"
	"bytes"
	"fmt"
)

func BuildDNSResponseTXT(req *dnsstorage.DNSMessage, txtRecords []string) ([]byte, error) {
	if len(req.Questions) == 0 {
		return nil, fmt.Errorf("❌ Pas de question DNS dans la requête")
	}
	question := req.Questions[0]

	response := &dnsstorage.DNSMessage{
		Header: dnsstorage.DNSHeader{
			ID:      req.Header.ID,
			QR:      true,
			Opcode:  0,
			AA:      true,
			TC:      false,
			RD:      req.Header.RD,
			RA:      true,
			Z:       0,
			RCode:   0,
			QDCount: 1,
			ANCount: uint16(len(txtRecords)),
			NSCount: 0,
			ARCount: 0,
		},
		Questions: req.Questions,
		Answers:   make([]dnsstorage.DNSResourceRecord, 0, len(txtRecords)),
	}

	for _, txt := range txtRecords {
		var buf bytes.Buffer

		if len(txt) > 255 {
			return nil, fmt.Errorf("❌ TXT trop long (>255 caractères)")
		}

		// Format DNS : longueur + texte
		buf.WriteByte(byte(len(txt)))
		buf.WriteString(txt)

		answer := dnsstorage.DNSResourceRecord{
			Name:  question.Name,
			Type:  16, // TXT
			Class: question.Class,
			TTL:   3600,
			RData: buf.Bytes(),
		}

		response.Answers = append(response.Answers, answer)
	}

	return BuildDNSMessage(response)
}
