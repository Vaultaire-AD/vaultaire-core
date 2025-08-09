package dnsparser

import (
	dnsstorage "DUCKY/serveur/dns/DNS_Storage"
	dnstools "DUCKY/serveur/dns/DNS_Tools"
	"bytes"
	"encoding/binary"
	"fmt"
)

func BuildDNSResponseMX(req *dnsstorage.DNSMessage, records []dnsstorage.MXRecord) ([]byte, error) {
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
			ANCount: uint16(len(records)),
			NSCount: 0,
			ARCount: 0,
		},
		Questions: req.Questions,
		Answers:   make([]dnsstorage.DNSResourceRecord, 0, len(records)),
	}

	for _, rec := range records {
		rdataDomain, err := dnstools.EncodeDomainName(rec.Host)
		if err != nil {
			return nil, fmt.Errorf("❌ Erreur encodage MX host '%s': %v", rec.Host, err)
		}

		// Construire le RDATA spécifique MX : priorité (2 octets) + nom du mail exchanger (encoded)
		buf := bytes.Buffer{}
		// priorité : uint16 big endian
		_ = binary.Write(&buf, binary.BigEndian, uint16(rec.Priority))
		// nom encodé
		_, _ = buf.Write(rdataDomain)

		answer := dnsstorage.DNSResourceRecord{
			Name:  question.Name,
			Type:  15, // MX
			Class: question.Class,
			TTL:   uint32(rec.TTL),
			RData: buf.Bytes(),
		}
		response.Answers = append(response.Answers, answer)
	}

	return BuildDNSMessage(response)
}
