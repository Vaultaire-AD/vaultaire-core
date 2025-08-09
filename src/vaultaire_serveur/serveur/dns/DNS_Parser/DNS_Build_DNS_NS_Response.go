package dnsparser

import (
	dnsstorage "DUCKY/serveur/dns/DNS_Storage"
	dnstools "DUCKY/serveur/dns/DNS_Tools"
	"fmt"
)

func BuildDNSResponseNS(req *dnsstorage.DNSMessage, records []dnsstorage.ZoneRecord) ([]byte, error) {
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
		// data = nom du serveur NS (doit être encodé en format DNS)
		rdata, err := dnstools.EncodeDomainName(rec.Data)
		if err != nil {
			return nil, fmt.Errorf("❌ Erreur encodage NS record '%s' : %v", rec.Data, err)
		}

		answer := dnsstorage.DNSResourceRecord{
			Name:  question.Name,
			Type:  2, // NS
			Class: question.Class,
			TTL:   uint32(rec.TTL),
			RData: rdata,
		}
		response.Answers = append(response.Answers, answer)
	}

	return BuildDNSMessage(response)
}
