package dnsparser

import (
	"fmt"
	"log"
	"net"
	dnsstorage "vaultaire/core/dns/DNS_Storage"
	dnstools "vaultaire/core/dns/DNS_Tools"
)

func BuildDNSResponse(req *dnsstorage.DNSMessage, result string) ([]byte, error) {
	if len(req.Questions) == 0 {
		return nil, fmt.Errorf("❌ Pas de question DNS dans la requête")
	}

	question := req.Questions[0]
	var rdata []byte

	log.Printf("🧠 Type de requête reçu : %d (%s)", question.Type, question.Name)

	switch question.Type {
	case 1: // Type A
		ip := net.ParseIP(result).To4()
		if ip == nil {
			return nil, fmt.Errorf("❌ IP v4 invalide pour A : %s", result)
		}
		rdata = ip
	case 2: // NS
		var err error
		rdata, err = dnstools.EncodeDomainName(result)
		if err != nil {
			return nil, fmt.Errorf("❌ Erreur encodage NS : %v", err)
		}
	case 5: // CNAME
		var err error
		rdata, err = dnstools.EncodeDomainName(result)
		if err != nil {
			return nil, fmt.Errorf("❌ Erreur encodage CNAME : %v", err)
		}
	case 12: // Type PTR
		var err error
		rdata, err = dnstools.EncodeDomainName(result)
		if err != nil {
			return nil, fmt.Errorf("❌ Erreur encodage PTR : %v", err)
		}

	default:
		return nil, fmt.Errorf("❌ Type de ressource non pris en charge : %d", question.Type)
	}

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
			ANCount: 1,
			NSCount: 0,
			ARCount: 0,
		},
		Questions: req.Questions,
		Answers: []dnsstorage.DNSResourceRecord{
			{
				Name:  question.Name,
				Type:  question.Type,
				Class: question.Class,
				TTL:   3600,
				RData: rdata,
			},
		},
	}

	return BuildDNSMessage(response)
}
