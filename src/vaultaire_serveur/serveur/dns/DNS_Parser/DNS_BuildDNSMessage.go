package dnsparser

import (
	dnsstorage "vaultaire/serveur/dns/DNS_Storage"
	"bytes"
	"encoding/binary"
	"fmt"
)

func btoi(b bool) uint16 {
	if b {
		return 1
	}
	return 0
}

func BuildDNSMessage(msg *dnsstorage.DNSMessage) ([]byte, error) {
	buf := &bytes.Buffer{}

	// Header
	flags := uint16(0)
	flags |= btoi(msg.Header.QR) << 15
	flags |= uint16(msg.Header.Opcode&0xF) << 11
	flags |= btoi(msg.Header.AA) << 10
	flags |= btoi(msg.Header.TC) << 9
	flags |= btoi(msg.Header.RD) << 8
	flags |= btoi(msg.Header.RA) << 7
	flags |= uint16(msg.Header.Z&0x7) << 4
	flags |= uint16(msg.Header.RCode & 0xF)

	_ = binary.Write(buf, binary.BigEndian, msg.Header.ID)
	_ = binary.Write(buf, binary.BigEndian, flags)
	_ = binary.Write(buf, binary.BigEndian, msg.Header.QDCount)
	_ = binary.Write(buf, binary.BigEndian, msg.Header.ANCount)
	_ = binary.Write(buf, binary.BigEndian, msg.Header.NSCount)
	_ = binary.Write(buf, binary.BigEndian, msg.Header.ARCount)

	// Questions
	for _, q := range msg.Questions {
		if err := writeDomainName(buf, q.Name); err != nil {
			return nil, err
		}
		_ = binary.Write(buf, binary.BigEndian, q.Type)
		_ = binary.Write(buf, binary.BigEndian, q.Class)
	}

	// Answers
	for _, a := range msg.Answers {
		if err := writeDomainName(buf, a.Name); err != nil {
			return nil, err
		}
		_ = binary.Write(buf, binary.BigEndian, a.Type)
		_ = binary.Write(buf, binary.BigEndian, a.Class)
		_ = binary.Write(buf, binary.BigEndian, a.TTL)

		// A type only for now (IPv4)
		switch a.Type {
		case 1: // A
			if len(a.RData) != 4 {
				return nil, fmt.Errorf("❌ IP invalide pour enregistrement A : %v", a.RData)
			}
			_ = binary.Write(buf, binary.BigEndian, uint16(4)) // Data length
			_, _ = buf.Write(a.RData)                          // IPv4
		case 2: // NS
			_ = binary.Write(buf, binary.BigEndian, uint16(len(a.RData))) // longueur
			_, err := buf.Write(a.RData)                                  // nom encodé
			if err != nil {
				return nil, err
			}
		case 5: // CNAME
			// a.RData contient le nom cible encodé DNS, donc on écrit sa longueur et son contenu
			_ = binary.Write(buf, binary.BigEndian, uint16(len(a.RData))) // longueur
			_, err := buf.Write(a.RData)                                  // nom encodé
			if err != nil {
				return nil, err
			}
		case 12: // PTR
			_ = binary.Write(buf, binary.BigEndian, uint16(len(a.RData))) // Longueur du nom encodé
			_, _ = buf.Write(a.RData)                                     // Nom encodé DNS
		case 15: // MX
			_ = binary.Write(buf, binary.BigEndian, uint16(len(a.RData)))
			_, err := buf.Write(a.RData)
			if err != nil {
				return nil, err
			}
		case 16: // TXT
			if len(a.RData) == 0 {
				return nil, fmt.Errorf("❌ RData vide pour enregistrement TXT")
			}
			_ = binary.Write(buf, binary.BigEndian, uint16(len(a.RData)))
			_, err := buf.Write(a.RData)
			if err != nil {
				return nil, err
			}
		default:
			return nil, fmt.Errorf("❌ Type de ressource non pris en charge : %d", a.Type)
		}
	}

	return buf.Bytes(), nil
}

func writeDomainName(buf *bytes.Buffer, name string) error {
	labels := bytes.Split([]byte(name), []byte("."))

	for _, label := range labels {
		if len(label) > 63 {
			return fmt.Errorf("❌ Label DNS trop long : %s", label)
		}
		buf.WriteByte(byte(len(label)))
		buf.Write(label)
	}
	buf.WriteByte(0) // fin du nom
	return nil
}
