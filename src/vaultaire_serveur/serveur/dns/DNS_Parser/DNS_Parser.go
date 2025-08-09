package dnsparser

import (
	dnsstorage "DUCKY/serveur/dns/DNS_Storage"
	"encoding/binary"
	"errors"
	"fmt"
)

// parseName lit un nom DNS, supporte compression et retourne la nouvelle position après lecture
func parseName(msg []byte, offset int) (string, int, error) {
	var labels []string
	// startOffset := offset
	jumped := false
	jumpOffset := 0

	for {
		if offset >= len(msg) {
			return "", 0, errors.New("offset out of range")
		}

		length := int(msg[offset])
		if length == 0 {
			offset++
			break
		}

		// Compression ?
		if length&0xC0 == 0xC0 {
			if !jumped {
				jumpOffset = offset + 2
			}
			if offset+1 >= len(msg) {
				return "", 0, errors.New("offset out of range on compression pointer")
			}
			pointer := int(binary.BigEndian.Uint16(msg[offset:offset+2]) & 0x3FFF)
			offset = pointer
			jumped = true
			continue
		}

		offset++
		if offset+length > len(msg) {
			return "", 0, errors.New("label length out of range")
		}
		labels = append(labels, string(msg[offset:offset+length]))
		offset += length
	}

	if !jumped {
		return fmt.Sprintf("%s", joinLabels(labels)), offset, nil
	}
	return fmt.Sprintf("%s", joinLabels(labels)), jumpOffset, nil
}

func joinLabels(labels []string) string {
	s := ""
	for i, label := range labels {
		if i > 0 {
			s += "."
		}
		s += label
	}
	return s
}

func ParseDNSMessage(msg []byte) (*dnsstorage.DNSMessage, error) {
	if len(msg) < 12 {
		return nil, errors.New("message too short")
	}

	header := dnsstorage.DNSHeader{}
	header.ID = binary.BigEndian.Uint16(msg[0:2])

	flags := binary.BigEndian.Uint16(msg[2:4])
	header.QR = (flags & 0x8000) != 0
	header.Opcode = uint8((flags >> 11) & 0xF)
	header.AA = (flags & 0x0400) != 0
	header.TC = (flags & 0x0200) != 0
	header.RD = (flags & 0x0100) != 0
	header.RA = (flags & 0x0080) != 0
	header.Z = uint8((flags >> 4) & 0x7)
	header.RCode = uint8(flags & 0xF)

	header.QDCount = binary.BigEndian.Uint16(msg[4:6])
	header.ANCount = binary.BigEndian.Uint16(msg[6:8])
	header.NSCount = binary.BigEndian.Uint16(msg[8:10])
	header.ARCount = binary.BigEndian.Uint16(msg[10:12])

	dnsMsg := &dnsstorage.DNSMessage{
		Header: header,
	}

	offset := 12
	// Questions
	for i := 0; i < int(header.QDCount); i++ {
		name, newOffset, err := parseName(msg, offset)
		if err != nil {
			return nil, err
		}
		offset = newOffset

		if offset+4 > len(msg) {
			return nil, errors.New("message too short for question fields")
		}
		qtype := binary.BigEndian.Uint16(msg[offset : offset+2])
		qclass := binary.BigEndian.Uint16(msg[offset+2 : offset+4])
		offset += 4

		dnsMsg.Questions = append(dnsMsg.Questions, dnsstorage.DNSQuestion{
			Name:  name,
			Type:  qtype,
			Class: qclass,
		})
	}

	// Fonction pour parser les resource records
	parseRR := func(count uint16) ([]dnsstorage.DNSResourceRecord, int, error) {
		var rrs []dnsstorage.DNSResourceRecord
		off := offset
		for i := 0; i < int(count); i++ {
			name, newOff, err := parseName(msg, off)
			if err != nil {
				return nil, 0, err
			}
			off = newOff
			if off+10 > len(msg) {
				return nil, 0, errors.New("message too short for resource record header")
			}
			rtype := binary.BigEndian.Uint16(msg[off : off+2])
			rclass := binary.BigEndian.Uint16(msg[off+2 : off+4])
			ttl := binary.BigEndian.Uint32(msg[off+4 : off+8])
			rdlength := binary.BigEndian.Uint16(msg[off+8 : off+10])
			off += 10
			if off+int(rdlength) > len(msg) {
				return nil, 0, errors.New("message too short for rdata")
			}
			rdata := make([]byte, rdlength)
			copy(rdata, msg[off:off+int(rdlength)])
			off += int(rdlength)

			rrs = append(rrs, dnsstorage.DNSResourceRecord{
				Name:     name,
				Type:     rtype,
				Class:    rclass,
				TTL:      ttl,
				RDLength: rdlength,
				RData:    rdata,
			})
		}
		return rrs, off, nil
	}

	// Réponses
	dnsMsg.Answers, offset, _ = parseRR(header.ANCount)
	// Autorités
	dnsMsg.Authorities, offset, _ = parseRR(header.NSCount)
	// Additionnels
	dnsMsg.Additionals, offset, _ = parseRR(header.ARCount)

	return dnsMsg, nil
}
