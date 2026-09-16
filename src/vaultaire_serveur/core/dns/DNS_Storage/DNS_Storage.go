package dnsstorage

import "database/sql"

type DNSHeader struct {
	ID      uint16
	QR      bool
	Opcode  uint8
	AA      bool
	TC      bool
	RD      bool
	RA      bool
	Z       uint8
	RCode   uint8
	QDCount uint16
	ANCount uint16
	NSCount uint16
	ARCount uint16
}

type DNSQuestion struct {
	Name  string
	Type  uint16
	Class uint16
}

type DNSResourceRecord struct {
	Name     string
	Type     uint16
	Class    uint16
	TTL      uint32
	RDLength uint16
	RData    []byte

	// Champs spécifiques pour MX
	Priority uint16
	Exchange string
}

type DNSMessage struct {
	Header      DNSHeader
	Questions   []DNSQuestion
	Answers     []DNSResourceRecord
	Authorities []DNSResourceRecord
	Additionals []DNSResourceRecord
}

// Zone représente une zone DNS
type Zone struct {
	ZoneName  string
	TableName string
}

type ZoneRecord struct {
	ID       int64
	Name     string
	Type     string
	TTL      int
	Data     string
	Priority sql.NullInt64 // Peut être NULL
}

type MXRecord struct {
	Host     string
	Priority int
	TTL      int
}
