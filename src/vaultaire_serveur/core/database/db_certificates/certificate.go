package dbcertificates

import (
	"time"
)

// Certificate représente un certificat/clé stocké en base
type Certificate struct {
	ID              int
	Name            string
	CertificateType string
	CertificateData *string // Certificat X.509 (PEM) ou certificat SSH
	PrivateKeyData  *string // Clé privée (PEM)
	PublicKeyData   *string // Clé publique (PEM)
	Description     *string
	CreatedAt       time.Time
	UpdatedAt       time.Time
}
