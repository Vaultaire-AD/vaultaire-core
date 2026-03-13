package storage

import "time"

type UserConnected struct {
	ID          int
	Username    string
	CreatedAt   string
	TokenExpiry string
}

type GetUserInfoSingle struct {
	Username    string   `json:"username"`
	Firstname   string   `json:"firstname"`
	Lastname    string   `json:"lastname"`
	Email       string   `json:"email"`
	DateOfBirth string   `json:"date_naissance"`
	Groups      []string `json:"groups"`
	Connected   bool     `json:"connected"`
}

// PublicKey représente une clé publique d'un utilisateur
type PublicKey struct {
	ID        int
	UserID    int
	Key       string
	Label     string
	CreatedAt string
}

// Certificate représente un certificat/clé système stocké en base de données
type Certificate struct {
	ID              int
	Name            string
	CertificateType string // 'rsa_keypair', 'tls_cert', 'ssh_key', etc.
	CertificateData *string // Certificat X.509 (PEM) ou certificat SSH
	PrivateKeyData  *string // Clé privée (PEM)
	PublicKeyData   *string // Clé publique (PEM)
	Description     *string
	CreatedAt       time.Time
	UpdatedAt       time.Time
}

type GroupInfoLDAP struct {
	ID         int
	Name       string
	DomainName string
}
