package dbcertificates

import (
	"database/sql"
	"fmt"
	"vaultaire/core/database"
	"vaultaire/core/storage"
)

// GetCertificateByName récupère un certificat par son nom
func GetCertificateByName(name string) (*storage.Certificate, error) {
	db := database.GetDatabase()
	var cert storage.Certificate
	var certData, privKeyData, pubKeyData, desc sql.NullString
	var createdAtBytes, updatedAtBytes []byte

	err := db.QueryRow(
		"SELECT id_certificate, name, certificate_type, certificate_data, private_key_data, public_key_data, description, created_at, updated_at FROM certificates WHERE name = ?",
		name,
	).Scan(&cert.ID, &cert.Name, &cert.CertificateType, &certData, &privKeyData, &pubKeyData, &desc, &createdAtBytes, &updatedAtBytes)

	if err == sql.ErrNoRows {
		return nil, fmt.Errorf("certificat non trouvé: %s", name)
	}
	if err != nil {
		return nil, fmt.Errorf("erreur récupération certificat: %v", err)
	}

	if certData.Valid {
		cert.CertificateData = &certData.String
	}
	if privKeyData.Valid {
		cert.PrivateKeyData = &privKeyData.String
	}
	if pubKeyData.Valid {
		cert.PublicKeyData = &pubKeyData.String
	}
	if desc.Valid {
		cert.Description = &desc.String
	}
	cert.CreatedAt, _ = parseMySQLDateTime(createdAtBytes)
	cert.UpdatedAt, _ = parseMySQLDateTime(updatedAtBytes)

	return &cert, nil
}
