package dbcertificates

import (
	"database/sql"
	"fmt"
	"vaultaire/core/database"
	"vaultaire/core/storage"
)

// GetCertificateByID récupère un certificat par son ID
func GetCertificateByID(id int) (*storage.Certificate, error) {
	db := database.GetDatabase()
	var cert storage.Certificate
	var certData, privKeyData, pubKeyData, desc sql.NullString
	var createdAtBytes, updatedAtBytes []byte

	err := db.QueryRow(
		"SELECT id_certificate, name, certificate_type, certificate_data, private_key_data, public_key_data, description, created_at, updated_at FROM certificates WHERE id_certificate = ?",
		id,
	).Scan(&cert.ID, &cert.Name, &cert.CertificateType, &certData, &privKeyData, &pubKeyData, &desc, &createdAtBytes, &updatedAtBytes)

	if err == sql.ErrNoRows {
		return nil, fmt.Errorf("certificat non trouvé: ID %d", id)
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
