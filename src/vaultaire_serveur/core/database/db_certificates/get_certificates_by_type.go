package dbcertificates

import (
	"database/sql"
	"fmt"
	"vaultaire/core/database"
	"vaultaire/core/storage"
)

// GetCertificatesByType récupère tous les certificats d'un type donné
func GetCertificatesByType(certType string) ([]storage.Certificate, error) {
	db := database.GetDatabase()
	rows, err := db.Query(
		"SELECT id_certificate, name, certificate_type, certificate_data, private_key_data, public_key_data, description, created_at, updated_at FROM certificates WHERE certificate_type = ? ORDER BY name",
		certType,
	)
	if err != nil {
		return nil, fmt.Errorf("erreur récupération certificats par type: %v", err)
	}
	defer rows.Close()

	var certificates []storage.Certificate
	for rows.Next() {
		var cert storage.Certificate
		var certData, privKeyData, pubKeyData, desc sql.NullString
		var createdAtBytes, updatedAtBytes []byte

		err := rows.Scan(&cert.ID, &cert.Name, &cert.CertificateType, &certData, &privKeyData, &pubKeyData, &desc, &createdAtBytes, &updatedAtBytes)
		if err != nil {
			return nil, fmt.Errorf("erreur scan certificat: %v", err)
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

		certificates = append(certificates, cert)
	}

	// rows.Err() distingue « la lecture est terminée » de « la lecture s'est
	// interrompue ». Sans ce contrôle, une coupure en cours d'itération rend un
	// résultat PARTIEL présenté comme complet.
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return certificates, nil
}
