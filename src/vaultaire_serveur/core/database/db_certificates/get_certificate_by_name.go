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
	// Base absente : une ERREUR, pas une panique.
	//
	// Le cas se présente avant l'ouverture de la connexion et dans tout test
	// qui traverse un chemin lisant un certificat. La panique qui en résultait
	// était un déréférencement nul sans message, à trois appels de distance de
	// la cause.
	if db == nil {
		return nil, fmt.Errorf("erreur récupération certificat: connexion base indisponible")
	}

	var cert storage.Certificate
	var certData, privKeyData, pubKeyData, desc sql.NullString
	var createdAtBytes, updatedAtBytes []byte

	err := db.QueryRow(
		"SELECT id_certificate, name, certificate_type, certificate_data, private_key_data, public_key_data, description, created_at, updated_at FROM certificates WHERE name = ?",
		name,
	).Scan(&cert.ID, &cert.Name, &cert.CertificateType, &certData, &privKeyData, &pubKeyData, &desc, &createdAtBytes, &updatedAtBytes)

	if err == sql.ErrNoRows {
		return nil, fmt.Errorf("%w: %s", ErrCertificatIntrouvable, name)
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
