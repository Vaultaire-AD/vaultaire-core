package dbcertificates

import (
	"vaultaire/serveur/database"
	"vaultaire/serveur/storage"
	"database/sql"
	"fmt"
	"time"
)

// parseMySQLDateTime convertit des bytes DATETIME MySQL en time.Time
func parseMySQLDateTime(b []byte) (time.Time, error) {
	if len(b) == 0 {
		return time.Time{}, nil
	}
	// MySQL renvoie "2006-01-02 15:04:05" ou "2006-01-02 15:04:05.123456"
	s := string(b)
	if len(s) > 19 {
		s = s[:19]
	}
	return time.Parse("2006-01-02 15:04:05", s)
}

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

// GetAllCertificates récupère tous les certificats
func GetAllCertificates() ([]storage.Certificate, error) {
	db := database.GetDatabase()
	rows, err := db.Query("SELECT id_certificate, name, certificate_type, certificate_data, private_key_data, public_key_data, description, created_at, updated_at FROM certificates ORDER BY name")
	if err != nil {
		return nil, fmt.Errorf("erreur récupération certificats: %v", err)
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

	return certificates, nil
}

// CreateCertificate crée un nouveau certificat
func CreateCertificate(name, certType string, certData, privKeyData, pubKeyData, description *string) (*storage.Certificate, error) {
	db := database.GetDatabase()

	// Vérifier si le certificat existe déjà
	var existingID int
	err := db.QueryRow("SELECT id_certificate FROM certificates WHERE name = ?", name).Scan(&existingID)
	if err == nil {
		return nil, fmt.Errorf("un certificat avec le nom '%s' existe déjà", name)
	}
	if err != sql.ErrNoRows {
		return nil, fmt.Errorf("erreur vérification certificat existant: %v", err)
	}

	// Insérer le nouveau certificat
	result, err := db.Exec(
		"INSERT INTO certificates (name, certificate_type, certificate_data, private_key_data, public_key_data, description) VALUES (?, ?, ?, ?, ?, ?)",
		name, certType, certData, privKeyData, pubKeyData, description,
	)
	if err != nil {
		return nil, fmt.Errorf("erreur création certificat: %v", err)
	}

	id, err := result.LastInsertId()
	if err != nil {
		return nil, fmt.Errorf("erreur récupération ID: %v", err)
	}

	return GetCertificateByID(int(id))
}

// UpdateCertificate met à jour un certificat existant
func UpdateCertificate(id int, certData, privKeyData, pubKeyData, description *string) error {
	db := database.GetDatabase()

	_, err := db.Exec(
		"UPDATE certificates SET certificate_data = ?, private_key_data = ?, public_key_data = ?, description = ? WHERE id_certificate = ?",
		certData, privKeyData, pubKeyData, description, id,
	)
	if err != nil {
		return fmt.Errorf("erreur mise à jour certificat: %v", err)
	}

	return nil
}

// DeleteCertificate supprime un certificat
func DeleteCertificate(id int) error {
	db := database.GetDatabase()

	result, err := db.Exec("DELETE FROM certificates WHERE id_certificate = ?", id)
	if err != nil {
		return fmt.Errorf("erreur suppression certificat: %v", err)
	}

	rowsAffected, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("erreur vérification suppression: %v", err)
	}
	if rowsAffected == 0 {
		return fmt.Errorf("certificat non trouvé: ID %d", id)
	}

	return nil
}

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

	return certificates, nil
}
