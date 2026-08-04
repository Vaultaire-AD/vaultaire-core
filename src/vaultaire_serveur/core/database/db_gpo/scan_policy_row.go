package dbgpo

import (
	"database/sql"
	"vaultaire/core/gpo"
)

// scanPolicyRow lit les métadonnées d'une GPO depuis une ligne de résultat.
func scanPolicyRow(scanner interface{ Scan(...any) error }) (gpo.Policy, error) {
	var p gpo.Policy
	var scope, description sql.NullString
	var createdAt, updatedAt sql.NullTime

	if err := scanner.Scan(&p.ID, &p.Name, &scope, &description, &p.Version, &p.Enabled, &createdAt, &updatedAt); err != nil {
		return p, err
	}
	p.Scope = gpo.Scope(scope.String)
	p.Description = description.String
	if createdAt.Valid {
		p.CreatedAt = createdAt.Time
	}
	if updatedAt.Valid {
		p.UpdatedAt = updatedAt.Time
	}
	return p, nil
}
