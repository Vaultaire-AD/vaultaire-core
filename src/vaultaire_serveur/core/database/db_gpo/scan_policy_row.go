package dbgpo

import (
	"database/sql"
	"vaultaire/core/gpo"
)

// scanPolicyRow lit les métadonnées d'une GPO depuis une ligne de résultat.
func scanPolicyRow(scanner interface{ Scan(...any) error }) (gpo.Policy, error) {
	var p gpo.Policy
	var scope, description, driftMode sql.NullString
	var createdAt, updatedAt sql.NullTime

	if err := scanner.Scan(&p.ID, &p.Name, &scope, &description, &p.Version, &p.Enabled,
		&driftMode, &createdAt, &updatedAt); err != nil {
		return p, err
	}
	p.Scope = gpo.Scope(scope.String)
	p.Description = description.String

	// Une valeur illisible en base est ramenée au défaut plutôt que propagée.
	//
	// La colonne est contrainte par le code, pas par un ENUM : une écriture
	// directe en SQL peut y laisser n'importe quoi. Livrer cette valeur telle
	// quelle donnerait des agents qui ne reconnaissent aucun mode et se
	// rabattent chacun sur leur propre interprétation. Enforce est le choix
	// sûr : on fait respecter la politique.
	if mode, err := gpo.NormalizeDriftMode(driftMode.String); err == nil {
		p.DriftMode = mode
	} else {
		p.DriftMode = gpo.DefaultDriftMode
	}
	if createdAt.Valid {
		p.CreatedAt = createdAt.Time
	}
	if updatedAt.Valid {
		p.UpdatedAt = updatedAt.Time
	}
	return p, nil
}
