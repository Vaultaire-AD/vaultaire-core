package dbgpo

import (
	"database/sql"
	"fmt"
	"strings"
	"vaultaire/core/database"
	"vaultaire/core/gpo"
)

// AddAllowedValue ajoute une valeur autorisée à un champ.
// C'est le point d'entrée pour déclarer un besoin custom : une unité systemd
// maison, un paquet interne, un identifiant de tâche propre au client.
func AddAllowedValue(db *sql.DB, actor, moduleType, fieldName, value, label string) error {
	if err := requireSuperadmin(db, actor, "l'ajout d'une valeur autorisée"); err != nil {
		return err
	}
	value = strings.TrimSpace(value)
	if err := validateFieldTarget(moduleType, fieldName); err != nil {
		return err
	}
	// Sur un champ à contenu, un nom sans contenu serait accepté ici mais rejeté
	// à la validation de la GPO (« jeu vide »). Autant refuser tout de suite avec
	// le bon message, plutôt que de laisser une entrée inutilisable en base.
	if gpo.FieldHasPayload(moduleType, fieldName) {
		return fmt.Errorf("le champ %s/%s attend une définition avec son contenu, pas un simple nom", moduleType, fieldName)
	}
	if err := validateRestrictionValue(value, 512); err != nil {
		return err
	}
	// Le type de module et le nom de champ sont des identifiants du catalogue.
	// La valeur, elle, peut être un chemin, un nom de paquet ou un motif : elle
	// est déjà bornée par validateRestrictionValue juste au-dessus.
	if err := database.SanitizeIdentifier(moduleType, fieldName); err != nil {
		return err
	}
	if err := database.SanitizeInput(value); err != nil {
		return err
	}

	res, err := db.Exec(
		`INSERT IGNORE INTO gpo_restriction (kind, module_type, field_name, scope, value, note, updated_by)
		 VALUES (?, ?, ?, 'any', ?, ?, ?)`,
		KindAllowValue, moduleType, fieldName, value, nullIfEmpty(strings.TrimSpace(label)), actor)
	if err != nil {
		return fmt.Errorf("ajout de la valeur %q impossible : %v", value, err)
	}
	if affected, _ := res.RowsAffected(); affected == 0 {
		return fmt.Errorf("la valeur %q est déjà autorisée pour %s/%s", value, moduleType, fieldName)
	}
	auditRestriction(actor, "ajout de valeur autorisée", fmt.Sprintf("%s/%s += %q", moduleType, fieldName, value))
	return nil
}
