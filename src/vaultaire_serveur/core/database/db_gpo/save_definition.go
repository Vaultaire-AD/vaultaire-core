package dbgpo

import (
	"database/sql"
	"fmt"
	"strings"
	"vaultaire/core/database"
	"vaultaire/core/gpo"
)

// SaveDefinition crée ou met à jour une définition à contenu.
//
// C'est le point d'entrée pour créer un jeu de commandes sudo custom, ou tout
// futur champ à contenu : le kind attendu est déduit du catalogue, jamais fourni
// par l'appelant, pour qu'on ne puisse pas stocker un contenu d'un type que le
// champ ne sait pas interpréter.
func SaveDefinition(db *sql.DB, actor, moduleType, fieldName, name, payload, note string) error {
	if err := requireSuperadmin(db, actor, "l'enregistrement d'une définition"); err != nil {
		return err
	}
	if err := validateFieldTarget(moduleType, fieldName); err != nil {
		return err
	}
	kind := gpo.PayloadKindFor(moduleType, fieldName)
	if kind == gpo.PayloadNone {
		return fmt.Errorf("le champ %s/%s n'attend pas de contenu : utilisez la liste de valeurs", moduleType, fieldName)
	}

	name = strings.TrimSpace(name)
	if err := validateRestrictionValue(name, 128); err != nil {
		return err
	}
	if !definitionNameRe.MatchString(name) {
		return fmt.Errorf("nom invalide %q (lettres, chiffres, point, tiret, souligné ; 2 à 64 caractères)", name)
	}
	if err := database.SanitizeIdentifier(moduleType, fieldName, name); err != nil {
		return err
	}
	if err := gpo.ValidatePayload(kind, payload); err != nil {
		return err
	}

	previous, existed, err := getDefinition(db, moduleType, fieldName, name)
	if err != nil {
		return err
	}

	if _, err := db.Exec(
		`INSERT INTO gpo_value_definition (module_type, field_name, name, payload_kind, payload, note, updated_by)
		 VALUES (?, ?, ?, ?, ?, ?, ?)
		 ON DUPLICATE KEY UPDATE payload_kind = VALUES(payload_kind), payload = VALUES(payload),
		   note = VALUES(note), updated_by = VALUES(updated_by)`,
		moduleType, fieldName, name, string(kind), payload, nullIfEmpty(strings.TrimSpace(note)), actor,
	); err != nil {
		return fmt.Errorf("enregistrement de la définition %q impossible : %v", name, err)
	}

	action := "création de définition"
	detail := fmt.Sprintf("%s/%s/%s (%s) : %s", moduleType, fieldName, name, kind, oneLine(payload))
	if existed {
		action = "modification de définition"
		detail = fmt.Sprintf("%s/%s/%s (%s) : %s → %s",
			moduleType, fieldName, name, kind, oneLine(previous.Payload), oneLine(payload))
	}
	auditRestriction(actor, action, detail)
	return nil
}
