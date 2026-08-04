package dbgpo

import (
	"fmt"
	"vaultaire/core/gpo"
)

// validateFieldTarget vérifie que le couple module/champ existe et que son
// domaine est bien géré en base. Sans ce contrôle, on pourrait accumuler des
// restrictions sur un champ inexistant, qui ne s'appliqueraient jamais tout en
// donnant l'illusion d'une protection.
func validateFieldTarget(moduleType, fieldName string) error {
	if _, ok := gpo.BaseSchemaFor(moduleType); !ok {
		return fmt.Errorf("module inconnu : %s", moduleType)
	}
	for _, f := range gpo.DynamicFields() {
		if f.ModuleType == moduleType && f.FieldName == fieldName {
			return nil
		}
	}
	return fmt.Errorf("le champ %s/%s n'a pas de domaine géré en base", moduleType, fieldName)
}
