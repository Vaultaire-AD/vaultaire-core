package dbgpo

import (
	"database/sql"
	"fmt"
	"strings"
	"vaultaire/core/gpo"
	"vaultaire/core/logs"
)

// UpdatePolicyMeta met à jour la description et l'activation d'une GPO.
// Le nom et le scope ne sont pas modifiables : renommer casserait les
// références, et changer le scope reclasserait silencieusement des modules
// machine-only dans un contexte utilisateur.
func UpdatePolicyMeta(db *sql.DB, id int, description string, enabled bool) error {
	if err := gpo.ValidateDescription(description); err != nil {
		return err
	}
	_, err := db.Exec(
		`UPDATE gpo SET description = ?, enabled = ?, version = version + 1 WHERE id_gpo = ?`,
		strings.TrimSpace(description), enabled, id,
	)
	if err != nil {
		logs.Write_LogCode("ERROR", logs.CodeDBGeneric, "gpo: mise à jour de la GPO échouée : "+err.Error())
		return fmt.Errorf("mise à jour de la GPO impossible : %v", err)
	}
	return nil
}
