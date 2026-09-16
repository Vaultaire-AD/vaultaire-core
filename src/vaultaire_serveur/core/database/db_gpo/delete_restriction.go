package dbgpo

import (
	"database/sql"
	"fmt"
)

// DeleteRestriction supprime une ligne de restriction par son identifiant.
//
// Le retrait est journalisé avec la valeur exacte retirée : supprimer un refus
// de chemin élargit ce que le parc entier accepte d'écrire, il faut pouvoir
// retracer qui l'a fait et quoi.
func DeleteRestriction(db *sql.DB, actor string, id int) error {
	if err := requireSuperadmin(db, actor, "la suppression d'une restriction"); err != nil {
		return err
	}
	var kind, moduleType, fieldName, scope, value string
	err := db.QueryRow(
		`SELECT kind, module_type, field_name, scope, value FROM gpo_restriction WHERE id_gpo_restriction = ?`, id,
	).Scan(&kind, &moduleType, &fieldName, &scope, &value)
	if err == sql.ErrNoRows {
		return fmt.Errorf("restriction %d introuvable", id)
	}
	if err != nil {
		return fmt.Errorf("lecture de la restriction %d impossible : %v", id, err)
	}
	if _, err := db.Exec(`DELETE FROM gpo_restriction WHERE id_gpo_restriction = ?`, id); err != nil {
		return fmt.Errorf("suppression de la restriction %d impossible : %v", id, err)
	}
	auditRestriction(actor, "suppression de restriction",
		fmt.Sprintf("kind=%s %s/%s scope=%s valeur=%q", kind, moduleType, fieldName, scope, value))
	return nil
}
