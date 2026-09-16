package dbgpo

import (
	"database/sql"
	"fmt"
)

// BumpVersion incrémente la version d'une GPO.
//
// Toute modification de contenu doit passer par ici : la version alimente le
// hash côté agent, et c'est ce hash qui décide s'il faut réappliquer la
// politique. Une modification sans incrément resterait invisible pour le parc.
func BumpVersion(db *sql.DB, id int) error {
	if _, err := db.Exec(`UPDATE gpo SET version = version + 1 WHERE id_gpo = ?`, id); err != nil {
		return fmt.Errorf("incrément de version de la GPO %d impossible : %v", id, err)
	}
	return nil
}
