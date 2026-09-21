package dbsessions

import (
	"database/sql"
	"fmt"
	"vaultaire/core/logs"
)

// CleanUpExpiredSessions supprime les entrées did_login dont key_time_validity
// est dépassé.
//
// La comparaison se fait entièrement côté SQL (WHERE key_time_validity <
// NOW()) plutôt qu'en récupérant la date en Go pour la reparser : le driver
// MySQL (DSN parseTime=true) renvoie un TIMESTAMP scanné dans un string sous
// forme RFC3339Nano (ex "2026-07-28T15:43:41Z"), alors que le code
// attendait un format "2006-01-02 15:04:05" — ça ne matchait jamais et
// faisait échouer le nettoyage à chaque tick, en boucle, sans jamais rien
// supprimer. Laisser MySQL faire la comparaison de dates élimine ce problème
// de format une fois pour toutes.
//
// # Ligne par ligne, pas compte par compte
//
// La version précédente relevait les COMPTES dont une ligne avait expiré, puis
// effaçait toutes les lignes de ces comptes. Or tous les tunnels machine sont
// connectés sous le même compte, `vaultaire` : il suffisait qu'UNE machine
// cesse de battre pour que TOUTES disparaissent de `status -c`, jusqu'à leur
// battement suivant. Seules les lignes expirées sont effacées désormais.
func CleanUpExpiredSessions(db *sql.DB) error {
	res, err := db.Exec("DELETE FROM did_login WHERE key_time_validity < NOW()")
	if err != nil {
		return fmt.Errorf("erreur lors de la suppression des sessions expirées : %v", err)
	}
	if n, _ := res.RowsAffected(); n > 0 {
		logs.Write_Log("INFO", fmt.Sprintf("%d session(s) expirée(s) supprimée(s)", n))
	}
	return nil
}
