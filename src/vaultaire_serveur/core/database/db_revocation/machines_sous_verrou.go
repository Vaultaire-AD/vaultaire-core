package dbrevocation

import (
	"database/sql"
	"fmt"

	"vaultaire/core/database"
	"vaultaire/core/logs"
	"vaultaire/core/revocation"
)

// MachinesSousVerrou rend les machines visées par un verrouillage EN VIGUEUR
// d'un compte — TO-DO 49.
//
// # Pourquoi la levée en a besoin
//
// Une levée visait, comme tout ordre, les machines qui partagent AUJOURD'HUI un
// groupe avec le compte. Or le verrouillage, lui, avait visé celles qui en
// partageaient un LE JOUR OÙ il a été émis. Entre les deux, on retire souvent la
// personne de ses groupes — c'est même le geste qui accompagne un verrouillage.
//
// La machine qui avait verrouillé n'était alors plus visée par la levée : son
// compte local restait verrouillé et expiré pour toujours. Sans effet tant que
// la personne n'y revient pas ; le jour où on la remet dans le groupe, elle ne
// peut plus s'y connecter, et rien dans l'annuaire ne dit pourquoi.
//
// À lire AVANT LiftSoftRevocations : après, « en vigueur » ne désigne plus rien.
// Toutes les cibles comptent, acquittées ou non — une machine dont le
// verrouillage a échoué à mi-chemin a pu poser le verrou sans réussir à couper
// les processus.
func MachinesSousVerrou(db *sql.DB, username string) ([]string, error) {
	if err := database.SanitizeIdentifier(username); err != nil {
		return nil, err
	}
	rows, err := db.Query(
		`SELECT DISTINCT t.computeur_id
		   FROM user_revocation r
		   JOIN user_revocation_target t ON t.d_id_revocation = r.id_revocation
		  WHERE r.username = ? AND r.mode = ? AND r.lifted_at IS NULL
		  ORDER BY t.computeur_id`,
		username, string(revocation.ModeSoft))
	if err != nil {
		return nil, fmt.Errorf("recherche des machines sous verrou : %w", err)
	}
	defer func() {
		if cerr := rows.Close(); cerr != nil {
			logs.Write_Log("DEBUG", "revocation: fermeture du curseur: "+cerr.Error())
		}
	}()
	var machines []string
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			return nil, fmt.Errorf("lecture d'une machine sous verrou : %w", err)
		}
		machines = append(machines, id)
	}
	return machines, rows.Err()
}
