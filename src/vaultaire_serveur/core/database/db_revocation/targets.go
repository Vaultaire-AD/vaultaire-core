package dbrevocation

import (
	"database/sql"
	"fmt"

	"vaultaire/core/database"
	"vaultaire/core/logs"
)

// MachinesSharingGroupWith retourne les identifiants des machines partageant au
// moins un groupe avec un utilisateur.
//
// C'est exactement l'ensemble des machines où l'utilisateur a pu se connecter,
// donc où le module PAM a pu créer un compte local et écrire son mot de passe
// dans /etc/shadow. Autrement dit : l'ensemble des machines où une révocation
// a quelque chose à faire.
//
// La même règle que les GPO utilisateur (voir gpo_manager.HasSharedGroup), en
// une seule requête plutôt qu'une par machine — un ordre de révocation vise
// potentiellement tout le parc et se déclenche dans l'urgence.
func MachinesSharingGroupWith(db *sql.DB, username string) ([]string, error) {
	if err := database.SanitizeIdentifier(username); err != nil {
		return nil, err
	}

	rows, err := db.Query(`
		SELECT DISTINCT l.computeur_id
		  FROM users u
		  JOIN users_group ug     ON ug.d_id_user = u.id_user
		  JOIN logiciel_group lg  ON lg.d_id_group = ug.d_id_group
		  JOIN id_logiciels l     ON l.id_logiciel = lg.d_id_logiciel
		 WHERE u.username = ?
		   AND l.serveur = FALSE`, username)
	if err != nil {
		return nil, fmt.Errorf("recherche des machines cibles : %w", err)
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
			return nil, fmt.Errorf("lecture d'une machine cible : %w", err)
		}
		machines = append(machines, id)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("parcours des machines cibles : %w", err)
	}
	return machines, nil
}
