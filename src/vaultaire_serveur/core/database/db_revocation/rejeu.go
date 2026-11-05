package dbrevocation

import (
	"database/sql"
	"fmt"
	"strings"

	"vaultaire/core/database"
	"vaultaire/core/logs"
	"vaultaire/core/revocation"
)

// Ce qu'il reste à remettre, et le compte des essais — TO-DO 49.
//
// # Une seule définition de « à rejouer »
//
// Trois requêtes posaient chacune la question à sa façon (`status <> 'acked'`,
// écrit trois fois) : les ordres rendus à l'agent qui les réclame, et les deux
// décomptes « N machine(s) restant à traiter » de l'interface. Un quatrième
// état — le verrouillage levé — les aurait fait diverger en silence : l'agent
// n'aurait plus reçu l'ordre, et l'interface l'aurait compté « en attente »
// pour toujours.
//
// sqlARejouer est écrit une fois et repris partout ; un test vérifie qu'il dit
// la même chose que revocation.TargetStatus.ARejouer.
const sqlARejouer = "t.status IN ('pending', 'failed')"

// EnAttente est un ordre qu'une machine n'a pas acquitté, avec ce qu'il faut
// pour décider quand le lui remettre.
type EnAttente struct {
	Ordre  revocation.Order
	Statut revocation.TargetStatus

	// Essais : combien de fois l'ordre a déjà été remis à cette machine.
	Essais int
	// DepuisLeDernier : secondes écoulées depuis le dernier essai OU le dernier
	// compte rendu de la machine. Sans valeur tant que rien ne s'est passé.
	//
	// Calculé PAR LA BASE (TIMESTAMPDIFF sur NOW()), pas en soustrayant une
	// date relue à l'horloge du core : deux cores partagent la base sans
	// partager leur horloge, et un écart de quelques secondes entre eux est du
	// même ordre que le délai qu'on mesure ici.
	DepuisLeDernier sql.NullInt64
}

// MachinesEnAttente rend les machines à qui il reste au moins un ordre à
// remettre.
//
// C'est la question bon marché, posée à chaque tour du rejeu : elle ne lit que
// l'index (computeur_id, status), et rend le plus souvent une liste vide. Le
// détail n'est lu ensuite que pour les machines CONNECTÉES à ce core.
func MachinesEnAttente(db *sql.DB) ([]string, error) {
	rows, err := db.Query(
		`SELECT DISTINCT t.computeur_id
		   FROM user_revocation_target t
		  WHERE ` + sqlARejouer)
	if err != nil {
		return nil, fmt.Errorf("lecture des machines en attente : %w", err)
	}
	defer func() {
		if cerr := rows.Close(); cerr != nil {
			logs.Write_Log("DEBUG", "revocation: fermeture du curseur: "+cerr.Error())
		}
	}()
	var machines []string
	for rows.Next() {
		var m string
		if err := rows.Scan(&m); err != nil {
			return nil, fmt.Errorf("lecture d'une machine en attente : %w", err)
		}
		machines = append(machines, m)
	}
	return machines, rows.Err()
}

// EnAttentePour rend ce qu'une machine n'a pas acquitté, du plus ancien au plus
// récent, avec le compte des essais.
//
// Même sélection et même ordre que PendingOrdersForClient : c'est la même liste,
// lue pour le rejeu. L'ordre chronologique compte ici comme là-bas.
func EnAttentePour(db *sql.DB, computeurID string, limit int) ([]EnAttente, error) {
	if err := database.SanitizeIdentifier(computeurID); err != nil {
		return nil, err
	}
	if limit <= 0 || limit > 200 {
		limit = 200
	}
	rows, err := db.Query(
		`SELECT r.id_revocation, r.mode, r.username, r.reason_code,
		        t.status, t.attempts, TIMESTAMPDIFF(SECOND, t.last_attempt, NOW())
		   FROM user_revocation r
		   JOIN user_revocation_target t ON t.d_id_revocation = r.id_revocation
		  WHERE t.computeur_id = ? AND `+sqlARejouer+`
		  ORDER BY r.id_revocation ASC
		  LIMIT ?`, computeurID, limit)
	if err != nil {
		return nil, fmt.Errorf("lecture des ordres à rejouer : %w", err)
	}
	defer func() {
		if cerr := rows.Close(); cerr != nil {
			logs.Write_Log("DEBUG", "revocation: fermeture du curseur: "+cerr.Error())
		}
	}()

	var out []EnAttente
	for rows.Next() {
		var e EnAttente
		var mode, reason, statut string
		if err := rows.Scan(&e.Ordre.ID, &mode, &e.Ordre.Username, &reason,
			&statut, &e.Essais, &e.DepuisLeDernier); err != nil {
			return nil, fmt.Errorf("lecture d'un ordre à rejouer : %w", err)
		}
		e.Ordre.Mode = revocation.Mode(mode)
		e.Ordre.Reason = revocation.Reason(reason)
		e.Statut = revocation.TargetStatus(statut)
		if err := e.Ordre.Validate(); err != nil {
			logs.Write_LogCode("WARNING", logs.CodeDBQuery,
				"revocation: ordre illisible ignoré au rejeu: "+err.Error())
			continue
		}
		out = append(out, e)
	}
	return out, rows.Err()
}

// NoterEssai inscrit que des ordres viennent d'être REMIS à une machine.
//
// Ne touche ni au statut ni au détail : remettre n'est pas appliquer, et c'est
// le compte rendu de la machine (MarkTarget) qui dit ce qu'il en est advenu.
// Une cible acquittée ou levée entre-temps n'est pas modifiée.
func NoterEssai(db *sql.DB, computeurID string, orderIDs []int) error {
	if len(orderIDs) == 0 {
		return nil
	}
	if err := database.SanitizeIdentifier(computeurID); err != nil {
		return err
	}
	marques := strings.TrimSuffix(strings.Repeat("?,", len(orderIDs)), ",")
	args := make([]any, 0, len(orderIDs)+1)
	args = append(args, computeurID)
	for _, id := range orderIDs {
		args = append(args, id)
	}
	_, err := db.Exec(
		`UPDATE user_revocation_target t
		    SET t.attempts = t.attempts + 1, t.last_attempt = NOW()
		  WHERE t.computeur_id = ? AND t.d_id_revocation IN (`+marques+`) AND `+sqlARejouer, args...)
	if err != nil {
		return fmt.Errorf("inscription de l'essai : %w", err)
	}
	return nil
}
