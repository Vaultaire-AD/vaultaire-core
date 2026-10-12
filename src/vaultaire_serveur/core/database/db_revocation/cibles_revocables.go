package dbrevocation

import (
	"database/sql"
	"fmt"
	"strings"

	"vaultaire/core/clienttype"
	"vaultaire/core/database"
	"vaultaire/core/logs"
	"vaultaire/core/revocation"
)

// Le périmètre d'une révocation — TO-DO 167.
//
// Les cibles d'un ordre sont les machines qui partagent un groupe avec le
// compte, celles où il a une session, celles qu'un verrouillage avait visées.
// Aucune de ces trois règles ne regardait le TYPE de la machine : un proxy ou un
// Nexus rangé dans un groupe où se trouvent des comptes était visé, recevait la
// 06_05, n'avait aucun gestionnaire pour elle, et restait « en attente » pour
// toujours — rejoué toutes les cinq minutes, sans remède.
//
// Une cible n'est gardée que si son type sait ACQUITTER une révocation
// (clienttype.TypesQuiAcquittent). Une machine inconnue de id_logiciels est
// gardée : on ne sait rien d'elle, et l'écarter serait décider à sa place.

// TypesDesMachines rend le type de chaque machine connue parmi celles données.
func TypesDesMachines(db *sql.DB, machines []string) (map[string]string, error) {
	types := map[string]string{}
	if len(machines) == 0 {
		return types, nil
	}
	marques := make([]string, 0, len(machines))
	args := make([]any, 0, len(machines))
	for _, m := range machines {
		if err := database.SanitizeIdentifier(m); err != nil {
			continue
		}
		marques = append(marques, "?")
		args = append(args, m)
	}
	if len(args) == 0 {
		return types, nil
	}
	rows, err := db.Query(`SELECT computeur_id, logiciel_type FROM id_logiciels WHERE computeur_id IN (`+
		strings.Join(marques, ",")+`)`, args...)
	if err != nil {
		return nil, fmt.Errorf("lecture du type des machines visées : %w", err)
	}
	defer func() {
		if cerr := rows.Close(); cerr != nil {
			logs.Write_Log("DEBUG", "revocation: fermeture du curseur: "+cerr.Error())
		}
	}()
	for rows.Next() {
		var id, typ string
		if err := rows.Scan(&id, &typ); err != nil {
			return nil, fmt.Errorf("lecture d'un type de machine : %w", err)
		}
		types[strings.ToLower(id)] = typ
	}
	return types, rows.Err()
}

// GarderLesRevocables partage les cibles : celles qui peuvent appliquer un
// ordre, et les autres, avec leur type. Pure : les types sont donnés.
func GarderLesRevocables(cibles []string, types map[string]string) (gardees []string, ecartees []string) {
	for _, c := range cibles {
		typ, connu := types[strings.ToLower(c)]
		if connu && !clienttype.MayEmit(typ, "06_02") {
			ecartees = append(ecartees, c+" ("+typ+")")
			continue
		}
		gardees = append(gardees, c)
	}
	return gardees, ecartees
}

// MarquerMachineNonPriseEnCharge range TOUTES les cibles encore à rejouer d'une
// machine dans StatusNonPrisEnCharge : elle vient de dire qu'elle ne sait pas
// révoquer (06_03 « unsupported »), ce qui vaut pour chacun de ses ordres, pas
// seulement pour celui qui portait la réponse.
func MarquerMachineNonPriseEnCharge(db *sql.DB, computeurID, detail string) (int64, error) {
	if err := database.SanitizeIdentifier(computeurID); err != nil {
		return 0, err
	}
	if len(detail) > 512 {
		detail = detail[:512]
	}
	res, err := db.Exec(
		`UPDATE user_revocation_target t
		    SET t.status = ?, t.last_attempt = NOW(), t.detail = ?
		  WHERE t.computeur_id = ? AND `+sqlARejouer,
		string(revocation.StatusNonPrisEnCharge), detail, computeurID)
	if err != nil {
		return 0, fmt.Errorf("mise à jour des cibles de %s : %w", computeurID, err)
	}
	return res.RowsAffected()
}

// RangerLesCiblesSansCompte range dans StatusNonPrisEnCharge les cibles encore
// à rejouer dont la machine est d'un type qui ne sait pas acquitter — les
// services visés avant le TO-DO 167. Jouée à chaque démarrage : idempotente,
// et rien à faire une fois le parc rangé.
func RangerLesCiblesSansCompte(db *sql.DB) (int64, error) {
	types := clienttype.TypesQuiAcquittent()
	if len(types) == 0 {
		// Un catalogue sans aucun type acquitteur rangerait TOUT le parc : on
		// refuse plutôt que de vider le suivi des révocations.
		return 0, fmt.Errorf("aucun type de client ne sait acquitter une révocation : rien n'est rangé")
	}
	marques := make([]string, len(types))
	args := []any{string(revocation.StatusNonPrisEnCharge)}
	for i, t := range types {
		marques[i] = "?"
		args = append(args, t)
	}
	res, err := db.Exec(
		`UPDATE user_revocation_target t
		   JOIN id_logiciels l ON l.computeur_id = t.computeur_id
		    SET t.status = ?,
		        t.detail = CONCAT('service (', l.logiciel_type, ') : ne porte aucun compte local')
		  WHERE l.logiciel_type NOT IN (`+strings.Join(marques, ",")+`)
		    AND `+sqlARejouer, args...)
	if err != nil {
		return 0, fmt.Errorf("rangement des cibles sans compte : %w", err)
	}
	return res.RowsAffected()
}
