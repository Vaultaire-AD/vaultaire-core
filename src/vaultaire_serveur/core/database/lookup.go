package database

import (
	"database/sql"
	"fmt"
)

// lookup factorise le motif commun : assainissement, lecture, distinction entre
// « absent » et « en panne ».
//
// L'assainissement est fait ICI, au plus près de la base, et pas seulement chez
// l'appelant : c'est ce qui couvre les appelants qui seront écrits plus tard.
// Le paramètre est déjà passé en requête préparée — ce n'est donc pas une
// protection contre l'injection, mais un refus des noms que l'annuaire n'aurait
// jamais dû accepter.
func lookup(q RowQuerier, query, key string) (int, bool, error) {
	if err := SanitizeIdentifier(key); err != nil {
		return 0, false, err
	}
	if q == nil {
		return 0, false, fmt.Errorf("connexion base indisponible")
	}
	var id int
	switch err := q.QueryRow(query, key).Scan(&id); {
	case err == sql.ErrNoRows:
		return 0, false, nil
	case err != nil:
		return 0, false, err
	}
	return id, true, nil
}
