package database

import (
	"fmt"
)

// CountLink compte les lignes d'une table de liaison.
//
// Les deux tables concernées — users_group et logiciel_group — appartiennent à
// des paquets différents (dbgroups, dbclients), qui portent chacun leur requête.
// Seule la mécanique de lecture est commune, et elle vit ici parce qu'elle est
// du même ordre que les résolveurs : une lecture élémentaire dont le socle
// répond, pour que personne n'ait à réécrire la gestion d'erreur.
func CountLink(q RowQuerier, query string, left, right int) (bool, error) {
	if q == nil {
		return false, fmt.Errorf("connexion base indisponible")
	}
	var count int
	if err := q.QueryRow(query, left, right).Scan(&count); err != nil {
		return false, err
	}
	return count > 0, nil
}
