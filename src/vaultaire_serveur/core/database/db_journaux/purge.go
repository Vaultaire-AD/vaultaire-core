package dbjournaux

import (
	"database/sql"
	"fmt"
	"time"

	"vaultaire/core/logs"
)

// Purge de la rétention.
//
// # Par lots, et pourquoi le passage boucle
//
// Un `DELETE` sans borne sur une table qui a grossi verrouille et journalise
// tout d'un coup — voir LotPurgeMetriques, même raisonnement. Les lots sont
// donc de LotPurge lignes.
//
// Mais la purge des métriques passe chaque minute ; celle-ci, par défaut,
// toutes les vingt-quatre heures. Un lot par passage ne rattraperait jamais un
// emballement : le passage enchaîne donc les lots, avec une pause entre eux
// pour laisser passer les écritures, jusqu'à ce qu'un lot revienne incomplet —
// ou jusqu'à LotsParPassage, pour qu'un retard gigantesque ne transforme pas la
// purge en tâche d'une heure.

const (
	LotPurge       = 10000
	LotsParPassage = 100
	pauseEntreLots = 200 * time.Millisecond

	// RetentionMin refuse une rétention absurde : une durée nulle viderait la
	// table à chaque passage. Les bornes du réglage l'interdisent déjà ; celle-ci
	// tient si un appelant passe autre chose que le réglage.
	RetentionMin = 24 * time.Hour
)

// pause est remplaçable par les tests.
var pause = time.Sleep

// supprimerLot est remplaçable par les tests : la boucle de lots s'éprouve sans
// base.
var supprimerLot = func(db *sql.DB, limite time.Time) (int64, error) {
	res, err := db.Exec("DELETE FROM "+Table+" WHERE created_at < ? LIMIT ?", limite, LotPurge)
	if err != nil {
		return 0, err
	}
	return res.RowsAffected()
}

// Purger supprime les lignes plus anciennes que la rétention. Rend le nombre
// de lignes supprimées.
//
// Chaque core purge, sans se coordonner avec les autres : deux DELETE sur les
// mêmes lignes ne font rien de plus qu'un seul, et élire un « core qui purge »
// ajouterait une panne possible — celle où l'élu disparaît et où plus personne
// ne purge.
func Purger(db *sql.DB, retention time.Duration) (int64, error) {
	if db == nil {
		return 0, fmt.Errorf("connexion base indisponible")
	}
	if retention < RetentionMin {
		return 0, fmt.Errorf("rétention de %s refusée : au moins %s", retention, RetentionMin)
	}

	limite := time.Now().UTC().Add(-retention)
	var total int64
	for i := 0; i < LotsParPassage; i++ {
		if i > 0 {
			pause(pauseEntreLots)
		}
		n, err := supprimerLot(db, limite)
		total += n
		if err != nil {
			return total, fmt.Errorf("purge du journal commun : %w", err)
		}
		if n < LotPurge {
			break
		}
	}

	if total > 0 {
		logs.Write_LogCode("INFO", logs.CodeLogPurge, fmt.Sprintf(
			"journaux: %d ligne(s) de plus de %d jour(s) purgée(s)",
			total, int(retention.Hours()/24)))
	}
	return total, nil
}
