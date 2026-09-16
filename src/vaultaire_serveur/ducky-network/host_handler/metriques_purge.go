package hosthandler

import (
	"database/sql"
	"fmt"
	"time"

	dbsettings "vaultaire/core/database/db_settings"
	"vaultaire/core/logs"
)

// Rétention des métriques de nœuds.
//
// # Le défaut que ce fichier ferme
//
// `proxy_metrics` n'avait AUCUNE purge. Chaque trame 04_05 y insère une ligne, et
// rien n'en retirait jamais. La table grossissait indéfiniment — pas seulement
// sous une attaque : en fonctionnement normal aussi, à la cadence de remontée de
// chaque nœud, pour toujours.
//
// C'est une table d'OBSERVATION. Une mesure de charge d'il y a huit mois ne sert
// plus à personne : ce qu'on lit dans cette table, c'est « comment se comporte le
// parc en ce moment » et « à quoi cela ressemblait la dernière fois que ça allait
// bien ». Les deux tiennent dans quelques semaines.
//
// # Ce que la purge ne fait PAS
//
// Elle n'agrège pas. Les points anciens sont supprimés, pas résumés — pas de
// moyenne horaire conservée au-delà de la rétention. Une agrégation demanderait
// de décider quel résumé garde du sens pour quel type de métrique, et personne
// ne lit encore ces données : ce serait construire une réponse avant d'avoir la
// question.

// SettingMetricsRetentionDays est la durée de conservation d'une métrique.
const SettingMetricsRetentionDays = "proxy_metrics_retention_days"

// Bornes et défaut de la rétention.
//
// 30 jours : assez pour comparer un incident à « le mois dernier », assez court
// pour que la table reste petite sans que personne s'en occupe.
//
// 0 DÉSACTIVE la purge, comme pour les services partis. C'est une sortie
// volontaire — un exploitant qui exporte ses métriques ailleurs et veut garder
// la source doit pouvoir le dire, plutôt que de contourner en mettant une valeur
// absurde.
//
// Le maximum tient à deux ans. Au-delà, la question n'est plus la rétention mais
// l'agrégation, et cette table ne sait pas agréger.
const (
	MetricsRetentionDaysDefault = 30
	MetricsRetentionDaysMin     = 0
	MetricsRetentionDaysMax     = 730
)

// MetricsRetention retourne la rétention configurée, ou zéro si désactivée.
func MetricsRetention(db *sql.DB) time.Duration {
	jours := dbsettings.GetInt(db, SettingMetricsRetentionDays,
		MetricsRetentionDaysMin, MetricsRetentionDaysMax, MetricsRetentionDaysDefault)
	return time.Duration(jours) * 24 * time.Hour
}

// SetMetricsRetention écrit la rétention.
func SetMetricsRetention(db *sql.DB, jours int, updatedBy string) error {
	return dbsettings.SetInt(db, SettingMetricsRetentionDays, jours,
		MetricsRetentionDaysMin, MetricsRetentionDaysMax, updatedBy)
}

// LotPurgeMetriques borne le nombre de lignes supprimées par passage.
//
// # Pourquoi supprimer par lots
//
// Un `DELETE` sans borne sur une table qui a grossi pendant des mois verrouille
// et journalise tout d'un coup. Le premier passage après la mise en service est
// précisément celui qui a le plus à supprimer — c'est-à-dire que le comportement
// le plus lourd arrive au moment le moins attendu, et sur une base qui tourne.
//
// Avec une borne, le retard se résorbe en plusieurs passages. La purge tourne
// dans la même boucle que le balayage des services, donc toutes les minutes par
// défaut : dix mille lignes par minute suffisent à rattraper n'importe quel
// retard en une nuit.
const LotPurgeMetriques = 10000

// PurgeMetriquesAnciennes supprime les métriques au-delà de la rétention.
//
// Rend le nombre de lignes supprimées, pour que l'appelant puisse le journaliser
// quand il est non nul — une purge silencieuse qui efface des milliers de lignes
// est exactement ce qu'on cherche à comprendre après coup.
func PurgeMetriquesAnciennes(db *sql.DB) (int64, error) {
	if db == nil {
		return 0, fmt.Errorf("connexion base indisponible")
	}
	retention := MetricsRetention(db)
	if retention <= 0 {
		return 0, nil // purge désactivée
	}

	limite := time.Now().UTC().Add(-retention)
	res, err := db.Exec(
		`DELETE FROM proxy_metrics WHERE created_at < ? LIMIT ?`,
		limite, LotPurgeMetriques)
	if err != nil {
		return 0, fmt.Errorf("purge des métriques : %w", err)
	}
	n, _ := res.RowsAffected()

	if n >= LotPurgeMetriques {
		// Le lot est plein : il reste probablement des lignes. Le dire évite de
		// croire la purge terminée en lisant « 10000 supprimées » au moment où
		// c'est justement le signe du contraire.
		logs.Write_Log("INFO", fmt.Sprintf(
			"metriques: %d ligne(s) purgées (lot plein) — le rattrapage continue au prochain passage", n))
	} else if n > 0 {
		logs.Write_Log("INFO", fmt.Sprintf(
			"metriques: %d ligne(s) au-delà de %d jours purgées", n, int(retention.Hours()/24)))
	}
	return n, nil
}
