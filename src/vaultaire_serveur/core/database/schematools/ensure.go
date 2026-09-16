// Package schematools ajoute colonnes et index à des tables DÉJÀ créées.
//
// # Le défaut que ce paquet ferme
//
// Les tables sont créées par `CREATE TABLE IF NOT EXISTS`. La clause fait
// exactement ce qu'elle dit : sur une base où la table existe, elle ne fait
// RIEN — elle ne compare pas les colonnes, elle ne complète pas ce qui manque.
//
// Ajouter une colonne au texte du CREATE n'a donc aucun effet sur une base déjà
// en service. Le serveur démarre normalement, et échoue à la première requête
// qui nomme la colonne :
//
//	Error 1054 (42S22): Unknown column 'owner_client_id' in 'WHERE'
//
// Le message est juste et arrive au pire endroit : loin du fichier de schéma, en
// pleine exploitation, sur un chemin qui marchait la veille.
//
// `db_authpolicy` avait déjà résolu le problème pour les colonnes de `users` et
// `groups`, avec un helper privé. Ce paquet le sort de là pour que la solution
// serve à tout le monde — deux implémentations de la même idée finissent
// toujours par diverger, et celle qui n'est pas relue est celle qui se trompe.
//
// Le paquet ne dépend que des journaux, pour rester importable partout sans
// cycle.
package schematools

import (
	"database/sql"
	"fmt"
	"regexp"

	"vaultaire/core/logs"
)

// identifierPattern borne les noms de table, de colonne et d'index.
//
// Ils ne peuvent pas être passés en paramètre de requête préparée : MySQL
// n'accepte de placeholder que pour des VALEURS, pas pour des identifiants. La
// concaténation est donc inévitable, et c'est ce motif qui la rend sûre.
//
// Tous les appelants passent des constantes du code. Un futur appelant qui
// passerait une chaîne venue d'ailleurs se heurterait ici plutôt qu'à une
// injection.
var identifierPattern = regexp.MustCompile(`^[a-z_]{1,64}$`)

// EnsureColumn ajoute une colonne si elle n'existe pas déjà.
//
// # Pourquoi consulter information_schema plutôt qu'avaler l'erreur
//
// `ALTER TABLE … ADD COLUMN` n'est pas idempotent : il échoue avec l'erreur 1060
// quand la colonne existe. On pourrait avaler ce code précis, mais cela
// reviendrait à traiter le cas NORMAL — un serveur qui redémarre — comme une
// erreur, et à masquer du même geste une vraie 1060 venue d'ailleurs.
//
// `sujet` nomme le sous-système dans les journaux : c'est ce qui permet de
// savoir quel schéma a bougé au démarrage.
func EnsureColumn(db *sql.DB, sujet, table, column, definition string) error {
	if !identifierPattern.MatchString(table) || !identifierPattern.MatchString(column) {
		return fmt.Errorf("identifiant de schéma refusé : %s.%s", table, column)
	}

	var count int
	err := db.QueryRow(`SELECT COUNT(*) FROM information_schema.COLUMNS
		WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = ? AND COLUMN_NAME = ?`,
		table, column).Scan(&count)
	if err != nil {
		logs.Write_LogCode("ERROR", logs.CodeDBQuery,
			sujet+": inspection de "+table+"."+column+" échouée : "+err.Error())
		return fmt.Errorf("inspection de %s.%s : %w", table, column, err)
	}
	if count > 0 {
		return nil
	}

	if _, err := db.Exec("ALTER TABLE `" + table + "` ADD COLUMN `" + column + "` " + definition); err != nil {
		logs.Write_LogCode("ERROR", logs.CodeDBQuery,
			sujet+": ajout de "+table+"."+column+" échoué : "+err.Error())
		return fmt.Errorf("ajout de %s.%s : %w", table, column, err)
	}

	logs.Write_Log("INFO", sujet+": colonne "+table+"."+column+" ajoutée")
	return nil
}

// EnsureUniqueIndex ajoute un index UNIQUE s'il n'existe pas déjà.
//
// # L'ordre compte, et c'est le piège de cette fonction
//
// Un index UNIQUE posé sur une colonne dont plusieurs lignes portent la MÊME
// valeur échoue. C'est exactement l'état d'une table où la colonne vient d'être
// ajoutée : toutes les lignes existantes portent sa valeur par défaut.
//
// L'appelant doit donc avoir traité ces lignes AVANT — en les remplissant ou en
// les supprimant. La fonction ne le fait pas à sa place : que faire d'une ligne
// sans valeur dépend entièrement de ce qu'elle représente, et le deviner ici
// effacerait des données dans un cas et pas dans l'autre.
func EnsureUniqueIndex(db *sql.DB, sujet, table, index, column string) error {
	if !identifierPattern.MatchString(table) ||
		!identifierPattern.MatchString(index) ||
		!identifierPattern.MatchString(column) {
		return fmt.Errorf("identifiant de schéma refusé : %s.%s (%s)", table, index, column)
	}

	var count int
	err := db.QueryRow(`SELECT COUNT(*) FROM information_schema.STATISTICS
		WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = ? AND INDEX_NAME = ?`,
		table, index).Scan(&count)
	if err != nil {
		logs.Write_LogCode("ERROR", logs.CodeDBQuery,
			sujet+": inspection de l'index "+table+"."+index+" échouée : "+err.Error())
		return fmt.Errorf("inspection de l'index %s.%s : %w", table, index, err)
	}
	if count > 0 {
		return nil
	}

	if _, err := db.Exec("ALTER TABLE `" + table + "` ADD UNIQUE KEY `" + index + "` (`" + column + "`)"); err != nil {
		logs.Write_LogCode("ERROR", logs.CodeDBQuery,
			sujet+": ajout de l'index "+table+"."+index+" échoué : "+err.Error())
		return fmt.Errorf("ajout de l'index %s.%s : %w", table, index, err)
	}

	logs.Write_Log("INFO", sujet+": index unique "+table+"."+index+" ajouté")
	return nil
}
