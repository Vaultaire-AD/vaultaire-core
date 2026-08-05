package dbsettings

import (
	"database/sql"
	"fmt"
	"strconv"
	"strings"

	"vaultaire/core/logs"
)

// GetInt lit un réglage entier et le ramène dans ses bornes.
//
// Retourne def si la clé est absente, illisible ou hors bornes. Une panne de
// base retombe aussi sur le défaut : un réglage indisponible ne doit pas
// interrompre le service qui le consulte, seulement lui faire prendre la valeur
// la plus prudente.
func GetInt(db *sql.DB, key string, min, max, def int) int {
	if db == nil {
		return def
	}
	var raw string
	err := db.QueryRow(
		`SELECT setting_value FROM server_settings WHERE setting_key = ?`, key).Scan(&raw)
	switch {
	case err == sql.ErrNoRows:
		return def
	case err != nil:
		logs.Write_LogCode("WARNING", logs.CodeDBQuery,
			"dbsettings: lecture de "+key+" échouée, valeur par défaut retenue : "+err.Error())
		return def
	}

	value, convErr := strconv.Atoi(strings.TrimSpace(raw))
	if convErr != nil || value < min || value > max {
		logs.Write_Log("WARNING", fmt.Sprintf(
			"dbsettings: %s = %q hors bornes [%d..%d], défaut %d retenu", key, raw, min, max, def))
		return def
	}
	return value
}

// SetInt écrit un réglage entier après l'avoir borné.
//
// La validation est faite ICI et non chez l'appelant : c'est le seul point que
// traversent le CLI, l'interface web et tout appelant futur.
func SetInt(db *sql.DB, key string, value, min, max int, updatedBy string) error {
	if db == nil {
		return fmt.Errorf("connexion base indisponible")
	}
	if value < min || value > max {
		return fmt.Errorf("%s doit être compris entre %d et %d", key, min, max)
	}
	if _, err := db.Exec(
		`INSERT INTO server_settings (setting_key, setting_value, updated_by)
		 VALUES (?, ?, ?)
		 ON DUPLICATE KEY UPDATE setting_value = VALUES(setting_value), updated_by = VALUES(updated_by)`,
		key, strconv.Itoa(value), updatedBy); err != nil {
		logs.Write_LogCode("ERROR", logs.CodeDBQuery, "dbsettings: écriture de "+key+" échouée : "+err.Error())
		return fmt.Errorf("enregistrement du réglage %s : %w", key, err)
	}
	logs.Write_Log("SECURITY", fmt.Sprintf("réglage serveur %s porté à %d par %s", key, value, updatedBy))
	return nil
}
