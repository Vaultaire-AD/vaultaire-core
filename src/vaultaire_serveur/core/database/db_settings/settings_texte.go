package dbsettings

import (
	"database/sql"
	"fmt"
	"strings"

	"vaultaire/core/logs"
)

// Réglages TEXTE — le premier est la version attendue du parc (TO-DO 111).
//
// # Le typage reste chez l'appelant, mais la validation passe ici
//
// Une chaîne n'a pas de bornes à vérifier comme un entier. GetString prend donc
// un VALIDATEUR : la valeur lue en base n'est rendue que s'il l'accepte, et
// celle qu'on écrit ne l'est que s'il l'accepte aussi. C'est la même promesse
// que GetInt — une valeur aberrante en base retombe sur le défaut au lieu de se
// propager —, tenue par la règle de celui qui sait ce que la valeur veut dire.

// GetString lit un réglage texte.
//
// Rend ("", false, nil) quand la clé est absente, et l'erreur quand la base ne
// répond pas : contrairement à GetInt, l'appelant de ce réglage doit pouvoir
// distinguer « rien de posé » de « je n'ai pas pu lire ». Une vue qui dirait
// « aucune cible » parce que la base a flanché mentirait sur ce qui se passera.
func GetString(db *sql.DB, key string) (string, bool, error) {
	if db == nil {
		return "", false, fmt.Errorf("connexion base indisponible")
	}
	var raw string
	err := db.QueryRow(
		`SELECT setting_value FROM server_settings WHERE setting_key = ?`, key).Scan(&raw)
	switch {
	case err == sql.ErrNoRows:
		return "", false, nil
	case err != nil:
		logs.Write_LogCode("WARNING", logs.CodeDBQuery,
			"dbsettings: lecture de "+key+" échouée : "+err.Error())
		return "", false, fmt.Errorf("lecture du réglage %s : %w", key, err)
	}
	return strings.TrimSpace(raw), true, nil
}

// SetString écrit un réglage texte après l'avoir fait valider.
//
// Une valeur vide EFFACE la ligne : « pas de réglage » et « réglage vide » ne
// doivent pas être deux états distincts en base, puisqu'ils ne le sont pour
// aucun lecteur.
func SetString(db *sql.DB, key, value string, valider func(string) error, updatedBy string) error {
	if db == nil {
		return fmt.Errorf("connexion base indisponible")
	}
	value = strings.TrimSpace(value)
	if value == "" {
		return Effacer(db, key, updatedBy)
	}
	if valider == nil {
		return fmt.Errorf("%s : aucun validateur fourni, écriture refusée", key)
	}
	if err := valider(value); err != nil {
		return err
	}
	if len(value) > 255 {
		return fmt.Errorf("%s : valeur trop longue", key)
	}
	if _, err := db.Exec(
		`INSERT INTO server_settings (setting_key, setting_value, updated_by)
		 VALUES (?, ?, ?)
		 ON DUPLICATE KEY UPDATE setting_value = VALUES(setting_value), updated_by = VALUES(updated_by)`,
		key, value, updatedBy); err != nil {
		logs.Write_LogCode("ERROR", logs.CodeDBQuery, "dbsettings: écriture de "+key+" échouée : "+err.Error())
		return fmt.Errorf("enregistrement du réglage %s : %w", key, err)
	}
	logs.Write_Log("SECURITY", fmt.Sprintf("réglage serveur %s porté à %q par %s", key, value, updatedBy))
	return nil
}

// Effacer retire un réglage : le lecteur retombe sur son défaut.
func Effacer(db *sql.DB, key, updatedBy string) error {
	if db == nil {
		return fmt.Errorf("connexion base indisponible")
	}
	if _, err := db.Exec(`DELETE FROM server_settings WHERE setting_key = ?`, key); err != nil {
		logs.Write_LogCode("ERROR", logs.CodeDBQuery, "dbsettings: effacement de "+key+" échoué : "+err.Error())
		return fmt.Errorf("effacement du réglage %s : %w", key, err)
	}
	logs.Write_Log("SECURITY", fmt.Sprintf("réglage serveur %s retiré par %s", key, updatedBy))
	return nil
}
