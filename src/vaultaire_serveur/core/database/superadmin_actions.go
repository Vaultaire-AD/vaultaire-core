package database

import (
	"database/sql"
	"fmt"

	"vaultaire/core/logs"
)

// EnsureSuperadminActions accorde toutes les actions connues à la permission
// d'amorçage `vaultaire_all`.
//
// POURQUOI CETTE FONCTION EXISTE. Create_DataBase énumérait les clés d'action à
// la main, dans une longue clause SQL `UNION ALL`. Cette liste a dérivé du code
// dès le premier ajout : `write:killswitch` n'y figurait pas, donc le groupe
// superadmin lui-même n'avait pas le droit de déclencher le kill switch — et
// comme l'interface masque ce qu'on n'a pas le droit de faire, le bouton
// n'apparaissait nulle part. Le symptôme était une fonctionnalité invisible,
// la cause une liste recopiée.
//
// La liste est désormais fournie par l'appelant depuis
// permission.AllActionKeys(), la seule source de vérité. Elle est passée en
// paramètre plutôt qu'importée : core/permission importe core/database, un
// import dans l'autre sens créerait un cycle. C'est main, qui voit les deux
// paquets, qui fait la liaison.
//
// Appelée à CHAQUE démarrage, avec des INSERT IGNORE : les bases existantes
// reçoivent ainsi les clés apparues depuis leur création, sans script de
// migration. Une clé déjà présente n'est pas écrasée — si un administrateur a
// délibérément restreint une action, on ne la lui rouvre pas dans son dos.
func EnsureSuperadminActions(db *sql.DB, actionKeys []string) error {
	if db == nil {
		return fmt.Errorf("base indisponible")
	}
	if len(actionKeys) == 0 {
		return fmt.Errorf("aucune action à accorder")
	}

	var permID int64
	err := db.QueryRow(
		"SELECT id_user_permission FROM user_permission WHERE name = ? LIMIT 1",
		ProtectedUserPermission).Scan(&permID)
	if err == sql.ErrNoRows {
		// La permission n'existe pas encore : Create_DataBase ne l'a pas créée,
		// ce qui arrive sur une base vide au tout premier démarrage si l'ordre
		// des instructions change. Ce n'est pas une erreur bloquante, le
		// prochain démarrage rattrapera.
		logs.Write_Log("WARNING",
			"bootstrap: permission "+ProtectedUserPermission+" absente, actions non accordées")
		return nil
	}
	if err != nil {
		return fmt.Errorf("lecture de la permission %s : %w", ProtectedUserPermission, err)
	}

	// Les actions legacy vivent dans des colonnes de user_permission, pas dans
	// la table des actions. Command_SET_UserPermissionAction sait router, mais
	// il refuse d'écrire sur la permission protégée (garde volontaire) : on
	// écrit donc directement ici, en connaissance de cause.
	var granted, skipped int
	for _, key := range actionKeys {
		if legacyColumnsSuperadmin[key] {
			// Colonne legacy : on ne l'écrase que si elle vaut « nil », pour ne
			// pas défaire un réglage explicite.
			query := fmt.Sprintf(
				"UPDATE user_permission SET %s = 'all' WHERE id_user_permission = ? AND (%s IS NULL OR %s = 'nil' OR %s = '')",
				key, key, key, key)
			res, execErr := db.Exec(query, permID)
			if execErr != nil {
				return fmt.Errorf("action legacy %s : %w", key, execErr)
			}
			if n, _ := res.RowsAffected(); n > 0 {
				granted++
			} else {
				skipped++
			}
			continue
		}

		res, execErr := db.Exec(
			`INSERT IGNORE INTO user_permission_action (id_user_permission, action_key, value)
			 VALUES (?, ?, 'all')`, permID, key)
		if execErr != nil {
			return fmt.Errorf("action %s : %w", key, execErr)
		}
		if n, _ := res.RowsAffected(); n > 0 {
			granted++
		} else {
			skipped++
		}
	}

	if granted > 0 {
		logs.Write_Log("INFO", fmt.Sprintf(
			"bootstrap: %d action(s) accordée(s) à %s, %d déjà présente(s)",
			granted, ProtectedUserPermission, skipped))
	}
	return nil
}

// legacyColumnsSuperadmin réplique la table de routage de db_permission.
//
// Dupliquée plutôt qu'importée : db_permission importe core/database, l'inverse
// créerait un cycle. Elle est figée — ces cinq colonnes sont un héritage du
// modèle LDAP d'origine et aucune n'a été ajoutée depuis — donc le risque de
// dérive est nul, contrairement à la liste d'actions qui, elle, s'allonge.
var legacyColumnsSuperadmin = map[string]bool{
	"none": true, "web_admin": true, "auth": true, "compare": true, "search": true,
}
