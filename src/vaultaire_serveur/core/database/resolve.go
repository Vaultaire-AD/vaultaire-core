package database

import (
	"database/sql"
	"fmt"
)

// Résolution d'identifiants : nom d'entité -> clé primaire.
//
// Ces requêtes étaient recopiées dans une vingtaine de fonctions composées
// (Command_ADD_UserToGroup, Command_Remove_SoftwareFromGroup...), où la
// résolution n'est qu'une étape parmi d'autres. Les copies ne se comportaient
// pas toutes pareil : certaines assainissaient leur entrée, d'autres non.
//
// POURQUOI PAS LES FONCTIONS EXPORTÉES EXISTANTES. GetGroupIDByName et
// Get_User_ID_By_Username produisent leur propre message d'erreur quand
// l'entité est absente. Y rediriger les appelants aurait remplacé « groupe avec
// le nom X introuvable » par un message générique, alors que ces textes
// remontent jusqu'à l'administrateur en CLI et en web. Les résolveurs ci-dessous
// ne décident donc PAS : ils rendent found == false et laissent l'appelant
// formuler l'absence comme il l'entend.

// RowQuerier couvre *sql.DB ET *sql.Tx.
//
// Plusieurs appelants ouvrent une transaction avant de résoudre un identifiant.
// Un helper qui n'accepterait que *sql.DB lirait HORS de cette transaction : sur
// une lecture de clé primaire c'est aujourd'hui sans conséquence, mais le jour
// où la résolution suit une écriture dans la même transaction, elle ne verrait
// pas cette écriture. Le paramètre est une interface pour que la question ne se
// pose jamais.
type RowQuerier interface {
	QueryRow(query string, args ...any) *sql.Row
}

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

// LookupGroupID résout un nom de groupe en id_group.
func LookupGroupID(q RowQuerier, groupName string) (int, bool, error) {
	return lookup(q, `SELECT id_group FROM groups WHERE group_name = ?`, groupName)
}

// LookupUserID résout un nom d'utilisateur en id_user.
func LookupUserID(q RowQuerier, username string) (int, bool, error) {
	return lookup(q, `SELECT id_user FROM users WHERE username = ?`, username)
}

// LookupClientID résout un computeur_id en id_logiciel.
//
// LIMIT 1 : computeur_id n'est pas déclaré unique dans le schéma. Sans la
// limite, un doublon accidentel ferait échouer la lecture au lieu d'en
// désigner un — comportement déjà retenu par Get_ClientID_By_ComputerID.
func LookupClientID(q RowQuerier, computerID string) (int, bool, error) {
	return lookup(q, `SELECT id_logiciel FROM id_logiciels WHERE computeur_id = ? LIMIT 1`, computerID)
}

// LookupClientPermissionID résout un nom de permission CLIENT en id_permission.
func LookupClientPermissionID(q RowQuerier, permissionName string) (int, bool, error) {
	return lookup(q, `SELECT id_permission FROM client_permission WHERE name_permission = ?`, permissionName)
}

// LookupUserPermissionID résout un nom de permission UTILISATEUR en
// id_user_permission.
//
// Les deux familles de permissions vivent dans des tables distinctes et n'ont
// rien à voir : confondre leurs identifiants a déjà produit un défaut réel, voir
// Command_Remove_UserPermissionFromGroup.
func LookupUserPermissionID(q RowQuerier, permissionName string) (int, bool, error) {
	return lookup(q, `SELECT id_user_permission FROM user_permission WHERE name = ? LIMIT 1`, permissionName)
}

// userGroupLinkExists indique si un utilisateur est déjà rattaché à un groupe.
func userGroupLinkExists(q RowQuerier, userID, groupID int) (bool, error) {
	return linkExists(q, `SELECT COUNT(*) FROM users_group WHERE d_id_user = ? AND d_id_group = ?`, userID, groupID)
}

// clientGroupLinkExists indique si un client est déjà rattaché à un groupe.
func clientGroupLinkExists(q RowQuerier, clientID, groupID int) (bool, error) {
	return linkExists(q, `SELECT COUNT(*) FROM logiciel_group WHERE d_id_logiciel = ? AND d_id_group = ?`, clientID, groupID)
}

func linkExists(q RowQuerier, query string, left, right int) (bool, error) {
	if q == nil {
		return false, fmt.Errorf("connexion base indisponible")
	}
	var count int
	if err := q.QueryRow(query, left, right).Scan(&count); err != nil {
		return false, err
	}
	return count > 0, nil
}
