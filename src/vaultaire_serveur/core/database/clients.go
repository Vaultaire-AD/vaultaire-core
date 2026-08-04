package database

import (
	"database/sql"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"vaultaire/core/logs"
	"vaultaire/core/storage"
)

func Create_ClientSoftware(db *sql.DB, computeurID, logicielType, publicKey string, isServeur bool) error {
	injection := SanitizeIdentifier(computeurID, logicielType)
	if injection != nil {
		return injection
	}
	// Vérification si le computeurID existe déjà
	var exists bool
	queryCheck := `SELECT EXISTS(SELECT 1 FROM id_logiciels WHERE computeur_id = ?)`
	err := db.QueryRow(queryCheck, computeurID).Scan(&exists)
	if err != nil {
		logs.WriteLog("db", "erreur lors de la vérification de l'existence du computeurID : "+err.Error())
		return fmt.Errorf("erreur lors de la vérification de l'existence du computeurID : %v", err)
	}

	if exists {
		logs.Write_LogCode("WARNING", logs.CodeDBGeneric, "database: le computeurID existe déjà dans la base de données")
		return errors.New("le computeurID existe déjà dans la base de données")
	}

	// Insertion de la nouvelle entrée
	queryInsert := `
	INSERT INTO id_logiciels (public_key, logiciel_type, computeur_id, hostname, serveur, processeur, ram, os)
	VALUES (?, ?, ?, ?, ?, ?, ?, ?)`
	_, err = db.Exec(queryInsert, publicKey, logicielType, computeurID, "default", isServeur, 0, "0Go", "Linux")

	if err != nil {
		logs.WriteLog("db", "erreur lors de l'insertion dans la table id_logiciels : "+err.Error())
		return fmt.Errorf("erreur lors de l'insertion dans la table id_logiciels : %v", err)
	}
	logs.Write_LogCode("DEBUG", logs.CodeNone, "database: Nouvelle entrée insérée avec succès dans la base de données.")
	//fmt.Println("Nouvelle entrée insérée avec succès dans la base de données.")
	return nil
}

func UpdateHostname(db *sql.DB, computeurID, hostname, os, ram, proc string) error {
	// L'identifiant machine nomme une entité : liste blanche. Les informations
	// matérielles sont du texte libre — « Intel(R) Core(TM) i7 », « Ubuntu 22.04
	// LTS » — et ne passeraient pas une liste blanche d'identifiant.
	if err := SanitizeIdentifier(computeurID); err != nil {
		return err
	}
	injection := SanitizeInput(hostname, os, ram, proc)
	if injection != nil {
		return injection
	}
	proccesseur, _ := strconv.Atoi(proc)
	query := `
	UPDATE id_logiciels
	SET
    	hostname = ?,
    	processeur = ?,
    	ram = ?,
    	os = ?
	WHERE computeur_id = ?;
	`

	result, err := db.Exec(query, hostname, proccesseur, ram, os, computeurID)
	if err != nil {
		logs.WriteLog("db", "erreur lors de la mise à jour UpdateHostname : "+err.Error())
	}

	// Vérifier combien de lignes ont été affectées
	rowsAffected, err := result.RowsAffected()
	if err != nil {
		logs.WriteLog("db", "erreur lors de la récupération du nombre de lignes affectées UpdateHostname :"+err.Error())
	}
	if rowsAffected == 0 {
		// logs.WriteLog("db", "aucune ligne mise à jour, vérifiez computeur_id UpdateHostname")
		return nil
	}
	// logs.WriteLog("db", "Mise à jour réussie : "+strconv.FormatInt(rowsAffected, 10)+" ligne(s) affectée(s) UpdateHostname")
	return nil
}

// Supprime un client via son computeur_id
func Command_DELETE_ClientWithComputeurID(db *sql.DB, computeurID string) error {
	injection := SanitizeIdentifier(computeurID)
	if injection != nil {
		return injection
	}
	query := `DELETE FROM id_logiciels WHERE computeur_id = ?`
	_, err := db.Exec(query, computeurID)
	if err != nil {
		logs.WriteLog("db", "Erreur lors de la suppression du client : "+err.Error())
		return fmt.Errorf("erreur lors de la suppression du client %s : %v", computeurID, err)
	}
	logs.Write_LogCode("DEBUG", logs.CodeNone, fmt.Sprintf("database: Client %s supprimé avec succès", computeurID))
	return nil
}

func Command_GET_AllClients(db *sql.DB) ([]storage.GetClientsByPermission, error) {
	// Requête SQL pour récupérer tous les clients
	query := `
		SELECT 
			l.id_logiciel, 
			l.logiciel_type, 
			l.computeur_id, 
			l.hostname, 
			l.serveur, 
			l.processeur, 
			l.ram, 
			l.os 
		FROM 
			id_logiciels l
	`

	// Exécution de la requête SQL
	rows, err := db.Query(query)
	if err != nil {
		logs.WriteLog("db", "Erreur lors de l'exécution de la requête : "+err.Error())
		return nil, fmt.Errorf("erreur lors de l'exécution de la requête : %v", err)
	}
	defer func() {
		if err := rows.Close(); err != nil {
			// Handle or log the error
			logs.Write_Log("ERROR", "Error closing connection: "+err.Error())
		}
	}()

	// Déclaration d'une slice pour stocker les résultats
	var clients []storage.GetClientsByPermission
	for rows.Next() {
		// Structure pour stocker un client logiciel
		var client storage.GetClientsByPermission
		// Scan des résultats de la requête dans la structure
		if err := rows.Scan(&client.ID, &client.LogicielType, &client.ComputeurID, &client.Hostname, &client.Serveur, &client.Processeur, &client.RAM, &client.OS); err != nil {
			logs.WriteLog("db", "Erreur lors du scan des résultats : "+err.Error())
			return nil, fmt.Errorf("erreur lors du scan des résultats : %v", err)
		}
		// Ajout du client à la slice
		clients = append(clients, client)
	}

	// Vérifier s'il y a une erreur d'itération des résultats
	if err = rows.Err(); err != nil {
		logs.WriteLog("db", "Erreur lors de l'itération des résultats : "+err.Error())
		return nil, fmt.Errorf("erreur lors de l'itération des résultats : %v", err)
	}

	// Retourner les clients récupérés
	return clients, nil
}

func Command_GET_ClientByComputeurID(db *sql.DB, computeurID string) (*storage.Software, error) {
	if err := SanitizeIdentifier(computeurID); err != nil {
		return nil, err
	}

	query := `
SELECT 
    l.id_logiciel, 
    l.logiciel_type, 
    l.computeur_id, 
    l.hostname, 
    l.serveur, 
    l.processeur, 
    l.ram, 
    l.os,
    COALESCE(GROUP_CONCAT(DISTINCT g.group_name SEPARATOR ', '), '') AS groups,
    COALESCE(GROUP_CONCAT(DISTINCT p.name_permission SEPARATOR ', '), '') AS permissions
FROM 
    id_logiciels l
LEFT JOIN 
    logiciel_group lg ON l.id_logiciel = lg.d_id_logiciel
LEFT JOIN 
    groups g ON lg.d_id_group = g.id_group
LEFT JOIN 
    group_permission_logiciel lp ON lg.d_id_group = lp.d_id_group
LEFT JOIN 
    client_permission p ON lp.d_id_permission = p.id_permission
WHERE 
    l.computeur_id = ?
GROUP BY 
    l.id_logiciel
`

	row := db.QueryRow(query, computeurID)

	var software storage.Software
	var groups, permissions string

	err := row.Scan(
		&software.ID,
		&software.LogicielType,
		&software.ComputeurID,
		&software.Hostname,
		&software.Serveur,
		&software.Processeur,
		&software.RAM,
		&software.OS,
		&groups,
		&permissions,
	)

	if err != nil {
		if err == sql.ErrNoRows {
			return nil, fmt.Errorf("❌ Aucun client trouvé avec le Computeur ID: %s", computeurID)
		}
		logs.WriteLog("db", "Erreur lors de la récupération du client : "+err.Error())
		return nil, fmt.Errorf("❌ Erreur lors de la récupération du client : %v", err)
	}

	// Transformer les chaînes séparées en slices, en évitant les éléments vides
	if groups == "" {
		software.Groups = []string{}
	} else {
		software.Groups = strings.Split(groups, ", ")
	}

	if permissions == "" {
		software.Permissions = []string{}
	} else {
		software.Permissions = strings.Split(permissions, ", ")
	}

	return &software, nil
}

func Command_GET_ClientsByGroup(db *sql.DB, groupName string) ([]storage.GetClientsByGroup, error) {
	injection := SanitizeIdentifier(groupName)
	if injection != nil {
		return nil, injection
	}
	query := `
		SELECT 
			l.id_logiciel, 
			l.logiciel_type, 
			l.computeur_id, 
			l.hostname, 
			l.serveur, 
			l.processeur, 
			l.ram, 
			l.os 
		FROM 
			logiciel_group lg
		JOIN 
			id_logiciels l ON lg.d_id_logiciel = l.id_logiciel
		JOIN 
			groups g ON lg.d_id_group = g.id_group
		WHERE 
			g.group_name = ?
	`

	rows, err := db.Query(query, groupName)
	if err != nil {
		logs.WriteLog("db", "Erreur lors de l'exécution de la requête : "+err.Error())
		return nil, fmt.Errorf("erreur lors de l'exécution de la requête : %v", err)
	}
	defer func() {
		if err := rows.Close(); err != nil {
			// Handle or log the error
			logs.Write_Log("ERROR", "Error closing connection: "+err.Error())
		}
	}()

	var clients []storage.GetClientsByGroup
	for rows.Next() {
		var client storage.GetClientsByGroup
		if err := rows.Scan(&client.ID, &client.LogicielType, &client.ComputeurID, &client.Hostname, &client.Serveur, &client.Processeur, &client.RAM, &client.OS); err != nil {
			logs.WriteLog("db", "Erreur lors du scan des résultats : "+err.Error())
			return nil, fmt.Errorf("erreur lors du scan des résultats : %v", err)
		}
		clients = append(clients, client)
	}

	// Vérifier s'il y a une erreur d'itération des résultats
	if err = rows.Err(); err != nil {
		logs.WriteLog("db", "Erreur lors de l'itération des résultats : "+err.Error())
		return nil, fmt.Errorf("erreur lors de l'itération des résultats : %v", err)
	}

	return clients, nil
}

// Get_ClientID_By_ComputerID récupère l'id_logiciel d'un client depuis son
// computeur_id.
//
// La version précédente sélectionnait d_id_group en passant par logiciel_group :
// elle retournait donc un identifiant de GROUPE sous le nom de clientID. Le
// défaut se compensait avec celui de Command_GET_GroupIDsFromClientID, qui
// filtrait lui aussi sur la colonne groupe — le couple rendait exactement un
// groupe, toujours le même, et paraissait fonctionner tant qu'un client n'avait
// qu'un seul groupe.
//
// Deux conséquences corrigées ici :
//   - la lecture part de id_logiciels, donc l'identifiant retourné est bien
//     celui du client ;
//   - un client n'appartenant à aucun groupe est désormais trouvé. L'ancienne
//     jointure sur logiciel_group le faisait passer pour inexistant, alors qu'un
//     client sans groupe est un état normal juste après sa création.
func Get_ClientID_By_ComputerID(db *sql.DB, computerID string) (int, error) {
	if err := SanitizeIdentifier(computerID); err != nil {
		return 0, err
	}

	clientID, found, err := LookupClientID(db, computerID)
	if err != nil {
		logs.Write_Log("ERROR", fmt.Sprintf("Erreur Get_ClientID_By_ComputerID: %v", err))
		return 0, err
	}
	if !found {
		return 0, fmt.Errorf("aucun client trouvé pour l'ordinateur %s", computerID)
	}
	return clientID, nil
}

// Command_GET_GroupIDsFromClientID récupère tous les IDs de groupes liés à un client.
//
// clientID est un id_logiciel, pas un id_group : le filtre porte donc sur
// lg.d_id_logiciel. La version précédente filtrait sur lg.d_id_group, ce qui
// retournait le groupe dont l'identifiant coïncidait avec celui du client —
// donc presque toujours un seul groupe, et le plus souvent le mauvais. Le défaut
// passait inaperçu tant que le client avait peu de groupes et un identifiant bas.
//
// Impacts corrigés : résolution des GPO machine, intersection des groupes en
// scope user, et résolution des domaines d'un client pour les contrôles RBAC.
func Command_GET_GroupIDsFromClientID(db *sql.DB, clientID int) ([]int, error) {
	query := `
		SELECT g.id_group
		FROM groups g
		JOIN logiciel_group lg ON lg.d_id_group = g.id_group
		WHERE lg.d_id_logiciel = ?
		ORDER BY g.id_group;
	`
	rows, err := db.Query(query, clientID)
	if err != nil {
		logs.Write_Log("ERROR", fmt.Sprintf("Erreur Command_GET_GroupIDsFromClientID: %v", err))
		return nil, err
	}
	defer func() {
		if err := rows.Close(); err != nil {
			logs.Write_Log("ERROR", "Erreur fermeture curseur Command_GET_GroupIDsFromClientID: "+err.Error())
		}
	}()

	var groupIDs []int
	for rows.Next() {
		var id int
		if err := rows.Scan(&id); err != nil {
			logs.Write_Log("ERROR", fmt.Sprintf("Erreur lecture row Command_GET_GroupIDsFromClientID: %v", err))
			continue
		}
		groupIDs = append(groupIDs, id)
	}
	// Sans ce contrôle, une erreur survenue en cours d'itération retournerait une
	// liste tronquée sans le signaler : le client se verrait appliquer les GPO
	// d'une partie seulement de ses groupes, silencieusement.
	if err := rows.Err(); err != nil {
		logs.Write_Log("ERROR", fmt.Sprintf("Erreur parcours Command_GET_GroupIDsFromClientID: %v", err))
		return nil, err
	}
	return groupIDs, nil
}

func Get_Client_Software_PublicKey(db *sql.DB, clientSoftwareID string) (string, error) {
	injection := SanitizeIdentifier(clientSoftwareID)
	if injection != nil {
		return "", injection
	}
	var publicKey string
	query := `SELECT public_key FROM id_logiciels WHERE computeur_id = ?`

	err := db.QueryRow(query, clientSoftwareID).Scan(&publicKey)
	if err != nil {
		if err == sql.ErrNoRows {
			logs.WriteLog("db", "clé publique non trouvée pour clientSoftware ID"+err.Error())
			return "", fmt.Errorf("clé publique non trouvée pour clientSoftware ID %s", clientSoftwareID)
		}
		logs.WriteLog("db", "erreur lors de la récupération de la clé publique du clientSoftware : "+err.Error())
		return "", fmt.Errorf("erreur lors de la récupération de la clé publique du clientSoftware : %v", err)
	}

	return publicKey, nil
}

func Command_ADD_SoftwareToGroup(db *sql.DB, computeur_id, groupName string) error {
	injection := SanitizeIdentifier(computeur_id, groupName)
	if injection != nil {
		return injection
	}
	// Vérifier si le logiciel existe
	logicielID, found, err := LookupClientID(db, computeur_id)
	if err != nil {
		logs.WriteLog("db", "Erreur lors de la récupération du logiciel : "+err.Error())
		return fmt.Errorf("erreur lors de la récupération du logiciel : %v", err)
	}
	if !found {
		return fmt.Errorf("logiciel avec l'computeur_id %s introuvable", computeur_id)
	}

	// Vérifier si le groupe existe
	groupID, found, err := LookupGroupID(db, groupName)
	if err != nil {
		logs.WriteLog("db", "Erreur lors de la récupération du groupe : "+err.Error())
		return fmt.Errorf("erreur lors de la récupération du groupe : %v", err)
	}
	if !found {
		return fmt.Errorf("groupe avec le nom %s introuvable", groupName)
	}

	// Vérifier si le logiciel est déjà dans ce groupe
	already, err := clientGroupLinkExists(db, logicielID, groupID)
	if err != nil {
		logs.WriteLog("db", "Erreur lors de la vérification du logiciel dans le groupe : "+err.Error())
		return fmt.Errorf("erreur lors de la vérification du logiciel dans le groupe : %v", err)
	}

	if already {
		return fmt.Errorf("le logiciel %s est déjà dans le groupe %s", computeur_id, groupName)
	}

	// Ajouter le logiciel au groupe
	queryAdd := `INSERT INTO logiciel_group (d_id_logiciel, d_id_group) VALUES (?, ?)`
	_, err = db.Exec(queryAdd, logicielID, groupID)
	if err != nil {
		logs.WriteLog("db", "Erreur lors de l'ajout du logiciel au groupe : "+err.Error())
		return fmt.Errorf("erreur lors de l'ajout du logiciel au groupe : %v", err)
	}

	return nil
}

// Command_Remove_SoftwareFromGroup supprime un logiciel d'un groupe
func Command_Remove_SoftwareFromGroup(db *sql.DB, computeur_id, groupName string) error {
	injection := SanitizeIdentifier(computeur_id, groupName)
	if injection != nil {
		return injection
	}
	// Vérifier si le logiciel existe
	logicielID, found, err := LookupClientID(db, computeur_id)
	if err != nil {
		logs.WriteLog("db", fmt.Sprintf("Erreur lors de la récupération du logiciel : %v", err))
		return fmt.Errorf("erreur lors de la récupération du logiciel : %v", err)
	}
	if !found {
		logs.Write_LogCode("WARNING", logs.CodeDBGeneric, fmt.Sprintf("database: Logiciel avec computeur_id %s introuvable", computeur_id))
		return fmt.Errorf("logiciel avec computeur_id %s introuvable", computeur_id)
	}

	// Vérifier si le groupe existe
	groupID, found, err := LookupGroupID(db, groupName)
	if err != nil {
		logs.WriteLog("db", fmt.Sprintf("Erreur lors de la récupération du groupe : %v", err))
		return fmt.Errorf("erreur lors de la récupération du groupe : %v", err)
	}
	if !found {
		logs.Write_LogCode("WARNING", logs.CodeDBGeneric, fmt.Sprintf("database: Groupe %s introuvable", groupName))
		return fmt.Errorf("groupe %s introuvable", groupName)
	}

	// Vérifier si le logiciel est dans ce groupe
	member, err := clientGroupLinkExists(db, logicielID, groupID)
	if err != nil {
		logs.WriteLog("db", fmt.Sprintf("Erreur lors de la vérification du logiciel dans le groupe : %v", err))
		return fmt.Errorf("erreur lors de la vérification du logiciel dans le groupe : %v", err)
	}

	if !member {
		logs.Write_LogCode("WARNING", logs.CodeDBGeneric, fmt.Sprintf("database: Le logiciel %s ne fait pas partie du groupe %s", computeur_id, groupName))
		return fmt.Errorf("le logiciel %s ne fait pas partie du groupe %s", computeur_id, groupName)
	}

	// Supprimer le logiciel du groupe
	queryRemove := `DELETE FROM logiciel_group WHERE d_id_logiciel = ? AND d_id_group = ?`
	_, err = db.Exec(queryRemove, logicielID, groupID)
	if err != nil {
		logs.WriteLog("db", fmt.Sprintf("Erreur lors de la suppression du logiciel du groupe : %v", err))
		return fmt.Errorf("erreur lors de la suppression du logiciel du groupe : %v", err)
	}

	// Log de succès
	logs.Write_LogCode("DEBUG", logs.CodeNone, fmt.Sprintf("database: Logiciel %s retiré du groupe %s", computeur_id, groupName))

	return nil
}
