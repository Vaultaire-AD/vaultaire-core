package commanddelete

import (
	"fmt"
	"vaultaire/core/database"
	dbclients "vaultaire/core/database/db_clients"
	"vaultaire/core/logs"
	"vaultaire/core/permission"
)

// delete_Client_Command_Parser handles the deletion of a client by its computer ID.
// Usage: delete -c <computer_id>
func delete_Client_Command_Parser(command_list []string, sender_groupsIDs []int, action, sender_Username string) string {
	db := database.GetDatabase()

	// 🔸 Vérification du format
	if len(command_list) != 2 || command_list[0] != "-c" {
		return "Requête invalide. Utilisez : delete -c <computer_id>"
	}

	clientID := command_list[1]

	// 🔸 Protection contre suppression critique
	if clientID == "vaultaire" {
		logs.Write_Log("SECURITY", fmt.Sprintf("%s a tenté de supprimer le client protégé '%s'", sender_Username, clientID))
		return ">> Suppression refusée : client 'vaultaire' protégé."
	}

	// 🔹 Étape 1 : Récupération du client
	client, err := dbclients.Command_GET_ClientByComputeurID(db, clientID)
	if err != nil {
		logs.Write_Log("WARNING", fmt.Sprintf("Erreur récupération client %s : %v", clientID, err))
		return fmt.Sprintf("Erreur récupération client %s : %v", clientID, err)
	}

	// 🔹 Étape 2 : Récupération des domaines associés à tous les groupes du client
	var domains []string
	for _, group := range client.Groups { // client.Groups est un slice de string
		groupDomains, err := permission.GetDomainsFromGroupName(group)
		if err != nil {
			logs.Write_Log("WARNING", fmt.Sprintf("Erreur récupération domaines du groupe %s pour le client %s : %v", group, clientID, err))
			return fmt.Sprintf("Erreur récupération domaines du client %s : %v", clientID, err)
		}
		domains = append(domains, groupDomains...)
	}

	// Optionnel : supprimer les doublons dans domains si besoin
	uniqueDomains := make(map[string]struct{})
	for _, d := range domains {
		uniqueDomains[d] = struct{}{}
	}
	domains = make([]string, 0, len(uniqueDomains))
	for d := range uniqueDomains {
		domains = append(domains, d)
	}

	// 🔹 Étape 3 : Vérification des permissions sur les domaines liés
	ok, reason := permission.CheckPermissionsAllDomains(sender_groupsIDs, action, domains)
	if !ok {
		logs.Write_Log("WARNING", fmt.Sprintf("Permission refused: user=%s action=%s client=%s reason=%s", sender_Username, action, clientID, reason))
		logs.Write_Log("SECURITY", fmt.Sprintf("Suppression refusée : %s tente de supprimer le client %s (domaines : %v) — %s", sender_Username, clientID, domains, reason))
		return fmt.Sprintf("Permission refusée : %s", reason)
	}
	logs.Write_Log("INFO", fmt.Sprintf("Permission used: user=%s action=%s (delete client)", sender_Username, action))

	// 🔹 Étape 4 : Suppression du client
	err = dbclients.Command_DELETE_ClientWithComputeurID(db, clientID)
	if err != nil {
		logs.Write_Log("ERROR", fmt.Sprintf("Erreur suppression client %s : %v", clientID, err))
		return fmt.Sprintf("Erreur lors de la suppression du client %s : %v", clientID, err)
	}

	// 🔹 Étape 5 : Vérification de suppression effective
	_, err = dbclients.Command_GET_ClientByComputeurID(db, clientID)
	if err == nil {
		logs.Write_Log("WARNING", fmt.Sprintf("Le client %s semble encore exister après suppression.", clientID))
		return fmt.Sprintf("Le client %s semble encore exister après suppression.", clientID)
	}

	// 🔹 Étape 6 : Log succès
	logs.Write_Log("INFO", fmt.Sprintf("Client '%s' supprimé avec succès par %s", clientID, sender_Username))
	return fmt.Sprintf("Client '%s' supprimé avec succès.", clientID)
}
