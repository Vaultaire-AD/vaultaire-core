package commanddelete

import (
	"fmt"

	"vaultaire/core/database"
	dbgpo "vaultaire/core/database/db_gpo"
	"vaultaire/core/logs"
	"vaultaire/core/permission"
)

// delete_GPO_Command_Parser supprime définitivement une GPO, ses modules et ses
// liaisons de groupe.
//
// Usage : delete -gpo <nom_gpo>
func delete_GPO_Command_Parser(command_list []string, sender_groupsIDs []int, action, sender_Username string) string {
	db := database.GetDatabase()

	if len(command_list) != 2 || command_list[0] != "-gpo" {
		return "Requête invalide. Utilisez : delete -gpo <nom_de_la_GPO>"
	}

	gpoName := command_list[1]

	// Les domaines sont lus AVANT la suppression : après, la GPO n'a plus de
	// liaison de groupe et la vérification de permission n'aurait plus de portée.
	domains, err := permission.GetDomainslistFromGPO(gpoName)
	if err != nil {
		logs.Write_Log("WARNING", fmt.Sprintf("Erreur récupération domaines GPO %s : %v", gpoName, err))
		return fmt.Sprintf("Erreur lors de la récupération des domaines de la GPO %s : %v", gpoName, err)
	}
	// Une GPO non liée à un groupe ne couvre aucun domaine : supprimer exige
	// alors le droit global, faute de quoi n'importe quel délégué pourrait
	// effacer une GPO en attente de rattachement.
	if len(domains) == 0 {
		domains = []string{"*"}
	}

	ok, reason := permission.CheckPermissionsAllDomains(sender_groupsIDs, action, domains)
	if !ok {
		logs.Write_Log("WARNING", fmt.Sprintf("Permission refused: user=%s action=%s gpo=%s reason=%s", sender_Username, action, gpoName, reason))
		logs.Write_Log("SECURITY", fmt.Sprintf("Suppression refusée : %s tente de supprimer la GPO %s (domaines : %v) — %s", sender_Username, gpoName, domains, reason))
		return fmt.Sprintf("Permission refusée : %s", reason)
	}
	logs.Write_Log("INFO", fmt.Sprintf("Permission used: user=%s action=%s (delete gpo)", sender_Username, action))

	if err := dbgpo.DeletePolicyByName(db, gpoName); err != nil {
		logs.Write_Log("ERROR", fmt.Sprintf("Erreur suppression GPO %s : %v", gpoName, err))
		return fmt.Sprintf("Erreur lors de la suppression de la GPO %s : %v", gpoName, err)
	}

	if dbgpo.PolicyExists(db, gpoName) {
		return fmt.Sprintf("La GPO %s semble encore exister après suppression.", gpoName)
	}

	logs.Write_Log("INFO", fmt.Sprintf("GPO '%s' supprimée avec succès par %s", gpoName, sender_Username))
	return fmt.Sprintf("GPO '%s' supprimée avec succès (modules et liaisons de groupe inclus).", gpoName)
}
