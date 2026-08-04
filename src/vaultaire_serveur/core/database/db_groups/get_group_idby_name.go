package dbgroups

import (
	"database/sql"
	"fmt"
	database "vaultaire/core/database"
	"vaultaire/core/logs"
)

// GetGroupIDByName retourne l'identifiant interne d'un groupe depuis son nom.
//
// POINT D'ENTRÉE UNIQUE pour cette question. La même requête était recopiée
// dans dix fonctions du projet ; ce helper existait déjà mais n'était appelé
// par presque personne, et il était le SEUL à ne pas assainir son entrée — les
// copies en ligne, elles, le faisaient. Rediriger les appelants vers lui aurait
// donc affaibli le code au lieu de le renforcer. D'où l'ordre : durcir ici
// d'abord, rediriger ensuite.
//
// Un nom de groupe désigne une entité : liste blanche (SanitizeIdentifier), pas
// liste noire. Le paramètre est déjà passé en requête préparée, donc ce n'est
// pas une protection contre l'injection : c'est un refus des noms que
// l'annuaire n'aurait jamais dû accepter, posé au plus près de la base pour
// couvrir tous les appelants, y compris ceux qui seront écrits plus tard.
func GetGroupIDByName(db *sql.DB, groupName string) (int, error) {
	if err := database.SanitizeIdentifier(groupName); err != nil {
		return 0, err
	}

	groupID, found, err := database.LookupGroupID(db, groupName)
	if err != nil {
		logs.Write_LogCode("ERROR", logs.CodeDBQuery,
			"database: lecture de l'ID du groupe '"+groupName+"' échouée : "+err.Error())
		return 0, fmt.Errorf("erreur lors de la récupération de l'ID du groupe '%s' : %v", groupName, err)
	}
	if !found {
		// Le message parlait de « permission », par copier-coller depuis une
		// fonction de permission. Un administrateur qui cherchait pourquoi un
		// groupe manquait trouvait « permission introuvable » dans les
		// journaux, et cherchait au mauvais endroit.
		logs.Write_LogCode("WARNING", logs.CodeDBGeneric,
			fmt.Sprintf("database: groupe '%s' introuvable", groupName))
		return 0, fmt.Errorf("groupe '%s' introuvable", groupName)
	}

	return groupID, nil
}
