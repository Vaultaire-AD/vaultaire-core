package database

import (
	"database/sql"
	"fmt"
	"vaultaire/core/logs"
)

func CreateGroup(db *sql.DB, groupName string, domainName string) (int64, error) {

	tx, err := db.Begin()
	if err != nil {
		logs.WriteLog("db", "erreur lors de l'initialisation de la transaction CreateGroupe: "+err.Error())
		return 0, fmt.Errorf("erreur lors de l'initialisation de la transaction: %v", err)
	}

	// Insérer le groupe
	result, err := tx.Exec(`INSERT INTO groups (group_name) VALUES (?)`, groupName)
	if err != nil {
		err = tx.Rollback()
		if err != nil {
			logs.WriteLog("db", "erreur lors de l'annulation de la transaction : "+err.Error())
		}
		logs.WriteLog("db", "erreur lors de l'insertion du groupe CreateGroupe: "+err.Error())
		return 0, fmt.Errorf("erreur lors de l'insertion du groupe: %v", err)
	}

	groupID, err := result.LastInsertId()
	if err != nil {
		err = tx.Rollback()
		if err != nil {
			logs.WriteLog("db", "erreur lors de l'annulation de la transaction : "+err.Error())
		}
		logs.WriteLog("db", "erreur lors de la récupération de l'ID du groupe CreateGroupe: "+err.Error())
		return 0, fmt.Errorf("erreur lors de la récupération de l'ID du groupe: %v", err)
	}
	// Insérer le domaine associé
	_, err = tx.Exec(`INSERT INTO domain_group (d_id_group, domain_name) VALUES (?, ?)`, groupID, domainName)
	if err != nil {
		err = tx.Rollback()
		if err != nil {
			logs.WriteLog("db", "erreur lors de l'annulation de la transaction : "+err.Error())
		}
		logs.WriteLog("db", "erreur lors de l'insertion du domaine CreateGroup: "+err.Error())
		return 0, fmt.Errorf("erreur lors de l'insertion du domaine: %v", err)
	}

	err = tx.Commit()
	if err != nil {
		logs.WriteLog("db", "erreur lors de la validation de la transaction CreateGroupe : "+err.Error())
		return 0, fmt.Errorf("erreur lors de la validation de la transaction: %v", err)
	}

	return groupID, nil
}

// DeleteGroup a été supprimée : code mort ET cassé.
//
// Aucun appelant dans tout le dépôt. Mais surtout, elle visait deux tables qui
// n'existent pas : `group_permission` et `groupe`. Le schéma réel porte
// `group_user_permission`, `group_permission_logiciel` et `groups`. Elle aurait
// donc échoué à la première exécution, sur une erreur MySQL de table inconnue.
//
// C'est le danger de ce genre de reste : le nom est parfaitement plausible, la
// signature aussi, et quiconque aurait cherché « comment supprimer un groupe »
// l'aurait appelée en toute confiance. La suppression d'un groupe passe par
// Command_DELETE_GroupWithGroupName, qui connaît le vrai schéma.

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
	if err := SanitizeIdentifier(groupName); err != nil {
		return 0, err
	}

	var groupID int
	err := db.QueryRow(`SELECT id_group FROM groups WHERE group_name = ?`, groupName).Scan(&groupID)
	if err != nil {
		if err == sql.ErrNoRows {
			// Le message parlait de « permission », par copier-coller depuis une
			// fonction de permission. Un administrateur qui cherchait pourquoi un
			// groupe manquait trouvait « permission introuvable » dans les
			// journaux, et cherchait au mauvais endroit.
			logs.Write_LogCode("WARNING", logs.CodeDBGeneric,
				fmt.Sprintf("database: groupe '%s' introuvable", groupName))
			return 0, fmt.Errorf("groupe '%s' introuvable", groupName)
		}
		logs.Write_LogCode("ERROR", logs.CodeDBQuery,
			"database: lecture de l'ID du groupe '"+groupName+"' échouée : "+err.Error())
		return 0, fmt.Errorf("erreur lors de la récupération de l'ID du groupe '%s' : %v", groupName, err)
	}

	return groupID, nil
}
