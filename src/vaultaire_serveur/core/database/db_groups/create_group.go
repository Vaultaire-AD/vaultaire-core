package dbgroups

import (
	"database/sql"
	"fmt"
	"vaultaire/core/domainname"
	"vaultaire/core/logs"
)

// CreateGroup crée un groupe dans un domaine, et les domaines parents qui
// manquent.
//
// Voir CreateGroupAvecParents pour le détail ; cette forme ignore la liste des
// parents créés.
func CreateGroup(db *sql.DB, groupName string, domainName string) (int64, error) {
	id, _, err := CreateGroupAvecParents(db, groupName, domainName)
	return id, err
}

// CreateGroupAvecParents crée un groupe et rend aussi les domaines parents
// qu'il a fallu créer.
//
// # Pourquoi créer les parents
//
// Un domaine n'existe que porté par un groupe (table domain_group). Créer
// `infra.acme.lan` sans que rien ne porte `acme.lan` laissait un annuaire
// bancal : l'arbre affichait un nœud `acme.lan` qui n'existait pas en base, sur
// lequel on ne pouvait rien rattacher, et aucun compte ne pouvait se connecter
// sous `@acme.lan` — le domaine principal, le seul valide pour une connexion.
//
// Chaque domaine parent manquant, jusqu'au domaine principal, reçoit donc un
// groupe du même nom que lui (`acme.lan`, `cloud.acme.lan`), sans membre ni
// permission. Le nom du domaine est le seul nom qui ne peut pas entrer en
// collision avec un groupe métier sans que ce soit voulu : group_name est
// unique dans tout l'annuaire.
//
// Le tout dans UNE transaction : un groupe créé sans ses parents reproduirait
// exactement l'état qu'on veut éviter.
//
// Le domaine est normalisé (minuscules, sans point final) et validé : au moins
// deux labels, caractères d'un nom DNS.
func CreateGroupAvecParents(db *sql.DB, groupName string, domainName string) (int64, []string, error) {
	if err := domainname.ValiderDomaine(domainName); err != nil {
		return 0, nil, err
	}
	domainName = domainname.NormaliserDomaine(domainName)

	tx, err := db.Begin()
	if err != nil {
		logs.Write_LogCode("ERROR", logs.CodeDBQuery, "database: "+"erreur lors de l'initialisation de la transaction CreateGroupe: "+err.Error())
		return 0, nil, fmt.Errorf("erreur lors de l'initialisation de la transaction: %v", err)
	}
	defer func() { _ = tx.Rollback() }()

	crees, err := creerParentsManquants(tx, domainName)
	if err != nil {
		logs.Write_LogCode("ERROR", logs.CodeDBQuery, "database: CreateGroup: "+err.Error())
		return 0, nil, err
	}

	groupID, err := insererGroupe(tx, groupName, domainName)
	if err != nil {
		logs.Write_LogCode("ERROR", logs.CodeDBQuery, "database: CreateGroup: "+err.Error())
		return 0, nil, err
	}

	if err := tx.Commit(); err != nil {
		logs.Write_LogCode("ERROR", logs.CodeDBQuery, "database: "+"erreur lors de la validation de la transaction CreateGroupe : "+err.Error())
		return 0, nil, fmt.Errorf("erreur lors de la validation de la transaction: %v", err)
	}
	for _, p := range crees {
		logs.Write_Log("INFO", fmt.Sprintf("domaine parent %s créé (groupe %s) pour %s", p, p, domainName))
	}
	return groupID, crees, nil
}

// CreerDomainesParentsManquants comble les trous de l'arborescence existante.
//
// Rattrapage des bases créées avant que CreateGroup ne crée les parents : un
// `infra.acme.lan` sans `acme.lan` y reste possible. Appelée à chaque
// démarrage ; ne crée que ce qui manque, donc sans effet la seconde fois.
func CreerDomainesParentsManquants(db *sql.DB) ([]string, error) {
	if db == nil {
		return nil, fmt.Errorf("base indisponible")
	}
	rows, err := db.Query(`SELECT DISTINCT domain_name FROM domain_group`)
	if err != nil {
		return nil, fmt.Errorf("lecture des domaines : %w", err)
	}
	var domaines []string
	for rows.Next() {
		var d string
		if err := rows.Scan(&d); err != nil {
			rows.Close()
			return nil, err
		}
		domaines = append(domaines, d)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return nil, err
	}

	var total []string
	for _, d := range domaines {
		if domainname.ValiderDomaine(d) != nil {
			// Un domaine hors forme (ancienne saisie) n'est pas corrigé ici :
			// deviner son parent serait inventer.
			continue
		}
		tx, err := db.Begin()
		if err != nil {
			return total, err
		}
		crees, err := creerParentsManquants(tx, domainname.NormaliserDomaine(d))
		if err != nil {
			_ = tx.Rollback()
			return total, fmt.Errorf("parents de %s : %w", d, err)
		}
		if err := tx.Commit(); err != nil {
			return total, err
		}
		total = append(total, crees...)
	}
	return total, nil
}

// creerParentsManquants crée, dans tx, un groupe pour chaque ancêtre de domaine
// qui n'existe pas encore. Rend les domaines créés.
func creerParentsManquants(tx *sql.Tx, domaine string) ([]string, error) {
	var crees []string
	for _, parent := range domainname.Ancetres(domaine) {
		var n int
		// FOR UPDATE : deux créations simultanées sous le même parent ne le
		// créent pas deux fois.
		if err := tx.QueryRow(
			`SELECT COUNT(*) FROM domain_group WHERE LOWER(domain_name) = ? FOR UPDATE`, parent,
		).Scan(&n); err != nil {
			return crees, fmt.Errorf("lecture du domaine %s : %w", parent, err)
		}
		if n > 0 {
			continue
		}

		var pris int
		if err := tx.QueryRow(`SELECT COUNT(*) FROM groups WHERE group_name = ?`, parent).Scan(&pris); err != nil {
			return crees, fmt.Errorf("lecture du groupe %s : %w", parent, err)
		}
		if pris > 0 {
			// Un groupe porte déjà ce nom, mais dans un autre domaine : le
			// réutiliser le déplacerait, en créer un autre est impossible
			// (nom unique). On s'arrête et on le dit.
			return crees, fmt.Errorf(
				"le domaine parent %s n'existe pas et le groupe %q, qui devrait le porter, existe déjà dans un autre domaine : "+
					"créez d'abord un groupe dans %s", parent, parent, parent)
		}
		if _, err := insererGroupe(tx, parent, parent); err != nil {
			return crees, err
		}
		crees = append(crees, parent)
	}
	return crees, nil
}

// insererGroupe écrit le groupe et son domaine.
func insererGroupe(tx *sql.Tx, groupName, domainName string) (int64, error) {
	result, err := tx.Exec(`INSERT INTO groups (group_name) VALUES (?)`, groupName)
	if err != nil {
		return 0, fmt.Errorf("erreur lors de l'insertion du groupe %s: %v", groupName, err)
	}
	groupID, err := result.LastInsertId()
	if err != nil {
		return 0, fmt.Errorf("erreur lors de la récupération de l'ID du groupe: %v", err)
	}
	if _, err := tx.Exec(`INSERT INTO domain_group (d_id_group, domain_name) VALUES (?, ?)`, groupID, domainName); err != nil {
		return 0, fmt.Errorf("erreur lors de l'insertion du domaine %s: %v", domainName, err)
	}
	return groupID, nil
}
