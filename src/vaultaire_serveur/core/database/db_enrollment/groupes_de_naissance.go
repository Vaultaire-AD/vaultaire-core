package dbenrollment

import (
	"database/sql"
	"fmt"
	"strings"
)

// Groupes de NAISSANCE d'une clé d'enrôlement — lot 7 du point 38.
//
// # Ce que cela résout
//
// Un proxy enrôlé n'appartient à aucun groupe. Il faut donc, après chaque
// déploiement, aller le rattacher à la main au groupe de son site — sans quoi
// l'affinité du lot 6 ne trie rien pour lui, et il sert le parc entier
// indifféremment.
//
// Une chaîne de déploiement qui crée des proxies sans intervention humaine ne
// peut pas faire ce geste : elle n'a que la clé. Porter les groupes SUR la clé
// referme la boucle — la clé du site de Lyon produit des proxies de Lyon.
//
// # Appliqué UNE FOIS, à l'enrôlement
//
// Et jamais relu. Une clé modifiée ne doit pas changer les groupes d'un service
// déjà en production : le lien entre la cause et l'effet serait introuvable des
// mois plus tard. Après l'enrôlement, les groupes du service se modifient comme
// ceux de n'importe quelle machine.

// SetKeyGroups fixe les groupes de naissance d'une clé.
//
// Remplacement et non ajout : l'appelant décrit l'état voulu. Une liste vide
// retire tout rattachement — la clé produit alors des services sans groupe,
// c'est-à-dire le comportement d'avant le lot 7.
//
// # Aucune vérification d'existence ici
//
// Les noms sont enregistrés tels quels. Vérifier à l'émission ne servirait pas à
// grand-chose : la clé sera consommée des mois plus tard, et c'est à CE moment
// que le groupe doit exister. Le contrôle utile est à la consommation.
//
// L'appelant qui veut prévenir l'administrateur au moment de la saisie peut le
// faire — c'est un confort, pas une garantie.
func SetKeyGroups(db *sql.DB, keyID int, groupes []string) error {
	if db == nil {
		return fmt.Errorf("connexion base indisponible")
	}

	tx, err := db.Begin()
	if err != nil {
		return fmt.Errorf("ouverture de transaction : %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	if _, err := tx.Exec(
		`DELETE FROM service_enrollment_key_group WHERE d_id_key = ?`, keyID); err != nil {
		return fmt.Errorf("retrait des groupes de la clé %d : %w", keyID, err)
	}

	vus := map[string]bool{}
	for _, brut := range groupes {
		nom := strings.TrimSpace(brut)
		if nom == "" || vus[nom] {
			continue
		}
		vus[nom] = true
		if _, err := tx.Exec(
			`INSERT INTO service_enrollment_key_group (d_id_key, group_name) VALUES (?, ?)`,
			keyID, nom); err != nil {
			return fmt.Errorf("ajout du groupe %q à la clé %d : %w", nom, keyID, err)
		}
	}

	return tx.Commit()
}

// KeyGroups rend les groupes de naissance d'une clé, triés.
func KeyGroups(db *sql.DB, keyID int) ([]string, error) {
	if db == nil {
		return nil, fmt.Errorf("connexion base indisponible")
	}

	rows, err := db.Query(
		`SELECT group_name FROM service_enrollment_key_group
		  WHERE d_id_key = ? ORDER BY group_name`, keyID)
	if err != nil {
		return nil, fmt.Errorf("lecture des groupes de la clé %d : %w", keyID, err)
	}
	defer closeRows(rows)

	var noms []string
	for rows.Next() {
		var nom string
		if err := rows.Scan(&nom); err != nil {
			return nil, fmt.Errorf("lecture d'un groupe de clé : %w", err)
		}
		noms = append(noms, nom)
	}
	return noms, rows.Err()
}

// KeyGroupsByKey rend les groupes de TOUTES les clés, indexés par identifiant.
//
// Une requête pour la vue des clés : une par ligne affichée transformerait un
// tableau de vingt clés en vingt-et-un allers-retours.
func KeyGroupsByKey(db *sql.DB) (map[int][]string, error) {
	if db == nil {
		return nil, fmt.Errorf("connexion base indisponible")
	}

	rows, err := db.Query(
		`SELECT d_id_key, group_name FROM service_enrollment_key_group
		  ORDER BY d_id_key, group_name`)
	if err != nil {
		return nil, fmt.Errorf("lecture des groupes de clés : %w", err)
	}
	defer closeRows(rows)

	parCle := map[int][]string{}
	for rows.Next() {
		var id int
		var nom string
		if err := rows.Scan(&id, &nom); err != nil {
			return nil, fmt.Errorf("lecture d'un groupe de clé : %w", err)
		}
		parCle[id] = append(parCle[id], nom)
	}
	return parCle, rows.Err()
}
