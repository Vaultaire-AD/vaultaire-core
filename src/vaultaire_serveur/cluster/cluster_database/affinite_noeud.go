package clusterdatabase

import (
	"database/sql"
	"fmt"
	"sort"
	"strings"
)

// Affinité nœud ↔ groupe — lot 6 du point 38.
//
// # La question à laquelle elle répond
//
// « Quel nœud sert ce site en premier ? »
//
// Sans elle, tous les agents du parc reçoivent la même liste, triée par rôle
// puis par priorité globale. Un parc à plusieurs sites y perd exactement ce
// qu'un proxy est censé apporter : les agents de Lyon peuvent très bien être
// servis par le proxy de Paris, parce que rien ne dit qu'un proxy appartient à
// un site.
//
// # Préférence, jamais exclusivité
//
// Un nœud affin passe DEVANT les autres de son rôle. Il ne les remplace pas :
// tous les nœuds exposés restent dans la liste, en queue.
//
// C'est la règle qui empêche la panne d'un site de devenir une panne
// d'authentification pour ce site. Un agent dont le proxy local est tombé
// descend dans sa liste et finit par joindre un core — plus loin, plus lent, et
// il travaille. Une exclusivité l'aurait laissé sans personne à joindre.
//
// # Pourquoi une table dédiée et non les groupes du client propriétaire
//
// Un proxy est un client et pourrait figurer dans `logiciel_group`. Un CORE, non :
// il n'a pas de ligne client, il se déclare lui-même avec le propriétaire
// réservé « @core:<hostname> ». Faire dépendre l'affinité des groupes du client
// aurait donc laissé les cores dehors, et demandé un second mécanisme pour eux —
// donc deux endroits à lire, à éditer et à tenir d'accord.

// GroupesDuNoeud rend les identifiants de groupes affins à un nœud.
//
// Triés, pour que deux lectures successives rendent la même chose : une liste
// dont l'ordre change ferait varier les vues sans que rien n'ait bougé.
func GroupesDuNoeud(db *sql.DB, idNode int) ([]int, error) {
	if db == nil {
		return nil, fmt.Errorf("connexion base indisponible")
	}

	rows, err := db.Query(
		`SELECT d_id_group FROM cluster_node_group WHERE d_id_node = ? ORDER BY d_id_group`, idNode)
	if err != nil {
		return nil, fmt.Errorf("lecture des groupes du nœud %d : %w", idNode, err)
	}
	defer func() { _ = rows.Close() }()

	var ids []int
	for rows.Next() {
		var id int
		if err := rows.Scan(&id); err != nil {
			return nil, fmt.Errorf("lecture d'un groupe du nœud %d : %w", idNode, err)
		}
		ids = append(ids, id)
	}
	return ids, rows.Err()
}

// AffinitesParNoeud rend les groupes de TOUS les nœuds, indexés par identifiant.
//
// # Pourquoi une seule requête et non une par nœud
//
// La liste des nœuds est calculée à chaque `04_03`, c'est-à-dire au démarrage de
// chaque agent du parc et à chaque reconnexion de son tunnel. Interroger la base
// une fois par nœud ferait, sur un cluster de dix nœuds, dix requêtes par agent
// et par reconnexion — pour une table qui tient entièrement en mémoire.
func AffinitesParNoeud(db *sql.DB) (map[int][]int, error) {
	if db == nil {
		return nil, fmt.Errorf("connexion base indisponible")
	}

	rows, err := db.Query(
		`SELECT d_id_node, d_id_group FROM cluster_node_group ORDER BY d_id_node, d_id_group`)
	if err != nil {
		return nil, fmt.Errorf("lecture des affinités : %w", err)
	}
	defer func() { _ = rows.Close() }()

	parNoeud := map[int][]int{}
	for rows.Next() {
		var idNode, idGroup int
		if err := rows.Scan(&idNode, &idGroup); err != nil {
			return nil, fmt.Errorf("lecture d'une affinité : %w", err)
		}
		parNoeud[idNode] = append(parNoeud[idNode], idGroup)
	}
	return parNoeud, rows.Err()
}

// RemplacerGroupesDuNoeud fixe la liste des groupes affins d'un nœud.
//
// # Remplacement et non ajout
//
// L'appelant décrit l'état voulu, pas un delta. C'est ce qui permet au
// formulaire web d'envoyer une sélection complète, et à la ligne de commande de
// dire « ce nœud sert paris et lyon » sans avoir à retirer ce qui traîne.
//
// # Tout ou rien
//
// Sous transaction : une écriture partielle laisserait le nœud avec un sous-
// ensemble de ses groupes, donc servi à des agents qu'il ne devait plus servir
// et pas à ceux qu'il devait. Le tri n'échouerait pas — il trierait faux, ce qui
// est plus difficile à voir.
func RemplacerGroupesDuNoeud(db *sql.DB, idNode int, idsGroupes []int) error {
	if db == nil {
		return fmt.Errorf("connexion base indisponible")
	}

	tx, err := db.Begin()
	if err != nil {
		return fmt.Errorf("ouverture de transaction : %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	if _, err := tx.Exec(`DELETE FROM cluster_node_group WHERE d_id_node = ?`, idNode); err != nil {
		return fmt.Errorf("retrait des affinités du nœud %d : %w", idNode, err)
	}

	// Dédupliqué : la même sélection peut arriver deux fois d'un formulaire, et
	// la clé primaire composite refuserait la seconde — l'écriture entière
	// échouerait alors sur une saisie que rien ne rend fautive.
	vus := map[int]bool{}
	for _, id := range idsGroupes {
		if id <= 0 || vus[id] {
			continue
		}
		vus[id] = true
		if _, err := tx.Exec(
			`INSERT INTO cluster_node_group (d_id_node, d_id_group) VALUES (?, ?)`,
			idNode, id); err != nil {
			return fmt.Errorf("ajout du groupe %d au nœud %d : %w", id, idNode, err)
		}
	}

	return tx.Commit()
}

// NomsDesGroupesDuNoeud rend les groupes affins sous leur nom, triés.
//
// Pour les vues. Un identifiant numérique ne dit rien à qui lit un tableau, et
// le faire résoudre par chaque appelant produirait autant de requêtes que de
// lignes affichées.
func NomsDesGroupesDuNoeud(db *sql.DB, idNode int) ([]string, error) {
	if db == nil {
		return nil, fmt.Errorf("connexion base indisponible")
	}

	rows, err := db.Query(`
		SELECT g.group_name
		  FROM cluster_node_group cng
		  JOIN groups g ON g.id_group = cng.d_id_group
		 WHERE cng.d_id_node = ?
		 ORDER BY g.group_name`, idNode)
	if err != nil {
		return nil, fmt.Errorf("lecture des groupes du nœud %d : %w", idNode, err)
	}
	defer func() { _ = rows.Close() }()

	var noms []string
	for rows.Next() {
		var nom string
		if err := rows.Scan(&nom); err != nil {
			return nil, fmt.Errorf("lecture d'un nom de groupe : %w", err)
		}
		noms = append(noms, nom)
	}
	return noms, rows.Err()
}

// IDsDeGroupesParNoms résout des noms de groupes en identifiants.
//
// Rend AUSSI les noms introuvables, plutôt que de les taire.
//
// # Pourquoi les rendre au lieu d'échouer
//
// L'appelant décide. Régler l'affinité à la main sur un groupe mal orthographié
// doit échouer — sinon on croit avoir posé une préférence qui n'existe pas. Mais
// une clé d'enrôlement dont un groupe a été renommé depuis ne doit PAS bloquer
// l'enrôlement : elle porte une affinité, pas un droit. Les deux appelants ont
// besoin de la même résolution et de réponses différentes.
func IDsDeGroupesParNoms(db *sql.DB, noms []string) (ids []int, introuvables []string, err error) {
	if db == nil {
		return nil, nil, fmt.Errorf("connexion base indisponible")
	}

	vus := map[string]bool{}
	for _, brut := range noms {
		nom := strings.TrimSpace(brut)
		if nom == "" || vus[strings.ToLower(nom)] {
			continue
		}
		vus[strings.ToLower(nom)] = true

		var id int
		err := db.QueryRow(`SELECT id_group FROM groups WHERE group_name = ?`, nom).Scan(&id)
		switch {
		case err == sql.ErrNoRows:
			introuvables = append(introuvables, nom)
		case err != nil:
			return nil, nil, fmt.Errorf("résolution du groupe %q : %w", nom, err)
		default:
			ids = append(ids, id)
		}
	}

	sort.Ints(ids)
	sort.Strings(introuvables)
	return ids, introuvables, nil
}
