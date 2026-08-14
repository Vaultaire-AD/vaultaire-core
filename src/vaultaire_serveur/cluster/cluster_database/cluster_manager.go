package clusterdatabase

import (
	"database/sql"
	"errors"
	"fmt"
	"strings"
	"time"

	clusterstorage "vaultaire/cluster/cluster_storage"
)

// PrefixeProprietaireLocal ouvre les propriétaires qui ne viennent PAS du réseau.
//
// Réservé : ProprietaireDepuisSession refuse un identifiant de client qui
// commencerait par lui. Sans cette réserve, un client dont l'identifiant
// ressemblerait à « @core:… » revendiquerait la ligne d'un core.
const PrefixeProprietaireLocal = "@"

// ProprietaireCoreLocal rend le propriétaire de la ligne d'un core.
//
// Par HOSTNAME et non une valeur unique pour tous les cores : sur un cluster à
// plusieurs cores, un propriétaire commun laisserait chacun écrire la ligne des
// autres — c'est-à-dire le défaut corrigé, sous une autre forme.
func ProprietaireCoreLocal(hostname string) string {
	return PrefixeProprietaireLocal + "core:" + strings.TrimSpace(hostname)
}

// ErrProprietaireReserve refuse un identifiant de session dans l'espace local.
var ErrProprietaireReserve = errors.New(
	"identifiant de client réservé : le préfixe « " + PrefixeProprietaireLocal +
		" » désigne un nœud déclaré localement, pas par le réseau")

// ProprietaireDepuisSession rend le propriétaire d'un nœud enregistré par le réseau.
//
// C'est l'identifiant machine figé à la poignée de main 01_01, jamais celui
// annoncé dans le contenu d'une trame.
func ProprietaireDepuisSession(clientSoftwareID string) (string, error) {
	id := strings.TrimSpace(clientSoftwareID)
	if id == "" {
		return "", errors.New("session non liée à une machine : enregistrement refusé")
	}
	if strings.HasPrefix(id, PrefixeProprietaireLocal) {
		return "", ErrProprietaireReserve
	}
	return id, nil
}

// ErrNoeudAppartientAUnAutre refuse d'écrire la ligne de quelqu'un d'autre.
var ErrNoeudAppartientAUnAutre = errors.New(
	"ce hostname appartient déjà à un autre nœud du cluster")

// RegisterNode enregistre ou met à jour la ligne du nœud DEMANDEUR.
//
// # La règle, et le défaut qu'elle ferme
//
// Un nœud ne peut modifier QUE sa propre ligne, ou la créer si elle n'existe pas
// encore. La ligne lui appartient par `owner_client_id`.
//
// La version antérieure ne connaissait pas cette notion. Elle tentait d'abord un
// `UPDATE … WHERE ip_address = ?`, puis un `INSERT … ON DUPLICATE KEY UPDATE` sur
// le hostname — deux chemins qui écrivaient la ligne désignée par le CONTENU de
// la trame 04_01, sans lien avec la session authentifiée.
//
// Un proxy enrôlé pouvait donc envoyer le hostname d'un core et écraser sa
// ligne : adresse, port, et surtout EMPREINTE. La liste servie aux agents
// annonçait ensuite l'empreinte de l'attaquant sous le nom du core ; les agents
// l'apprenaient, la plaçaient devant leurs serveurs statiques, et s'y
// connectaient pour s'authentifier.
//
// # Pourquoi un SELECT puis un UPDATE, et non un UPDATE seul
//
// MySQL rend `RowsAffected() == 0` quand l'UPDATE ne CHANGE rien — ce qui est le
// cas ordinaire d'un nœud qui se réenregistre sans avoir bougé. S'en servir pour
// décider « la ligne n'existe pas, il faut l'insérer » ferait échouer chaque
// réenregistrement sur le conflit de hostname, et seulement celui-là : le défaut
// n'apparaîtrait qu'au deuxième démarrage d'un nœud stable.
//
// # Ce que l'enregistrement NE touche pas
//
// `priorite` et `expose_aux_agents` sont absents des requêtes, et délibérément :
// ce sont des décisions d'EXPLOITATION, prises par un administrateur, pas des
// faits déclarés par le nœud.
//
// Les inclure ferait qu'un proxy sorti de la rotation pour maintenance y
// rentrerait tout seul à son prochain redémarrage — c'est-à-dire au moment
// précis où quelqu'un le manipule. Le port, lui, est bien un fait : le nœud est
// seul à savoir sur quoi il écoute.
func RegisterNode(db *sql.DB, n clusterstorage.Node) error {
	proprietaire := strings.TrimSpace(n.Proprietaire)
	if proprietaire == "" {
		// FAIL-CLOSED. Une ligne sans propriétaire ne pourrait plus jamais être
		// mise à jour par personne, et — la colonne étant UNIQUE — la deuxième
		// ferait échouer l'insertion sur un conflit incompréhensible.
		return errors.New("enregistrement sans propriétaire : refusé")
	}

	var idNode int
	err := db.QueryRow(
		`SELECT id_node FROM cluster_nodes WHERE owner_client_id = ?`, proprietaire,
	).Scan(&idNode)

	switch {
	case err == nil:
		// La ligne du demandeur existe : on la met à jour, PAR SON ID.
		//
		// Le hostname peut avoir changé — un conteneur qui redémarre en prend un
		// neuf. C'était le motif de l'UPDATE par IP de la version antérieure ; il
		// est satisfait ici sans laisser personne désigner la ligne d'un autre.
		_, err := db.Exec(
			`UPDATE cluster_nodes
			    SET hostname=?, fqdn=?, ip_address=?, role=?, status='online',
			        version_code=?, capabilities=?, ducky_port=?,
			        key_fingerprint=?, sdk_version=?, last_heartbeat=NOW()
			  WHERE id_node=?`,
			n.Hostname, n.FQDN, n.IPAddress, n.Role, n.VersionCode, n.Capabilities,
			n.Port, n.Empreinte, n.VersionSDK, idNode)
		if err != nil {
			// Le hostname est UNIQUE : l'erreur signifie qu'un autre nœud le
			// porte déjà. Le dire ainsi évite de chercher du côté de la base.
			return fmt.Errorf("mise à jour du nœud %s : %w", n.Hostname, err)
		}
		return nil

	case errors.Is(err, sql.ErrNoRows):
		// Première déclaration. On refuse d'écraser un hostname pris par un
		// AUTRE propriétaire — c'est exactement le geste de l'usurpation.
		var proprietaireExistant string
		err := db.QueryRow(
			`SELECT owner_client_id FROM cluster_nodes WHERE hostname = ? OR fqdn = ?`,
			n.Hostname, n.FQDN,
		).Scan(&proprietaireExistant)
		switch {
		case err == nil:
			return fmt.Errorf("%w : %q est à %q, le demandeur est %q",
				ErrNoeudAppartientAUnAutre, n.Hostname, proprietaireExistant, proprietaire)
		case !errors.Is(err, sql.ErrNoRows):
			return fmt.Errorf("vérification du hostname %s : %w", n.Hostname, err)
		}

		// expose_aux_agents est absent des colonnes : le DEFAULT TRUE du schéma
		// s'applique. Un nœud neuf est joignable sans que personne le déclare.
		_, err = db.Exec(
			`INSERT INTO cluster_nodes
			   (hostname, fqdn, ip_address, role, status, version_code, capabilities,
			    ducky_port, key_fingerprint, sdk_version, owner_client_id, last_heartbeat)
			 VALUES (?, ?, ?, ?, 'online', ?, ?, ?, ?, ?, ?, NOW())`,
			n.Hostname, n.FQDN, n.IPAddress, n.Role, n.VersionCode, n.Capabilities,
			n.Port, n.Empreinte, n.VersionSDK, proprietaire)
		if err != nil {
			return fmt.Errorf("création du nœud %s : %w", n.Hostname, err)
		}
		return nil

	default:
		return fmt.Errorf("recherche du nœud de %s : %w", proprietaire, err)
	}
}

// UpdateHeartbeat rafraîchit la ligne du nœud DEMANDEUR.
//
// Par propriétaire, et non par hostname. Le hostname venait du contenu de la
// trame 04_07 : n'importe quel nœud pouvait donc maintenir n'importe quelle
// ligne en ligne — y compris celle d'un core éteint, qui restait annoncé aux
// agents et absorbait leurs tentatives de connexion.
//
// Rend le nombre de lignes touchées. Zéro n'est PAS une erreur de base : c'est
// un nœud qui bat sans s'être enregistré, et l'appelant le lui dit pour qu'il
// rejoue son 04_01 au lieu de battre dans le vide.
func UpdateHeartbeat(db *sql.DB, proprietaire string) (int64, error) {
	if strings.TrimSpace(proprietaire) == "" {
		return 0, errors.New("battement sans propriétaire : refusé")
	}
	res, err := db.Exec(
		`UPDATE cluster_nodes SET last_heartbeat=NOW(), status='online'
		  WHERE owner_client_id = ?`, proprietaire)
	if err != nil {
		return 0, err
	}
	n, _ := res.RowsAffected()
	return n, nil
}

// HostnameDuProprietaire rend le hostname de la ligne d'un nœud.
//
// Sert aux écritures qui portent un hostname sans le décider — les métriques,
// par exemple, qui sont indexées par nom lisible et non par identifiant machine.
func HostnameDuProprietaire(db *sql.DB, proprietaire string) (string, error) {
	var hostname string
	err := db.QueryRow(
		`SELECT hostname FROM cluster_nodes WHERE owner_client_id = ?`, proprietaire,
	).Scan(&hostname)
	return hostname, err
}

func GetActiveNodesByRole(db *sql.DB, role string) ([]clusterstorage.Node, error) {
	rows, err := db.Query(`SELECT id_node, hostname, fqdn, ip_address, role, status, version_code, capabilities, last_heartbeat, ducky_port, priorite, expose_aux_agents, key_fingerprint, sdk_version 
                            FROM cluster_nodes 
                            WHERE role=? AND status='online'`, role)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var nodes []clusterstorage.Node
	for rows.Next() {
		var n clusterstorage.Node
		var lastHeartbeat time.Time
		if err := rows.Scan(&n.ID, &n.Hostname, &n.FQDN, &n.IPAddress, &n.Role, &n.Status, &n.VersionCode,
			&n.Capabilities, &lastHeartbeat, &n.Port, &n.Priorite, &n.ExposeAuxAgents,
			&n.Empreinte, &n.VersionSDK); err != nil {
			return nil, err
		}
		n.LastHeartbeat = lastHeartbeat
		nodes = append(nodes, n)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return nodes, nil
}

// GetAllNodes retourne tous les nœuds, quelque soit leur état.
func GetAllNodes(db *sql.DB) ([]clusterstorage.Node, error) {
	rows, err := db.Query(`SELECT id_node, hostname, fqdn, ip_address, role, status, version_code, capabilities, last_heartbeat, ducky_port, priorite, expose_aux_agents, key_fingerprint, sdk_version 
                            FROM cluster_nodes 
                            ORDER BY role, hostname`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var nodes []clusterstorage.Node
	for rows.Next() {
		var n clusterstorage.Node
		var lastHeartbeat time.Time
		if err := rows.Scan(&n.ID, &n.Hostname, &n.FQDN, &n.IPAddress, &n.Role, &n.Status, &n.VersionCode,
			&n.Capabilities, &lastHeartbeat, &n.Port, &n.Priorite, &n.ExposeAuxAgents,
			&n.Empreinte, &n.VersionSDK); err != nil {
			return nil, err
		}
		n.LastHeartbeat = lastHeartbeat
		nodes = append(nodes, n)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return nodes, nil
}

// CleanupStaleNodes applique la politique :
// - >1 minute sans heartbeat => status='offline'
// - >5 minutes sans heartbeat => suppression.
func CleanupStaleNodes(db *sql.DB) error {
	// Mettre hors ligne les nœuds inactifs depuis plus d'une minute
	if _, err := db.Exec(`UPDATE cluster_nodes 
                           SET status='offline' 
                           WHERE status='online' AND last_heartbeat < DATE_SUB(NOW(), INTERVAL 1 MINUTE)`); err != nil {
		return err
	}
	// Supprimer les nœuds inactifs depuis plus de cinq minutes
	if _, err := db.Exec(`DELETE FROM cluster_nodes 
                           WHERE last_heartbeat < DATE_SUB(NOW(), INTERVAL 5 MINUTE)`); err != nil {
		return err
	}
	return nil
}
