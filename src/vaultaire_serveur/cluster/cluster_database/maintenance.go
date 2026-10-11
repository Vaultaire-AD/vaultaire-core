package clusterdatabase

import (
	"database/sql"
	"errors"
	"fmt"
	"strings"
	"time"

	clusterstorage "vaultaire/cluster/cluster_storage"
	"vaultaire/core/logs"
)

// Maintenance, purge et oubli d'un nœud — TO-DO 146 et 147.
//
// # Trois gestes, trois portées
//
//   - la MAINTENANCE retire un nœud de toutes les listes servies (04_04,
//     04_16) sans le retirer du cluster : il bat toujours, se voit, et revient
//     tel qu'il était quand on la lève ;
//   - la PURGE vide un core de ses sessions. Elle ne peut être faite que par
//     le core visé — les sessions vivent dans sa mémoire —, donc elle est
//     DEMANDÉE ici et exécutée par lui, à son battement ;
//   - l'OUBLI retire la ligne d'un nœud parti, sans attendre le délai de
//     purge du cluster.

// ErrNoeudInconnu est celle d'exposition_noeud.go : un seul « inconnu » pour
// tous les gestes sur un nœud.

// --- lecture ---------------------------------------------------------------------

// LireEtatsMaintenance rend l'état de maintenance de chaque nœud, par nom.
func LireEtatsMaintenance(db *sql.DB) (map[string]clusterstorage.EtatMaintenance, error) {
	if db == nil {
		return nil, fmt.Errorf("connexion base indisponible")
	}
	rows, err := db.Query(`SELECT hostname, maintenance, maintenance_par, maintenance_le,
	                              purge_demandee_le, purge_par, purge_etalement_s,
	                              purge_terminee_le, purge_fermees
	                         FROM cluster_nodes`)
	if err != nil {
		return nil, fmt.Errorf("lecture des maintenances : %w", err)
	}
	defer func() { _ = rows.Close() }()

	out := map[string]clusterstorage.EtatMaintenance{}
	for rows.Next() {
		var hote string
		var e clusterstorage.EtatMaintenance
		var depuis, demandee, terminee sql.NullTime
		if err := rows.Scan(&hote, &e.Active, &e.Par, &depuis, &demandee, &e.PurgePar,
			&e.Etalement, &terminee, &e.Fermees); err != nil {
			return nil, fmt.Errorf("lecture des maintenances : %w", err)
		}
		e.Depuis, e.PurgeDemandee, e.PurgeTerminee = depuis.Time, demandee.Time, terminee.Time
		out[hote] = e
	}
	return out, rows.Err()
}

// GarnirMaintenance pose l'état de maintenance sur les nœuds d'une liste.
//
// Même tolérance que les mesures : un état illisible laisse le champ nil et
// la vue s'affiche. Mais il est JOURNALISÉ — une maintenance qu'on ne voit
// pas est un nœud qu'on croit en service.
func GarnirMaintenance(db *sql.DB, noeuds []clusterstorage.Node) {
	if len(noeuds) == 0 {
		return
	}
	etats, err := LireEtatsMaintenance(db)
	if err != nil {
		logs.Write_Log("WARNING", "cluster: états de maintenance illisibles : "+err.Error())
		return
	}
	for i := range noeuds {
		if e, ok := etats[noeuds[i].Hostname]; ok {
			e := e
			noeuds[i].Maintenance = &e
		}
	}
}

// --- maintenance -----------------------------------------------------------------

// PoserMaintenance met un nœud en maintenance, ou l'en sort.
//
// Ne touche NI à expose_aux_agents NI à la priorité : la maintenance est une
// couche au-dessus, et la lever rend le nœud tel qu'il était — y compris hors
// rotation, s'il l'était avant.
func PoserMaintenance(db *sql.DB, hostname string, active bool, par string) error {
	if db == nil {
		return fmt.Errorf("connexion base indisponible")
	}
	var res sql.Result
	var err error
	if active {
		res, err = db.Exec(`UPDATE cluster_nodes
		                       SET maintenance = TRUE, maintenance_par = ?, maintenance_le = NOW()
		                     WHERE hostname = ?`, par, hostname)
	} else {
		res, err = db.Exec(`UPDATE cluster_nodes
		                       SET maintenance = FALSE, maintenance_par = '', maintenance_le = NULL
		                     WHERE hostname = ?`, hostname)
	}
	if err != nil {
		return fmt.Errorf("maintenance de %s : %w", hostname, err)
	}
	if n, _ := res.RowsAffected(); n == 0 {
		// MySQL compte les lignes MODIFIÉES : une maintenance déjà dans l'état
		// demandé rend zéro. On distingue en relisant.
		if _, err := NoeudParHostname(db, hostname); err != nil {
			return ErrNoeudInconnu
		}
	}
	return nil
}

// CoresDisponiblesHors compte les cores qui restent servis si `hostname`
// sort : en ligne, en rotation, pas en maintenance.
//
// C'est la question du garde-fou : mettre en maintenance le DERNIER, c'est
// couper le parc.
func CoresDisponiblesHors(db *sql.DB, hostname string) (int, error) {
	if db == nil {
		return 0, fmt.Errorf("connexion base indisponible")
	}
	var n int
	err := db.QueryRow(`SELECT COUNT(*) FROM cluster_nodes
	                     WHERE role = 'core' AND status = 'online'
	                       AND expose_aux_agents = TRUE AND maintenance = FALSE
	                       AND hostname <> ?`, hostname).Scan(&n)
	return n, err
}

// --- purge -----------------------------------------------------------------------

// ErrPurgeHorsMaintenance : une purge hors maintenance ferait revenir les
// agents sur le nœud même qu'on vide — il est encore dans leur liste.
var ErrPurgeHorsMaintenance = errors.New("purge refusée : le nœud n'est pas en maintenance")

// ErrPurgePasUnCore : seul un core tient des sessions qu'il peut fermer.
var ErrPurgePasUnCore = errors.New("purge refusée : seul un core se purge de ses sessions")

// DemanderPurge écrit la demande ; le core visé l'exécutera à son battement.
//
// Les deux conditions sont dans le WHERE, pas seulement vérifiées avant : une
// maintenance levée entre la vérification et l'écriture ne doit pas laisser
// passer une purge.
func DemanderPurge(db *sql.DB, hostname, par string, etalement int) error {
	if db == nil {
		return fmt.Errorf("connexion base indisponible")
	}
	res, err := db.Exec(`UPDATE cluster_nodes
	                        SET purge_demandee_le = NOW(), purge_par = ?, purge_etalement_s = ?,
	                            purge_terminee_le = NULL, purge_fermees = 0
	                      WHERE hostname = ? AND maintenance = TRUE AND role = 'core'`,
		par, etalement, hostname)
	if err != nil {
		return fmt.Errorf("demande de purge de %s : %w", hostname, err)
	}
	if n, _ := res.RowsAffected(); n > 0 {
		return nil
	}
	n, err := NoeudParHostname(db, hostname)
	if err != nil {
		return ErrNoeudInconnu
	}
	if n.Role != "core" {
		return ErrPurgePasUnCore
	}
	return ErrPurgeHorsMaintenance
}

// DemandeDePurge est ce qu'un core lit de sa propre ligne.
type DemandeDePurge struct {
	Demandee  time.Time
	Etalement time.Duration
}

// PurgeAFaire dit au core `proprietaire` s'il a une purge à exécuter.
//
// Par le propriétaire « @core:<hostname> », comme le battement : un core ne
// lit que SA ligne.
func PurgeAFaire(db *sql.DB, proprietaire string) (DemandeDePurge, bool, error) {
	if db == nil {
		return DemandeDePurge{}, false, nil
	}
	var demandee, terminee sql.NullTime
	var etalement int
	var maintenance bool
	err := db.QueryRow(`SELECT purge_demandee_le, purge_terminee_le, purge_etalement_s, maintenance
	                      FROM cluster_nodes WHERE owner_client_id = ?`, proprietaire).
		Scan(&demandee, &terminee, &etalement, &maintenance)
	if errors.Is(err, sql.ErrNoRows) {
		return DemandeDePurge{}, false, nil
	}
	if err != nil {
		return DemandeDePurge{}, false, err
	}
	e := clusterstorage.EtatMaintenance{PurgeDemandee: demandee.Time, PurgeTerminee: terminee.Time}
	// Une maintenance levée pendant la purge l'interrompt : les agents
	// reviendraient de toute façon, le nœud étant de nouveau dans les listes.
	if !maintenance || !e.PurgeEnCours() {
		return DemandeDePurge{}, false, nil
	}
	return DemandeDePurge{Demandee: demandee.Time, Etalement: time.Duration(etalement) * time.Second}, true, nil
}

// TerminerPurge écrit la fin d'une purge et le nombre de sessions fermées.
//
// Seulement si la demande est toujours CELLE-LÀ : une seconde purge demandée
// pendant la première ne doit pas être marquée faite par la fin de l'autre.
func TerminerPurge(db *sql.DB, proprietaire string, demandee time.Time, fermees int) error {
	if db == nil {
		return nil
	}
	_, err := db.Exec(`UPDATE cluster_nodes
	                      SET purge_terminee_le = NOW(), purge_fermees = ?
	                    WHERE owner_client_id = ? AND purge_demandee_le = ?`,
		fermees, proprietaire, demandee)
	return err
}

// --- oubli (TO-DO 146) -------------------------------------------------------------

// BilanOubli dit ce qui est parti avec la ligne : c'est ce qu'il faudrait
// refaire si le nœud revient.
type BilanOubli struct {
	Hostname         string
	Role             string
	DernierBattement time.Time
	AdresseDeclaree  string
	PortPublic       int
	Priorite         int
	HorsRotation     bool
	Maintenance      bool
	Groupes          []string
	Relais           []string
}

// ErrNoeudVivant : le nœud bat encore, ou vient de battre.
var ErrNoeudVivant = errors.New("nœud en ligne")

// refusDOubli tranche, sans base : le nœud doit être hors ligne ET silencieux
// depuis plus que `silence`.
//
// Les deux, et pas l'un ou l'autre. « offline » est posé par la boucle de
// nettoyage d'UN core ; un nœud peut l'être depuis une seconde, juste avant
// son battement de retour. Et un battement ancien sur une ligne encore
// « online » dit seulement que la boucle n'est pas encore passée.
func refusDOubli(statut string, silencieux bool, dernier time.Time, silence time.Duration) error {
	if strings.EqualFold(statut, "online") || !silencieux {
		return fmt.Errorf("%w : dernier battement le %s (état %s). Seul un nœud hors ligne "+
			"et silencieux depuis plus de %s s'oublie — un nœud vivant se réinscrirait au "+
			"battement suivant", ErrNoeudVivant, dernier.Format("2006-01-02 15:04:05"), statut,
			silence.Round(time.Second))
	}
	return nil
}

// OublierNoeud retire un nœud hors ligne, ses affinités et ce que le core lui
// demandait d'exposer.
//
// # Les relais partent, et c'est la différence avec l'oubli automatique
//
// cluster_relays est indexée par le PROPRIÉTAIRE et non par le nœud, pour que
// l'oubli automatique — un proxy absent un jour — ne lui fasse pas perdre sa
// configuration à son retour. Ici l'oubli est une DÉCISION : le proxy est
// démonté. Garder ses relais laisserait des lignes sans effet et sans fin. Le
// bilan les nomme, pour qui se serait trompé de nœud.
//
// # Une transaction, et la condition rejouée dans le DELETE
//
// Un nœud qui revient entre la lecture et la suppression ne doit pas être
// effacé : le DELETE porte les mêmes conditions que la vérification.
func OublierNoeud(db *sql.DB, hostname string, silence time.Duration) (BilanOubli, error) {
	if db == nil {
		return BilanOubli{}, fmt.Errorf("connexion base indisponible")
	}
	secondes := int64(silence / time.Second)

	tx, err := db.Begin()
	if err != nil {
		return BilanOubli{}, err
	}
	defer func() { _ = tx.Rollback() }()

	var b BilanOubli
	var id int
	var proprietaire, statut string
	var silencieux bool
	err = tx.QueryRow(`SELECT id_node, hostname, role, status, last_heartbeat, owner_client_id,
	                          adresse_publique, port_public, priorite, NOT expose_aux_agents,
	                          maintenance,
	                          last_heartbeat < DATE_SUB(NOW(), INTERVAL ? SECOND)
	                     FROM cluster_nodes WHERE hostname = ? FOR UPDATE`, secondes, hostname).
		Scan(&id, &b.Hostname, &b.Role, &statut, &b.DernierBattement, &proprietaire,
			&b.AdresseDeclaree, &b.PortPublic, &b.Priorite, &b.HorsRotation, &b.Maintenance, &silencieux)
	if errors.Is(err, sql.ErrNoRows) {
		return BilanOubli{}, ErrNoeudInconnu
	}
	if err != nil {
		return BilanOubli{}, fmt.Errorf("lecture du nœud %s : %w", hostname, err)
	}
	if err := refusDOubli(statut, silencieux, b.DernierBattement, silence); err != nil {
		return BilanOubli{}, err
	}

	// Ce qui part avec la ligne, lu AVANT de l'effacer.
	if rows, err := tx.Query(`SELECT g.group_name FROM cluster_node_group ng
	                            JOIN groups g ON g.id_group = ng.d_id_group
	                           WHERE ng.d_id_node = ? ORDER BY g.group_name`, id); err == nil {
		for rows.Next() {
			var g string
			if rows.Scan(&g) == nil {
				b.Groupes = append(b.Groupes, g)
			}
		}
		_ = rows.Close()
	}
	if rows, err := tx.Query(`SELECT nom FROM cluster_relays WHERE owner_client_id = ?
	                           ORDER BY position, nom`, proprietaire); err == nil {
		for rows.Next() {
			var r string
			if rows.Scan(&r) == nil {
				b.Relais = append(b.Relais, r)
			}
		}
		_ = rows.Close()
	}

	res, err := tx.Exec(`DELETE FROM cluster_nodes
	                      WHERE id_node = ? AND status <> 'online'
	                        AND last_heartbeat < DATE_SUB(NOW(), INTERVAL ? SECOND)`, id, secondes)
	if err != nil {
		return BilanOubli{}, fmt.Errorf("oubli du nœud %s : %w", hostname, err)
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return BilanOubli{}, fmt.Errorf("%w : il a battu pendant l'oubli", ErrNoeudVivant)
	}
	// Les relais : une ligne vide de propriétaire n'est jamais effacée — elle
	// désignerait toutes les lignes sans propriétaire.
	if strings.TrimSpace(proprietaire) != "" {
		if _, err := tx.Exec(`DELETE FROM cluster_relays WHERE owner_client_id = ?`, proprietaire); err != nil {
			return BilanOubli{}, fmt.Errorf("relais du nœud %s : %w", hostname, err)
		}
		if _, err := tx.Exec(`DELETE FROM cluster_relay_state WHERE owner_client_id = ?`, proprietaire); err != nil {
			return BilanOubli{}, fmt.Errorf("état des relais du nœud %s : %w", hostname, err)
		}
	}
	if err := tx.Commit(); err != nil {
		return BilanOubli{}, err
	}
	return b, nil
}
