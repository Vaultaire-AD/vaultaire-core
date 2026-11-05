package dbgpo

import (
	"database/sql"
	"fmt"
	"strings"
	"time"
)

// Les demandes de cycle relayées par la base — TO-DO 172.
//
// # Pourquoi passer par la base
//
// « Demander un cycle » pousse la trame 05_18 par le tunnel de la machine. Ce
// tunnel vit dans la mémoire d'UN core : sur un cluster, une machine connectée
// à un autre core était introuvable, et le bilan la rangeait parmi les « hors
// ligne » alors qu'elle était en ligne, ailleurs.
//
// Les cores partagent la base, et rien d'autre. Une demande qu'un core ne peut
// pas remettre lui-même y est donc écrite ; chaque core relève les demandes en
// attente, et celui qui tient la machine la PREND (une mise à jour qui ne
// réussit qu'une fois) puis pousse la trame. Le demandeur relit la ligne pour
// savoir qui l'a remise. C'est le même partage que la purge (147) et les relais
// pilotés (141) : la base porte la décision, le core qui tient la session agit.
//
// # Ce qui n'est pas fait
//
// Une demande n'est jamais REJOUÉE : passé DureeDeVieDemande, elle n'est plus
// relevée — une machine hors ligne partout fait de toute façon un cycle à sa
// reconnexion (voir rafraichissement.go).

// tableDemandesCycleDDL est créée avec le reste du schéma GPO.
const tableDemandesCycleDDL = `CREATE TABLE IF NOT EXISTS gpo_cycle_demande (
	id_demande BIGINT AUTO_INCREMENT PRIMARY KEY,
	computeur_id VARCHAR(191) NOT NULL,
	motif VARCHAR(255) NOT NULL DEFAULT '',
	demande_par VARCHAR(255) NOT NULL DEFAULT '',
	cree_le DATETIME(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
	prise_par VARCHAR(255) DEFAULT NULL,
	prise_le DATETIME(3) DEFAULT NULL,
	remise BOOLEAN NOT NULL DEFAULT FALSE,
	INDEX idx_gpo_cycle_attente (prise_le, cree_le)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;`

// DureeDeVieDemande : au-delà, une demande n'est plus relevée. Une minute
// couvre une reconnexion en cours sans faire jouer un cycle demandé il y a
// longtemps à une machine qui revient.
const DureeDeVieDemande = time.Minute

// DemandeDeCycle est une ligne en attente.
type DemandeDeCycle struct {
	ID          int64
	ComputeurID string
	Motif       string
	DemandePar  string
}

// IssueDeDemande est ce que le demandeur relit.
type IssueDeDemande struct {
	Prise    bool
	PrisePar string
	Remise   bool
}

// EcrireDemandeDeCycle écrit une demande pour qu'un autre core la remette.
func EcrireDemandeDeCycle(db *sql.DB, computeurID, motif, par string) (int64, error) {
	if db == nil {
		return 0, fmt.Errorf("connexion base indisponible")
	}
	res, err := db.Exec(`INSERT INTO gpo_cycle_demande (computeur_id, motif, demande_par) VALUES (?, ?, ?)`,
		strings.TrimSpace(computeurID), tronquer(motif, 255), tronquer(par, 255))
	if err != nil {
		return 0, fmt.Errorf("demande de cycle pour %s : %w", computeurID, err)
	}
	return res.LastInsertId()
}

// DemandesDeCycleEnAttente rend les demandes ni prises ni périmées.
func DemandesDeCycleEnAttente(db *sql.DB) ([]DemandeDeCycle, error) {
	if db == nil {
		return nil, nil
	}
	rows, err := db.Query(`SELECT id_demande, computeur_id, motif, demande_par FROM gpo_cycle_demande
	                        WHERE prise_le IS NULL AND cree_le > NOW(3) - INTERVAL ? SECOND
	                        ORDER BY id_demande`, int(DureeDeVieDemande/time.Second))
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []DemandeDeCycle
	for rows.Next() {
		var d DemandeDeCycle
		if err := rows.Scan(&d.ID, &d.ComputeurID, &d.Motif, &d.DemandePar); err != nil {
			return nil, err
		}
		out = append(out, d)
	}
	return out, rows.Err()
}

// PrendreDemandeDeCycle réserve la demande à ce core. Rend vrai pour UN seul
// core : la condition « pas encore prise » est dans le WHERE, et la base
// sérialise les deux mises à jour concurrentes.
func PrendreDemandeDeCycle(db *sql.DB, id int64, par string) (bool, error) {
	if db == nil {
		return false, fmt.Errorf("connexion base indisponible")
	}
	res, err := db.Exec(`UPDATE gpo_cycle_demande SET prise_par = ?, prise_le = NOW(3)
	                      WHERE id_demande = ? AND prise_le IS NULL`, tronquer(par, 255), id)
	if err != nil {
		return false, err
	}
	n, err := res.RowsAffected()
	return n == 1, err
}

// NoterRemise dit si la trame est partie, une fois la demande prise.
func NoterRemise(db *sql.DB, id int64, remise bool) error {
	if db == nil {
		return nil
	}
	_, err := db.Exec(`UPDATE gpo_cycle_demande SET remise = ? WHERE id_demande = ?`, remise, id)
	return err
}

// IssuesDesDemandes relit des demandes : qui les a prises, et si la trame est
// partie. Une demande absente du résultat n'a pas été trouvée.
func IssuesDesDemandes(db *sql.DB, ids []int64) (map[int64]IssueDeDemande, error) {
	out := map[int64]IssueDeDemande{}
	if db == nil || len(ids) == 0 {
		return out, nil
	}
	marques := strings.TrimSuffix(strings.Repeat("?,", len(ids)), ",")
	args := make([]any, len(ids))
	for i, id := range ids {
		args[i] = id
	}
	rows, err := db.Query(`SELECT id_demande, COALESCE(prise_par, ''), prise_le IS NOT NULL, remise
	                        FROM gpo_cycle_demande WHERE id_demande IN (`+marques+`)`, args...)
	if err != nil {
		return out, err
	}
	defer rows.Close()
	for rows.Next() {
		var id int64
		var i IssueDeDemande
		if err := rows.Scan(&id, &i.PrisePar, &i.Prise, &i.Remise); err != nil {
			return out, err
		}
		out[id] = i
	}
	return out, rows.Err()
}

// OublierDemandesDeCycle efface les demandes de plus d'une heure : elles ne
// servent plus qu'au diagnostic d'une demande récente.
func OublierDemandesDeCycle(db *sql.DB) (int64, error) {
	if db == nil {
		return 0, nil
	}
	res, err := db.Exec(`DELETE FROM gpo_cycle_demande WHERE cree_le < NOW(3) - INTERVAL 1 HOUR`)
	if err != nil {
		return 0, err
	}
	return res.RowsAffected()
}

func tronquer(s string, n int) string {
	s = strings.TrimSpace(s)
	if r := []rune(s); len(r) > n {
		return string(r[:n])
	}
	return s
}

// AutresCoresEnLigne compte les cores en ligne autres que `moi`. En
// maintenance compris : un core en maintenance tient encore des tunnels tant
// qu'il n'a pas été purgé, et c'est précisément là qu'une machine peut être.
//
// Zéro veut dire « pas de cluster » : la demande n'est alors pas relayée, et
// une machine absente d'ici est hors ligne, tout simplement.
func AutresCoresEnLigne(db *sql.DB, moi string) (int, error) {
	if db == nil {
		return 0, nil
	}
	var n int
	err := db.QueryRow(`SELECT COUNT(*) FROM cluster_nodes
	                     WHERE role = 'core' AND status = 'online' AND hostname <> ?`, moi).Scan(&n)
	return n, err
}
