package dbgpo

import (
	"database/sql"
	"fmt"
	"strings"
	"time"

	"vaultaire/core/database"
)

// Historique des applications de politique.
//
// # Ce que les trois tables de conformité ne savent pas dire
//
// `gpo_compliance` et `gpo_module_report` sont ÉCRASÉES à chaque rapport : elles
// répondent à « où en est-on maintenant », et c'est ce qu'on regarde en
// permanence. Mais devant une machine en `partial`, la question suivante est
// toujours la même — « depuis quand ? » —, et aucune des deux ne peut y
// répondre. La réponse était dans le journal, mêlée à tout le reste.
//
// # Un historique des CHANGEMENTS, pas un journal des cycles
//
// Écrire une ligne par rapport reçu aurait fait, sur mille machines qui
// rapportent toutes les heures, vingt-quatre mille lignes par jour pour dire
// vingt-quatre mille fois « toujours pareil ». La table aurait grossi au
// rythme du parc, pas à celui des événements, et la question « depuis quand »
// aurait demandé de parcourir des milliers de lignes identiques.
//
// Une ligne n'est donc écrite que lorsque quelque chose CHANGE : le statut, ou
// l'empreinte de politique. Une machine saine et stable produit une ligne, à
// son premier rapport, et plus rien. Une machine qui casse produit une ligne le
// jour où elle casse — c'est exactement celle qu'on cherche.
//
// C'est aussi ce qui rend la rétention supportable : la borne protège d'un parc
// qui vacille, pas d'un parc qui tourne.

// MaxModulesEnEchecHistorises borne ce qu'une ligne d'historique retient des
// modules fautifs.
//
// Une politique peut porter des dizaines de modules, et une machine hors
// service les fait tous échouer à la fois. Sans borne, une seule transition
// écrirait un champ de plusieurs kilo-octets — répété à chaque aller-retour
// d'une machine instable. Le détail complet du DERNIER rapport reste dans
// `gpo_module_report` ; ce champ-ci sert à lire l'historique sans le joindre.
const MaxModulesEnEchecHistorises = 20

// historiqueDDL est ajouté au schéma de conformité.
var historiqueDDL = `CREATE TABLE IF NOT EXISTS gpo_apply_history (
	id_apply_history INT AUTO_INCREMENT PRIMARY KEY,
	computeur_id     VARCHAR(255) NOT NULL,
	scope            VARCHAR(16)  NOT NULL,
	target_user      VARCHAR(255) NOT NULL DEFAULT '',
	fingerprint      VARCHAR(128) NOT NULL DEFAULT '',
	status           VARCHAR(16)  NOT NULL DEFAULT '',
	modules_total    INT          NOT NULL DEFAULT 0,
	modules_failed   INT          NOT NULL DEFAULT 0,
	modules_skipped  INT          NOT NULL DEFAULT 0,
	modules_en_echec TEXT         NULL,
	reported_at      DATETIME     NOT NULL,
	-- L'index porte le triplet ET la date : la lecture d'une fiche demande
	-- toujours « les dernières transitions de cette machine », et la purge
	-- demande « tout ce qui est plus vieux que ». Sans la date, la première
	-- trierait en mémoire ce que la base sait trier.
	KEY idx_apply_history (computeur_id, scope, target_user, reported_at),
	KEY idx_apply_history_date (reported_at)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4`

// ApplyHistoryRow est une transition de l'état d'application.
type ApplyHistoryRow struct {
	ComputeurID    string
	Scope          string
	TargetUser     string
	Fingerprint    string
	Status         string
	ModulesTotal   int
	ModulesFailed  int
	ModulesSkipped int
	ModulesEnEchec string
	ReportedAt     time.Time
}

// enregistrerTransition ajoute une ligne d'historique si l'état a changé.
//
// Appelée DANS la transaction de SaveApplyReport : l'historique et l'état
// courant doivent bouger ensemble. Écrite hors transaction, une panne entre les
// deux laisserait un historique qui affirme un changement que l'état courant ne
// montre pas — ou l'inverse, plus trompeur encore.
//
// Rend une erreur : c'est une écriture de la même transaction, et l'avaler
// donnerait un historique à trous que rien ne signalerait.
func enregistrerTransition(tx *sql.Tx, r ApplyHistoryRow) error {
	var dernierStatut, derniereEmpreinte string

	err := tx.QueryRow(`
		SELECT status, fingerprint
		  FROM gpo_apply_history
		 WHERE computeur_id = ? AND scope = ? AND target_user = ?
		 ORDER BY reported_at DESC, id_apply_history DESC
		 LIMIT 1`,
		r.ComputeurID, r.Scope, r.TargetUser).Scan(&dernierStatut, &derniereEmpreinte)

	switch {
	case err == sql.ErrNoRows:
		// Première application connue de cette machine pour cette portée : la
		// ligne est écrite, quelle qu'elle soit. C'est le point de départ dont
		// toutes les durées se comptent.
	case err != nil:
		return fmt.Errorf("gpo: lecture de la dernière transition : %w", err)
	case dernierStatut == r.Status && derniereEmpreinte == r.Fingerprint:
		// Rien n'a changé. C'est le cas de loin le plus fréquent, et ne rien
		// écrire est tout l'intérêt de cette table.
		return nil
	}

	_, err = tx.Exec(`
		INSERT INTO gpo_apply_history
			(computeur_id, scope, target_user, fingerprint, status,
			 modules_total, modules_failed, modules_skipped, modules_en_echec, reported_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		r.ComputeurID, r.Scope, r.TargetUser, r.Fingerprint, r.Status,
		r.ModulesTotal, r.ModulesFailed, r.ModulesSkipped, r.ModulesEnEchec, r.ReportedAt)
	if err != nil {
		return fmt.Errorf("gpo: enregistrement de la transition : %w", err)
	}
	return nil
}

// ResumerModulesFautifs compose le champ retenu par l'historique.
//
// Les clés d'état seulement, pas les détails : le détail d'un échec est une
// phrase, parfois longue, et l'historique répond à « lesquels » et non à
// « pourquoi ». Le pourquoi du dernier rapport est dans `gpo_module_report`.
//
// Exportée pour être éprouvée sans base : la troncature est la partie qui
// décide de la taille de la table.
func ResumerModulesFautifs(modules []ModuleReport) string {
	var cles []string
	for _, m := range modules {
		if m.Result != "failed" && m.Result != "skipped" {
			continue
		}
		cle := strings.TrimSpace(m.StateKey)
		if cle == "" {
			cle = strings.TrimSpace(m.ModuleType)
		}
		if cle == "" {
			continue
		}
		cles = append(cles, cle+" ("+m.Result+")")
	}
	if len(cles) == 0 {
		return ""
	}
	if len(cles) > MaxModulesEnEchecHistorises {
		reste := len(cles) - MaxModulesEnEchecHistorises
		cles = cles[:MaxModulesEnEchecHistorises]
		cles = append(cles, fmt.Sprintf("… et %d de plus", reste))
	}
	return strings.Join(cles, ", ")
}

// HistoriqueApplication rend les transitions d'une machine, la plus récente en
// tête.
//
// `limite` borne la réponse : une fiche affiche les dernières transitions, pas
// l'histoire complète d'une machine que l'on répare depuis six mois.
func HistoriqueApplication(db *sql.DB, computeurID string, limite int) ([]ApplyHistoryRow, error) {
	if db == nil {
		return nil, fmt.Errorf("gpo: connexion base indisponible")
	}
	if err := database.SanitizeIdentifier(computeurID); err != nil {
		return nil, err
	}
	if limite <= 0 {
		limite = 20
	}

	rows, err := db.Query(`
		SELECT computeur_id, scope, target_user, fingerprint, status,
		       modules_total, modules_failed, modules_skipped,
		       COALESCE(modules_en_echec, ''), reported_at
		  FROM gpo_apply_history
		 WHERE computeur_id = ?
		 ORDER BY reported_at DESC, id_apply_history DESC
		 LIMIT ?`, computeurID, limite)
	if err != nil {
		return nil, fmt.Errorf("gpo: lecture de l'historique : %w", err)
	}
	defer closeRows(rows)

	var out []ApplyHistoryRow
	for rows.Next() {
		var r ApplyHistoryRow
		if err := rows.Scan(&r.ComputeurID, &r.Scope, &r.TargetUser, &r.Fingerprint, &r.Status,
			&r.ModulesTotal, &r.ModulesFailed, &r.ModulesSkipped, &r.ModulesEnEchec, &r.ReportedAt); err != nil {
			return out, fmt.Errorf("gpo: lecture d'une transition : %w", err)
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

// LotPurgeHistorique borne une passe de purge.
//
// Même raison que pour les métriques de nœuds : un DELETE non borné sur une
// table qui a grossi pendant des mois tient un verrou le temps qu'il faut, et
// c'est le moment que la base choisit pour ne plus répondre aux
// authentifications.
const LotPurgeHistorique = 10000

// PurgerHistoriqueApplication supprime les transitions plus anciennes que la
// rétention. Rend le nombre de lignes supprimées.
func PurgerHistoriqueApplication(db *sql.DB, retention time.Duration) (int64, error) {
	if db == nil {
		return 0, fmt.Errorf("gpo: connexion base indisponible")
	}
	if retention <= 0 {
		return 0, fmt.Errorf("gpo: rétention d'historique invalide (%s)", retention)
	}

	limite := time.Now().UTC().Add(-retention)
	res, err := db.Exec(
		`DELETE FROM gpo_apply_history WHERE reported_at < ? LIMIT ?`, limite, LotPurgeHistorique)
	if err != nil {
		return 0, fmt.Errorf("gpo: purge de l'historique : %w", err)
	}
	n, _ := res.RowsAffected()
	return n, nil
}
