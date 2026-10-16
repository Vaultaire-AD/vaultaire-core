package dbclients

import (
	"database/sql"
	"errors"
	"fmt"
	"sort"

	"vaultaire/core/clienttype"
	"vaultaire/core/logs"
)

// Lectures et écritures des versions attendues — TO-DO 111.
//
// Les colonnes sont posées par dbschema.EnsureVersionsCibles ; le défaut du
// parc vit dans server_settings et se lit par dbsettings. Ce fichier ne valide
// pas les versions : l'action le fait (parcversion.NormaliserCible) avant
// d'appeler, et la vue relit tout avec la même règle.

// AgentEtCibles est une machine du parc avec ce qui décide de sa version.
type AgentEtCibles struct {
	ComputeurID string
	Hostname    string
	OS          string
	// Declaree : agent_version, telle que la 02_12 l'a remontée.
	Declaree string
	// Derogation : agent_target_version de la machine, brute.
	Derogation string
	// Groupes : nom → agent_target_version du groupe, brute ; vide si le groupe
	// n'a pas de cible. TOUS les groupes de la machine y figurent, pour que la
	// vue puisse dire « dans aucun groupe ».
	Groupes map[string]string
}

// AgentsEtCibles rend les AGENTS du parc — les machines de type
// clienttype.Client, Linux et Windows — avec leurs cibles.
//
// # Pourquoi les services n'y sont pas
//
// Un proxy, un Nexus, l'interface web déclarent aussi une version, et
// VersionsDuParc les compte. Mais le mécanisme de mise à jour (points 115-116)
// ne concerne que l'agent : un service ne demandera jamais d'ordre de mise à
// jour, et lui afficher une version attendue ferait croire le contraire.
func AgentsEtCibles(db *sql.DB) ([]AgentEtCibles, error) {
	if db == nil {
		return nil, fmt.Errorf("base indisponible")
	}

	rows, err := db.Query(`
		SELECT computeur_id, hostname, os, agent_version, agent_target_version
		FROM id_logiciels
		WHERE logiciel_type = ?`, clienttype.Client)
	if err != nil {
		return nil, erreurLecture("machines", err)
	}
	parID := map[string]*AgentEtCibles{}
	var agents []*AgentEtCibles
	for rows.Next() {
		a := &AgentEtCibles{Groupes: map[string]string{}}
		if err := rows.Scan(&a.ComputeurID, &a.Hostname, &a.OS, &a.Declaree, &a.Derogation); err != nil {
			_ = rows.Close()
			return nil, erreurLecture("machines", err)
		}
		parID[a.ComputeurID] = a
		agents = append(agents, a)
	}
	if err := rows.Err(); err != nil {
		_ = rows.Close()
		return nil, erreurLecture("machines", err)
	}
	_ = rows.Close()

	rows, err = db.Query(`
		SELECT l.computeur_id, g.group_name, g.agent_target_version
		FROM logiciel_group lg
		JOIN id_logiciels l ON l.id_logiciel = lg.d_id_logiciel
		JOIN groups g ON g.id_group = lg.d_id_group
		WHERE l.logiciel_type = ?`, clienttype.Client)
	if err != nil {
		return nil, erreurLecture("groupes des machines", err)
	}
	defer func() { _ = rows.Close() }()
	for rows.Next() {
		var id, groupe, cible string
		if err := rows.Scan(&id, &groupe, &cible); err != nil {
			return nil, erreurLecture("groupes des machines", err)
		}
		if a, ok := parID[id]; ok {
			a.Groupes[groupe] = cible
		}
	}
	if err := rows.Err(); err != nil {
		return nil, erreurLecture("groupes des machines", err)
	}

	out := make([]AgentEtCibles, 0, len(agents))
	for _, a := range agents {
		out = append(out, *a)
	}
	return out, nil
}

// CibleGroupe est la cible posée sur un groupe.
type CibleGroupe struct {
	Groupe  string
	Version string
}

// CiblesDesGroupes rend les groupes qui portent une cible, triés par nom.
func CiblesDesGroupes(db *sql.DB) ([]CibleGroupe, error) {
	if db == nil {
		return nil, fmt.Errorf("base indisponible")
	}
	rows, err := db.Query(`SELECT group_name, agent_target_version FROM groups
		WHERE agent_target_version <> '' ORDER BY group_name`)
	if err != nil {
		return nil, erreurLecture("cibles des groupes", err)
	}
	defer func() { _ = rows.Close() }()
	var out []CibleGroupe
	for rows.Next() {
		var c CibleGroupe
		if err := rows.Scan(&c.Groupe, &c.Version); err != nil {
			return nil, erreurLecture("cibles des groupes", err)
		}
		out = append(out, c)
	}
	if err := rows.Err(); err != nil {
		return nil, erreurLecture("cibles des groupes", err)
	}
	sort.SliceStable(out, func(i, j int) bool { return out[i].Groupe < out[j].Groupe })
	return out, nil
}

// ErrIntrouvable : le groupe ou la machine nommés n'existent pas.
var ErrIntrouvable = errors.New("introuvable")

// DefinirCibleGroupe pose (ou efface, version vide) la cible d'un groupe.
//
// `updated_at = updated_at` : la cible n'est pas visible d'un client LDAP, et
// laisser la base bumper la date ferait réimporter le groupe par Keycloak —
// voir dbschema.EnsureVersionsCibles.
//
// L'existence est vérifiée à part : MariaDB rend, pour un UPDATE, le nombre de
// lignes CHANGÉES et non TROUVÉES. Reposer la même cible rendrait 0, et ce 0
// se lirait comme un groupe absent.
func DefinirCibleGroupe(db *sql.DB, groupe, version string) error {
	if db == nil {
		return fmt.Errorf("base indisponible")
	}
	var n int
	if err := db.QueryRow(`SELECT COUNT(*) FROM groups WHERE group_name = ?`, groupe).Scan(&n); err != nil {
		return erreurLecture("groupe "+groupe, err)
	}
	if n == 0 {
		return fmt.Errorf("groupe %q %w", groupe, ErrIntrouvable)
	}
	if _, err := db.Exec(`UPDATE groups SET agent_target_version = ?, updated_at = updated_at
		WHERE group_name = ?`, version, groupe); err != nil {
		logs.Write_LogCode("ERROR", logs.CodeDBQuery,
			"agent-update: cible du groupe "+groupe+" non écrite : "+err.Error())
		return fmt.Errorf("écriture de la cible du groupe %s : %w", groupe, err)
	}
	return nil
}

// DefinirDerogation pose (ou efface, version vide) la dérogation d'une machine.
//
// Refusée pour une machine qui n'est pas un agent : un proxy ou un Nexus ne
// demandera jamais d'ordre de mise à jour, et accepter la dérogation laisserait
// croire qu'elle sert à quelque chose.
func DefinirDerogation(db *sql.DB, computeurID, version string) error {
	if db == nil {
		return fmt.Errorf("base indisponible")
	}
	var typ string
	err := db.QueryRow(`SELECT logiciel_type FROM id_logiciels WHERE computeur_id = ?`,
		computeurID).Scan(&typ)
	switch {
	case err == sql.ErrNoRows:
		return fmt.Errorf("machine %q %w", computeurID, ErrIntrouvable)
	case err != nil:
		return erreurLecture("machine "+computeurID, err)
	}
	if typ != clienttype.Client {
		return fmt.Errorf("%s est un client de type %s : seuls les agents (%s) "+
			"suivent une version attendue", computeurID, typ, clienttype.Client)
	}
	if _, err := db.Exec(`UPDATE id_logiciels SET agent_target_version = ?
		WHERE computeur_id = ?`, version, computeurID); err != nil {
		logs.Write_LogCode("ERROR", logs.CodeDBQuery,
			"agent-update: dérogation de "+computeurID+" non écrite : "+err.Error())
		return fmt.Errorf("écriture de la dérogation de %s : %w", computeurID, err)
	}
	return nil
}

func erreurLecture(quoi string, err error) error {
	logs.Write_LogCode("ERROR", logs.CodeDBQuery,
		"agent-update: lecture échouée ("+quoi+") : "+err.Error())
	return fmt.Errorf("lecture impossible (%s) : %w", quoi, err)
}

// GroupeExiste dit si un groupe porte ce nom — pour « vlt agent -g », qui doit
// distinguer un groupe sans agent d'un nom mal tapé.
func GroupeExiste(db *sql.DB, groupe string) (bool, error) {
	if db == nil {
		return false, fmt.Errorf("base indisponible")
	}
	var n int
	if err := db.QueryRow(`SELECT COUNT(*) FROM groups WHERE group_name = ?`, groupe).Scan(&n); err != nil {
		return false, erreurLecture("groupe "+groupe, err)
	}
	return n > 0, nil
}
