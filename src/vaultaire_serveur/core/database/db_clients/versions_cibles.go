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
	// DerogationRetrograder : agent_target_downgrade — la dérogation autorise
	// une rétrogradation (TO-DO 204).
	DerogationRetrograder bool
	// Groupes : nom → agent_target_version du groupe, brute ; vide si le groupe
	// n'a pas de cible. TOUS les groupes de la machine y figurent, pour que la
	// vue puisse dire « dans aucun groupe ».
	Groupes map[string]string
	// CompteRendu : le dernier 09_04 de la machine (TO-DO 115) ; vide si
	// elle n'a jamais rendu compte.
	CompteRendu CompteRendu
	// Configuration : le dernier 09_07 (TO-DO 117) ; vide sans compte rendu.
	Configuration Configuration
}

// Configuration est le dernier mot d'une machine sur sa configuration système.
type Configuration struct {
	Etat  string // voir core/miseajour : conforme, reconciliee, ecart, desactivee, non_pris_en_charge
	Motif string
	Le    sql.NullTime
}

// CompteRendu est le dernier mot d'une machine sur sa mise à jour.
type CompteRendu struct {
	Version  string // la version tentée
	Resultat string // voir core/miseajour : installe, echec, refuse, non_pris_en_charge
	Motif    string
	Le       sql.NullTime
}

// Vide dit si la machine n'a jamais rendu compte.
func (c CompteRendu) Vide() bool { return c.Resultat == "" }

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
	return lireAgents(db, "")
}

// AgentEtCiblesDe rend UNE machine — pour répondre à sa 09_01 sans lire tout
// le parc. ErrIntrouvable si elle n'existe pas ou n'est pas un agent.
func AgentEtCiblesDe(db *sql.DB, computeurID string) (AgentEtCibles, error) {
	l, err := lireAgents(db, computeurID)
	if err != nil {
		return AgentEtCibles{}, err
	}
	if len(l) == 0 {
		return AgentEtCibles{}, fmt.Errorf("agent %q %w", computeurID, ErrIntrouvable)
	}
	return l[0], nil
}

func lireAgents(db *sql.DB, seulement string) ([]AgentEtCibles, error) {
	if db == nil {
		return nil, fmt.Errorf("base indisponible")
	}
	filtre, args := "", []any{clienttype.Client}
	if seulement != "" {
		filtre, args = " AND l.computeur_id = ?", append(args, seulement)
	}

	rows, err := db.Query(`
		SELECT computeur_id, hostname, os, agent_version, agent_target_version, agent_target_downgrade,
		       agent_update_version, agent_update_result, agent_update_reason, agent_update_at,
		       agent_conf_state, agent_conf_reason, agent_conf_at
		FROM id_logiciels l
		WHERE logiciel_type = ?`+filtre, args...)
	if err != nil {
		return nil, erreurLecture("machines", err)
	}
	parID := map[string]*AgentEtCibles{}
	var agents []*AgentEtCibles
	for rows.Next() {
		a := &AgentEtCibles{Groupes: map[string]string{}}
		if err := rows.Scan(&a.ComputeurID, &a.Hostname, &a.OS, &a.Declaree, &a.Derogation, &a.DerogationRetrograder,
			&a.CompteRendu.Version, &a.CompteRendu.Resultat, &a.CompteRendu.Motif, &a.CompteRendu.Le,
			&a.Configuration.Etat, &a.Configuration.Motif, &a.Configuration.Le); err != nil {
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
		WHERE l.logiciel_type = ?`+filtre, args...)
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
//
// retrograder (TO-DO 204) : la dérogation autorise de ramener la machine à
// une version INFÉRIEURE à la sienne, sans autre geste, tant qu'elle n'a pas
// rendu « installe » pour cette version. Toujours faux sans version.
func DefinirDerogation(db *sql.DB, computeurID, version string, retrograder bool) error {
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
	if version == "" {
		retrograder = false
	}
	if _, err := db.Exec(`UPDATE id_logiciels SET agent_target_version = ?, agent_target_downgrade = ?
		WHERE computeur_id = ?`, version, retrograder, computeurID); err != nil {
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

// EnregistrerCompteRendu range le dernier 09_04 d'une machine. Le motif est
// tronqué : il vient du réseau, et la colonne est bornée.
func EnregistrerCompteRendu(db *sql.DB, computeurID, version, resultat, motif string) error {
	if db == nil {
		return fmt.Errorf("base indisponible")
	}
	if r := []rune(motif); len(r) > 250 {
		motif = string(r[:250])
	}
	if len(version) > 64 {
		version = version[:64]
	}
	// Le drapeau de rétrogradation (TO-DO 204) tombe quand la machine rend
	// « installe » pour la version de sa dérogation : il a servi.
	if _, err := db.Exec(`UPDATE id_logiciels SET agent_update_version = ?, agent_update_result = ?,
		agent_update_reason = ?, agent_update_at = NOW(),
		agent_target_downgrade = IF(? = 'installe' AND agent_target_version = ?, 0, agent_target_downgrade)
		WHERE computeur_id = ?`,
		version, resultat, motif, resultat, version, computeurID); err != nil {
		logs.Write_LogCode("ERROR", logs.CodeDBQuery,
			"agent-update: compte rendu de "+computeurID+" non écrit : "+err.Error())
		return fmt.Errorf("écriture du compte rendu de %s : %w", computeurID, err)
	}
	return nil
}

// EnregistrerConfiguration range le dernier 09_07 d'une machine (TO-DO 117).
func EnregistrerConfiguration(db *sql.DB, computeurID, etat, motif string) error {
	if db == nil {
		return fmt.Errorf("base indisponible")
	}
	if r := []rune(motif); len(r) > 250 {
		motif = string(r[:250])
	}
	if _, err := db.Exec(`UPDATE id_logiciels SET agent_conf_state = ?, agent_conf_reason = ?,
		agent_conf_at = NOW() WHERE computeur_id = ?`, etat, motif, computeurID); err != nil {
		logs.Write_LogCode("ERROR", logs.CodeDBQuery,
			"confsys: compte rendu de "+computeurID+" non écrit : "+err.Error())
		return fmt.Errorf("écriture du compte rendu de configuration de %s : %w", computeurID, err)
	}
	return nil
}

// EnregistrerJeuAgent range le numéro du jeu de clés de confiance qu'une
// machine déclare tenir (09_09, TO-DO 207).
func EnregistrerJeuAgent(db *sql.DB, computeurID string, numero int) error {
	if db == nil {
		return fmt.Errorf("base indisponible")
	}
	if _, err := db.Exec(`UPDATE id_logiciels SET agent_pkg_trust = ? WHERE computeur_id = ?`,
		numero, computeurID); err != nil {
		logs.Write_LogCode("ERROR", logs.CodeDBQuery,
			"agent-update: jeu de clés de "+computeurID+" non écrit : "+err.Error())
		return fmt.Errorf("écriture du jeu de clés de %s : %w", computeurID, err)
	}
	return nil
}

// EffacerCompteRendu oublie le dernier compte rendu : la machine redevient
// « pas encore tentée », et la prochaine demande lui redonne l'ordre — c'est
// ce que fait « vlt agent update ».
func EffacerCompteRendu(db *sql.DB, computeurID string) error {
	if db == nil {
		return fmt.Errorf("base indisponible")
	}
	if _, err := db.Exec(`UPDATE id_logiciels SET agent_update_version = '', agent_update_result = '',
		agent_update_reason = '', agent_update_at = NULL WHERE computeur_id = ?`, computeurID); err != nil {
		return fmt.Errorf("effacement du compte rendu de %s : %w", computeurID, err)
	}
	return nil
}
