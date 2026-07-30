package dbgpo

import (
	"database/sql"
	"fmt"
	"strings"
	"time"

	"vaultaire/core/database"
	"vaultaire/core/gpo"
	"vaultaire/core/logs"
)

// CreatePolicy crée une GPO vide (sans module ni groupe).
//
// Le nom et le scope sont validés par core/gpo avant écriture : une GPO dont le
// scope serait invalide rendrait la précédence machine/user indécidable.
func CreatePolicy(db *sql.DB, name string, scope gpo.Scope, description string) (int, error) {
	if err := database.SanitizeInput(name); err != nil {
		return 0, err
	}
	if err := gpo.ValidatePolicyName(name); err != nil {
		return 0, err
	}
	if err := gpo.ValidateDescription(description); err != nil {
		return 0, err
	}
	if !gpo.IsValidPolicyScope(scope) {
		return 0, fmt.Errorf("scope invalide %q (attendu : %s ou %s)", scope, gpo.ScopeMachine, gpo.ScopeUser)
	}

	res, err := db.Exec(
		`INSERT INTO gpo (gpo_name, scope, description, version, enabled) VALUES (?, ?, ?, 1, TRUE)`,
		strings.TrimSpace(name), string(scope), strings.TrimSpace(description),
	)
	if err != nil {
		logs.Write_LogCode("ERROR", logs.CodeDBGeneric, "gpo: création de la GPO "+name+" échouée : "+err.Error())
		return 0, fmt.Errorf("création de la GPO %s impossible : %v", name, err)
	}
	id, err := res.LastInsertId()
	if err != nil {
		return 0, err
	}
	logs.Write_Log("INFO", fmt.Sprintf("gpo: GPO %s créée (scope %s, id %d)", name, scope, id))
	return int(id), nil
}

// GetPolicyIDByName résout l'identifiant d'une GPO depuis son nom.
func GetPolicyIDByName(db *sql.DB, name string) (int, error) {
	if err := database.SanitizeInput(name); err != nil {
		return 0, err
	}
	var id int
	err := db.QueryRow(`SELECT id_gpo FROM gpo WHERE gpo_name = ?`, name).Scan(&id)
	if err == sql.ErrNoRows {
		return 0, fmt.Errorf("GPO %s introuvable", name)
	}
	if err != nil {
		return 0, fmt.Errorf("erreur de lecture de la GPO %s : %v", name, err)
	}
	return id, nil
}

// scanPolicyRow lit les métadonnées d'une GPO depuis une ligne de résultat.
func scanPolicyRow(scanner interface{ Scan(...any) error }) (gpo.Policy, error) {
	var p gpo.Policy
	var scope, description sql.NullString
	var createdAt, updatedAt sql.NullTime

	if err := scanner.Scan(&p.ID, &p.Name, &scope, &description, &p.Version, &p.Enabled, &createdAt, &updatedAt); err != nil {
		return p, err
	}
	p.Scope = gpo.Scope(scope.String)
	p.Description = description.String
	if createdAt.Valid {
		p.CreatedAt = createdAt.Time
	}
	if updatedAt.Valid {
		p.UpdatedAt = updatedAt.Time
	}
	return p, nil
}

const policySelect = `SELECT id_gpo, gpo_name, scope, description, version, enabled, created_at, updated_at FROM gpo`

// GetPolicyByName retourne une GPO complète : métadonnées, modules triés dans
// leur ordre d'application, et noms des groupes auxquels elle est liée.
func GetPolicyByName(db *sql.DB, name string) (*gpo.Policy, error) {
	if err := database.SanitizeInput(name); err != nil {
		return nil, err
	}
	row := db.QueryRow(policySelect+` WHERE gpo_name = ?`, name)
	p, err := scanPolicyRow(row)
	if err == sql.ErrNoRows {
		return nil, fmt.Errorf("GPO %s introuvable", name)
	}
	if err != nil {
		return nil, fmt.Errorf("erreur de lecture de la GPO %s : %v", name, err)
	}

	modules, err := GetModulesForPolicy(db, p.ID)
	if err != nil {
		return nil, err
	}
	p.Modules = modules

	groups, err := GetGroupsForPolicy(db, p.ID)
	if err != nil {
		return nil, err
	}
	p.Groups = groups
	return &p, nil
}

// GetPolicyByID retourne une GPO complète depuis son identifiant.
func GetPolicyByID(db *sql.DB, id int) (*gpo.Policy, error) {
	row := db.QueryRow(policySelect+` WHERE id_gpo = ?`, id)
	p, err := scanPolicyRow(row)
	if err == sql.ErrNoRows {
		return nil, fmt.Errorf("GPO %d introuvable", id)
	}
	if err != nil {
		return nil, fmt.Errorf("erreur de lecture de la GPO %d : %v", id, err)
	}
	if p.Modules, err = GetModulesForPolicy(db, p.ID); err != nil {
		return nil, err
	}
	if p.Groups, err = GetGroupsForPolicy(db, p.ID); err != nil {
		return nil, err
	}
	return &p, nil
}

// PolicySummary est la vue de liste d'une GPO : métadonnées, nombre de modules
// et groupes liés, sans charger le détail des paramètres.
type PolicySummary struct {
	gpo.Policy
	ModuleCount int
}

// GetAllPolicies retourne toutes les GPO pour l'affichage en liste.
func GetAllPolicies(db *sql.DB) ([]PolicySummary, error) {
	rows, err := db.Query(policySelect + ` ORDER BY scope, gpo_name`)
	if err != nil {
		logs.Write_LogCode("ERROR", logs.CodeDBGeneric, "gpo: liste des GPO échouée : "+err.Error())
		return nil, fmt.Errorf("erreur de lecture des GPO : %v", err)
	}
	defer closeRows(rows)

	var out []PolicySummary
	for rows.Next() {
		p, err := scanPolicyRow(rows)
		if err != nil {
			return nil, fmt.Errorf("erreur de lecture d'une GPO : %v", err)
		}
		out = append(out, PolicySummary{Policy: p})
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}

	// Comptage des modules et récupération des groupes en dehors de la boucle de
	// scan : lire pendant qu'un *sql.Rows est ouvert monopolise la connexion.
	for i := range out {
		count, err := CountModulesForPolicy(db, out[i].ID)
		if err != nil {
			return nil, err
		}
		out[i].ModuleCount = count
		groups, err := GetGroupsForPolicy(db, out[i].ID)
		if err != nil {
			return nil, err
		}
		out[i].Groups = groups
	}
	return out, nil
}

// GetPoliciesByScope retourne les GPO d'un scope donné, modules chargés.
func GetPoliciesByScope(db *sql.DB, scope gpo.Scope) ([]gpo.Policy, error) {
	if !gpo.IsValidPolicyScope(scope) {
		return nil, fmt.Errorf("scope invalide : %s", scope)
	}
	rows, err := db.Query(policySelect+` WHERE scope = ? ORDER BY gpo_name`, string(scope))
	if err != nil {
		return nil, fmt.Errorf("erreur de lecture des GPO de scope %s : %v", scope, err)
	}
	defer closeRows(rows)

	var out []gpo.Policy
	for rows.Next() {
		p, err := scanPolicyRow(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, p)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	for i := range out {
		if out[i].Modules, err = GetModulesForPolicy(db, out[i].ID); err != nil {
			return nil, err
		}
	}
	return out, nil
}

// UpdatePolicyMeta met à jour la description et l'activation d'une GPO.
// Le nom et le scope ne sont pas modifiables : renommer casserait les
// références, et changer le scope reclasserait silencieusement des modules
// machine-only dans un contexte utilisateur.
func UpdatePolicyMeta(db *sql.DB, id int, description string, enabled bool) error {
	if err := gpo.ValidateDescription(description); err != nil {
		return err
	}
	_, err := db.Exec(
		`UPDATE gpo SET description = ?, enabled = ?, version = version + 1 WHERE id_gpo = ?`,
		strings.TrimSpace(description), enabled, id,
	)
	if err != nil {
		logs.Write_LogCode("ERROR", logs.CodeDBGeneric, "gpo: mise à jour de la GPO échouée : "+err.Error())
		return fmt.Errorf("mise à jour de la GPO impossible : %v", err)
	}
	return nil
}

// BumpVersion incrémente la version d'une GPO.
//
// Toute modification de contenu doit passer par ici : la version alimente le
// hash côté agent, et c'est ce hash qui décide s'il faut réappliquer la
// politique. Une modification sans incrément resterait invisible pour le parc.
func BumpVersion(db *sql.DB, id int) error {
	if _, err := db.Exec(`UPDATE gpo SET version = version + 1 WHERE id_gpo = ?`, id); err != nil {
		return fmt.Errorf("incrément de version de la GPO %d impossible : %v", id, err)
	}
	return nil
}

// DeletePolicyByName supprime une GPO. Les modules et les liaisons de groupe
// partent en cascade via les clés étrangères.
func DeletePolicyByName(db *sql.DB, name string) error {
	if err := database.SanitizeInput(name); err != nil {
		return err
	}
	res, err := db.Exec(`DELETE FROM gpo WHERE gpo_name = ?`, name)
	if err != nil {
		logs.Write_LogCode("ERROR", logs.CodeDBGeneric, "gpo: suppression de la GPO "+name+" échouée : "+err.Error())
		return fmt.Errorf("suppression de la GPO %s impossible : %v", name, err)
	}
	affected, _ := res.RowsAffected()
	if affected == 0 {
		return fmt.Errorf("GPO %s introuvable", name)
	}
	logs.Write_Log("INFO", "gpo: GPO "+name+" supprimée")
	return nil
}

// PolicyExists indique si une GPO de ce nom existe.
func PolicyExists(db *sql.DB, name string) bool {
	if err := database.SanitizeInput(name); err != nil {
		return false
	}
	var count int
	if err := db.QueryRow(`SELECT COUNT(*) FROM gpo WHERE gpo_name = ?`, name).Scan(&count); err != nil {
		return false
	}
	return count > 0
}

// closeRows ferme un *sql.Rows en journalisant l'échec éventuel, comme le reste
// de la couche base du projet.
func closeRows(rows *sql.Rows) {
	if err := rows.Close(); err != nil {
		logs.Write_Log("ERROR", "gpo: fermeture du curseur échouée : "+err.Error())
	}
}

// nowStamp est utilisé par les logs d'audit des modules.
func nowStamp() string { return time.Now().Format("2006-01-02 15:04:05") }
