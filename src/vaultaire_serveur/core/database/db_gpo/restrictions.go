package dbgpo

import (
	"database/sql"
	"fmt"
	"regexp"
	"strings"
	"time"

	"vaultaire/core/database"
	"vaultaire/core/gpo"
	"vaultaire/core/logs"
)

// definitionNameRe borne les noms de définition : ce nom est écrit tel quel dans
// les paramètres JSON d'un module, et recherché par motif lors de la suppression.
// Le restreindre garantit que les deux opérations restent exactes.
var definitionNameRe = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{1,63}$`)

// Persistance des restrictions GPO.
//
// Les listes d'autorisation, les règles de champ, les règles de chemin et les
// variables d'environnement interdites vivent en base et sont éditables par les
// membres du groupe superadmin `vaultaire` — et par eux seuls.
//
// La vérification d'appartenance est faite ICI, dans la couche base, et non
// seulement dans le handler web : c'est la seule façon de garantir qu'aucun
// appelant présent ou futur (CLI, API, LDAP) ne contourne la porte. Chaque
// écriture est journalisée en SECURITY avec son auteur, parce que modifier une
// restriction change ce que l'ensemble du parc accepte d'appliquer.

// Catégories de lignes dans gpo_restriction.
const (
	KindAllowValue = "allow_value" // valeur autorisée pour un champ de module
	KindPathAllow  = "path_allow"  // préfixe de chemin autorisé
	KindPathDeny   = "path_deny"   // préfixe de chemin refusé
	KindEnvDeny    = "env_deny"    // variable d'environnement interdite
)

var restrictionTablesDDL = []string{
	`CREATE TABLE IF NOT EXISTS gpo_restriction (
		id_gpo_restriction INT AUTO_INCREMENT PRIMARY KEY,
		kind VARCHAR(24) NOT NULL,
		module_type VARCHAR(64) NOT NULL DEFAULT '',
		field_name VARCHAR(64) NOT NULL DEFAULT '',
		scope VARCHAR(16) NOT NULL DEFAULT 'any',
		value VARCHAR(512) NOT NULL,
		note VARCHAR(255) DEFAULT NULL,
		updated_by VARCHAR(255) DEFAULT NULL,
		updated_at DATETIME DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
		UNIQUE KEY uk_gpo_restriction (kind, module_type, field_name, scope, value(191)),
		INDEX idx_gpo_restriction_kind (kind),
		INDEX idx_gpo_restriction_field (module_type, field_name)
	) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;`,

	// Valeurs nommées porteuses d'un contenu (ex. jeux de commandes sudo).
	// Table distincte de gpo_restriction : le contenu peut être long et
	// multiligne, ce qui ne tient pas dans une colonne indexée.
	`CREATE TABLE IF NOT EXISTS gpo_value_definition (
		id_gpo_value_definition INT AUTO_INCREMENT PRIMARY KEY,
		module_type VARCHAR(64) NOT NULL,
		field_name VARCHAR(64) NOT NULL,
		name VARCHAR(128) NOT NULL,
		payload_kind VARCHAR(32) NOT NULL,
		payload TEXT NOT NULL,
		note VARCHAR(255) DEFAULT NULL,
		updated_by VARCHAR(255) DEFAULT NULL,
		updated_at DATETIME DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
		UNIQUE KEY uk_gpo_value_definition (module_type, field_name, name),
		INDEX idx_gpo_value_definition_field (module_type, field_name)
	) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;`,

	`CREATE TABLE IF NOT EXISTS gpo_field_rule (
		id_gpo_field_rule INT AUTO_INCREMENT PRIMARY KEY,
		module_type VARCHAR(64) NOT NULL,
		field_name VARCHAR(64) NOT NULL,
		mode VARCHAR(16) NOT NULL DEFAULT 'list',
		allow_pattern VARCHAR(512) DEFAULT NULL,
		deny_pattern VARCHAR(512) DEFAULT NULL,
		note VARCHAR(512) DEFAULT NULL,
		updated_by VARCHAR(255) DEFAULT NULL,
		updated_at DATETIME DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
		UNIQUE KEY uk_gpo_field_rule (module_type, field_name)
	) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;`,
}

// RestrictionRow est une ligne de restriction telle qu'affichée dans l'interface.
type RestrictionRow struct {
	ID         int
	Kind       string
	ModuleType string
	FieldName  string
	Scope      string
	Value      string
	Note       string
	UpdatedBy  string
	UpdatedAt  time.Time
}

// DefinitionRow est une définition à contenu telle qu'affichée dans l'interface.
type DefinitionRow struct {
	ID          int
	ModuleType  string
	FieldName   string
	Name        string
	PayloadKind string
	Payload     string
	Note        string
	UpdatedBy   string
	UpdatedAt   time.Time
}

// FieldRuleRow est une règle de champ telle qu'affichée dans l'interface.
type FieldRuleRow struct {
	ID           int
	ModuleType   string
	FieldName    string
	Mode         string
	AllowPattern string
	DenyPattern  string
	Note         string
	UpdatedBy    string
	UpdatedAt    time.Time
}

// createRestrictionTables crée les tables de restrictions.
func createRestrictionTables(db *sql.DB) error {
	for _, ddl := range restrictionTablesDDL {
		if _, err := db.Exec(ddl); err != nil {
			logs.Write_LogCode("ERROR", logs.CodeDBGeneric, "gpo: création des tables de restrictions échouée : "+err.Error())
			return fmt.Errorf("gpo: création des tables de restrictions échouée : %v", err)
		}
	}
	return nil
}

// requireSuperadmin refuse l'opération si l'acteur n'est pas membre du groupe
// superadmin. Le nom de l'acteur est obligatoire : une écriture anonyme sur les
// restrictions serait intraçable, donc inacceptable.
func requireSuperadmin(db *sql.DB, actor, operation string) error {
	actor = strings.TrimSpace(actor)
	if actor == "" {
		return fmt.Errorf("auteur non identifié : opération refusée sur les restrictions GPO")
	}
	if !database.IsSuperadmin(db, actor) {
		logs.Write_Log("SECURITY", fmt.Sprintf(
			"gpo: %s a tenté %s sur les restrictions sans appartenir au groupe %s — refusé",
			actor, operation, database.ProtectedGroupName))
		return fmt.Errorf("réservé aux membres du groupe %s", database.ProtectedGroupName)
	}
	return nil
}

// auditRestriction journalise une modification de restriction.
func auditRestriction(actor, action, detail string) {
	logs.Write_Log("SECURITY", fmt.Sprintf("gpo/restrictions: %s par %s — %s", action, actor, detail))
	gpo.InvalidateRestrictionCache()
}

// ---------------------------------------------------------------------------
// Peuplement initial et réinitialisation
// ---------------------------------------------------------------------------

// SetupRestrictions crée les tables de restrictions et n'exécute le peuplement
// initial que pour celles qui viennent d'être créées.
//
// L'existence des tables est constatée AVANT leur création : c'est ce qui
// distingue un premier démarrage d'un redémarrage, et c'est ce qui garantit
// qu'une valeur supprimée depuis l'interface ne réapparaît jamais. Un marqueur
// stocké en base ne l'aurait pas garanti, puisqu'il est lui-même supprimable.
func SetupRestrictions(db *sql.DB) error {
	missing, err := missingRestrictionTables(db)
	if err != nil {
		return err
	}
	if err := createRestrictionTables(db); err != nil {
		return err
	}
	if len(missing) > 0 {
		var names []string
		for _, t := range restrictionTables {
			if missing[t] {
				names = append(names, t)
			}
		}
		logs.Write_Log("INFO", "gpo: tables de restrictions créées ("+strings.Join(names, ", ")+"), peuplement initial")
		if err := runSeed(db, missing); err != nil {
			return err
		}
	}

	// Les règles de champ sont vérifiées à chaque démarrage : elles définissent
	// COMMENT un champ se valide, pas quelles valeurs sont permises. Un champ
	// ajouté au catalogue doit obtenir sa règle même sur une base existante,
	// sinon son module refuserait tout.
	if err := ensureFieldRules(db); err != nil {
		return err
	}

	// Rattrapage des bases antérieures : un champ devenu porteur de définitions
	// ne doit plus avoir de valeurs de liste simple orphelines.
	return pruneOrphanAllowValues(db)
}

// ResetRestrictionsToDefaults purge les restrictions et rejoue le peuplement.
//
// Sortie de secours : puisque tout est éditable, il faut pouvoir revenir à un
// état connu après une modification malheureuse. C'est le SEUL chemin par lequel
// le socle initial est réécrit sur des tables existantes, et il est explicite,
// réservé au superadmin et journalisé.
func ResetRestrictionsToDefaults(db *sql.DB, actor string) error {
	if err := requireSuperadmin(db, actor, "la réinitialisation"); err != nil {
		return err
	}
	for _, table := range []string{"gpo_restriction", "gpo_field_rule", "gpo_value_definition"} {
		if _, err := db.Exec("DELETE FROM " + table); err != nil {
			return fmt.Errorf("gpo: purge de %s impossible : %v", table, err)
		}
	}
	if err := runSeed(db, nil); err != nil {
		return err
	}
	auditRestriction(actor, "réinitialisation complète", "socle initial réécrit depuis le script de peuplement embarqué")
	return nil
}

// ---------------------------------------------------------------------------
// Lecture (fournisseur pour core/gpo)
// ---------------------------------------------------------------------------

// Provider lit les restrictions depuis la base pour le compte de core/gpo.
type Provider struct{}

// RegisterRestrictionProvider installe le fournisseur base dans core/gpo, et
// branche le journal des échecs de chargement.
// Appelée depuis CreateTables, après création et peuplement des tables.
func RegisterRestrictionProvider() {
	gpo.SetRestrictionFailureLogger(func(message string) {
		logs.Write_LogCode("ERROR", logs.CodeDBGeneric,
			"gpo: restrictions non chargées, aucune GPO ne peut être validée — "+message)
	})
	gpo.SetRestrictionProvider(Provider{})
}

// LoadRestrictions implémente gpo.RestrictionProvider.
func (Provider) LoadRestrictions() (gpo.RestrictionSet, error) {
	db := database.GetDatabase()
	if db == nil {
		return gpo.RestrictionSet{}, fmt.Errorf("connexion base indisponible")
	}
	return loadRestrictions(db)
}

// loadRestrictions construit le jeu de restrictions depuis la base.
func loadRestrictions(db *sql.DB) (gpo.RestrictionSet, error) {
	rs := gpo.RestrictionSet{
		AllowedValues: map[string][]gpo.AllowedValue{},
		Definitions:   map[string][]gpo.ValueDefinition{},
		FieldRules:    map[string]gpo.FieldRule{},
	}

	rows, err := db.Query(
		`SELECT kind, module_type, field_name, scope, value, COALESCE(note, '')
		 FROM gpo_restriction ORDER BY kind, module_type, field_name, value`)
	if err != nil {
		return rs, fmt.Errorf("lecture des restrictions impossible : %v", err)
	}

	for rows.Next() {
		var kind, moduleType, fieldName, scope, value, note string
		if err := rows.Scan(&kind, &moduleType, &fieldName, &scope, &value, &note); err != nil {
			closeRows(rows)
			return rs, err
		}
		switch kind {
		case KindAllowValue:
			key := gpo.FieldKey(moduleType, fieldName)
			rs.AllowedValues[key] = append(rs.AllowedValues[key], gpo.AllowedValue{
				ModuleType: moduleType, FieldName: fieldName, Value: value, Label: note,
			})
		case KindPathAllow:
			rs.PathRules = append(rs.PathRules, gpo.PathRule{Scope: scope, Deny: false, Prefix: value, Note: note})
		case KindPathDeny:
			rs.PathRules = append(rs.PathRules, gpo.PathRule{Scope: scope, Deny: true, Prefix: value, Note: note})
		case KindEnvDeny:
			rs.EnvDenied = append(rs.EnvDenied, gpo.EnvRule{Name: value, Note: note})
		}
	}
	if err := rows.Err(); err != nil {
		closeRows(rows)
		return rs, err
	}
	// Le premier curseur est fermé avant d'ouvrir le second : un *sql.Rows non
	// fermé retient une connexion du pool, et cette fonction est appelée à chaque
	// rechargement du cache de restrictions.
	closeRows(rows)

	ruleRows, err := db.Query(
		`SELECT module_type, field_name, mode, COALESCE(allow_pattern, ''), COALESCE(deny_pattern, ''), COALESCE(note, ''), COALESCE(updated_by, '')
		 FROM gpo_field_rule`)
	if err != nil {
		return rs, fmt.Errorf("lecture des règles de champ impossible : %v", err)
	}
	defer closeRows(ruleRows)

	for ruleRows.Next() {
		var r gpo.FieldRule
		if err := ruleRows.Scan(&r.ModuleType, &r.FieldName, &r.Mode, &r.AllowPattern, &r.DenyPattern, &r.Note, &r.UpdatedBy); err != nil {
			return rs, err
		}
		if !gpo.IsValidFieldMode(r.Mode) {
			logs.Write_Log("WARNING", fmt.Sprintf(
				"gpo: mode de champ inconnu %q pour %s/%s — repli sur le mode liste", r.Mode, r.ModuleType, r.FieldName))
			r.Mode = gpo.FieldModeList
		}
		rs.FieldRules[gpo.FieldKey(r.ModuleType, r.FieldName)] = r
	}
	if err := ruleRows.Err(); err != nil {
		closeRows(ruleRows)
		return rs, err
	}
	closeRows(ruleRows)

	defRows, err := db.Query(
		`SELECT module_type, field_name, name, payload_kind, payload, COALESCE(note, ''), COALESCE(updated_by, '')
		 FROM gpo_value_definition ORDER BY module_type, field_name, name`)
	if err != nil {
		return rs, fmt.Errorf("lecture des définitions impossible : %v", err)
	}
	defer closeRows(defRows)

	for defRows.Next() {
		var d gpo.ValueDefinition
		var kind string
		if err := defRows.Scan(&d.ModuleType, &d.FieldName, &d.Name, &kind, &d.Payload, &d.Note, &d.UpdatedBy); err != nil {
			return rs, err
		}
		d.Kind = gpo.PayloadKind(kind)
		key := gpo.FieldKey(d.ModuleType, d.FieldName)
		rs.Definitions[key] = append(rs.Definitions[key], d)
	}
	return rs, defRows.Err()
}

// ListDefinitionsForField retourne les définitions d'un champ, pour l'interface.
func ListDefinitionsForField(db *sql.DB, moduleType, fieldName string) ([]DefinitionRow, error) {
	rows, err := db.Query(
		`SELECT id_gpo_value_definition, module_type, field_name, name, payload_kind, payload,
		        COALESCE(note, ''), COALESCE(updated_by, ''), updated_at
		 FROM gpo_value_definition WHERE module_type = ? AND field_name = ? ORDER BY name`,
		moduleType, fieldName)
	if err != nil {
		return nil, fmt.Errorf("lecture des définitions de %s/%s impossible : %v", moduleType, fieldName, err)
	}
	defer closeRows(rows)

	var out []DefinitionRow
	for rows.Next() {
		var d DefinitionRow
		var updatedAt sql.NullTime
		if err := rows.Scan(&d.ID, &d.ModuleType, &d.FieldName, &d.Name, &d.PayloadKind,
			&d.Payload, &d.Note, &d.UpdatedBy, &updatedAt); err != nil {
			return nil, err
		}
		if updatedAt.Valid {
			d.UpdatedAt = updatedAt.Time
		}
		out = append(out, d)
	}
	return out, rows.Err()
}

// SaveDefinition crée ou met à jour une définition à contenu.
//
// C'est le point d'entrée pour créer un jeu de commandes sudo custom, ou tout
// futur champ à contenu : le kind attendu est déduit du catalogue, jamais fourni
// par l'appelant, pour qu'on ne puisse pas stocker un contenu d'un type que le
// champ ne sait pas interpréter.
func SaveDefinition(db *sql.DB, actor, moduleType, fieldName, name, payload, note string) error {
	if err := requireSuperadmin(db, actor, "l'enregistrement d'une définition"); err != nil {
		return err
	}
	if err := validateFieldTarget(moduleType, fieldName); err != nil {
		return err
	}
	kind := gpo.PayloadKindFor(moduleType, fieldName)
	if kind == gpo.PayloadNone {
		return fmt.Errorf("le champ %s/%s n'attend pas de contenu : utilisez la liste de valeurs", moduleType, fieldName)
	}

	name = strings.TrimSpace(name)
	if err := validateRestrictionValue(name, 128); err != nil {
		return err
	}
	if !definitionNameRe.MatchString(name) {
		return fmt.Errorf("nom invalide %q (lettres, chiffres, point, tiret, souligné ; 2 à 64 caractères)", name)
	}
	if err := database.SanitizeIdentifier(moduleType, fieldName, name); err != nil {
		return err
	}
	if err := gpo.ValidatePayload(kind, payload); err != nil {
		return err
	}

	previous, existed, err := getDefinition(db, moduleType, fieldName, name)
	if err != nil {
		return err
	}

	if _, err := db.Exec(
		`INSERT INTO gpo_value_definition (module_type, field_name, name, payload_kind, payload, note, updated_by)
		 VALUES (?, ?, ?, ?, ?, ?, ?)
		 ON DUPLICATE KEY UPDATE payload_kind = VALUES(payload_kind), payload = VALUES(payload),
		   note = VALUES(note), updated_by = VALUES(updated_by)`,
		moduleType, fieldName, name, string(kind), payload, nullIfEmpty(strings.TrimSpace(note)), actor,
	); err != nil {
		return fmt.Errorf("enregistrement de la définition %q impossible : %v", name, err)
	}

	action := "création de définition"
	detail := fmt.Sprintf("%s/%s/%s (%s) : %s", moduleType, fieldName, name, kind, oneLine(payload))
	if existed {
		action = "modification de définition"
		detail = fmt.Sprintf("%s/%s/%s (%s) : %s → %s",
			moduleType, fieldName, name, kind, oneLine(previous.Payload), oneLine(payload))
	}
	auditRestriction(actor, action, detail)
	return nil
}

// DeleteDefinition supprime une définition à contenu.
//
// Refuse la suppression si la définition est encore référencée par un module de
// GPO : sans ce contrôle, la GPO deviendrait invalide et son application
// échouerait sur le parc, avec une cause difficile à retrouver.
func DeleteDefinition(db *sql.DB, actor string, id int) error {
	if err := requireSuperadmin(db, actor, "la suppression d'une définition"); err != nil {
		return err
	}
	var moduleType, fieldName, name, payload string
	err := db.QueryRow(
		`SELECT module_type, field_name, name, payload FROM gpo_value_definition WHERE id_gpo_value_definition = ?`, id,
	).Scan(&moduleType, &fieldName, &name, &payload)
	if err == sql.ErrNoRows {
		return fmt.Errorf("définition %d introuvable", id)
	}
	if err != nil {
		return fmt.Errorf("lecture de la définition %d impossible : %v", id, err)
	}

	users, err := findModulesUsingValue(db, moduleType, fieldName, name)
	if err != nil {
		return err
	}
	if len(users) > 0 {
		return fmt.Errorf("la définition %q est utilisée par %d module(s) de GPO (%s) : retirez-les d'abord",
			name, len(users), strings.Join(users, ", "))
	}

	if _, err := db.Exec(`DELETE FROM gpo_value_definition WHERE id_gpo_value_definition = ?`, id); err != nil {
		return fmt.Errorf("suppression de la définition %d impossible : %v", id, err)
	}
	auditRestriction(actor, "suppression de définition",
		fmt.Sprintf("%s/%s/%s : %s", moduleType, fieldName, name, oneLine(payload)))
	return nil
}

// getDefinition lit une définition par sa clé naturelle.
func getDefinition(db *sql.DB, moduleType, fieldName, name string) (DefinitionRow, bool, error) {
	var d DefinitionRow
	err := db.QueryRow(
		`SELECT id_gpo_value_definition, module_type, field_name, name, payload_kind, payload, COALESCE(note, '')
		 FROM gpo_value_definition WHERE module_type = ? AND field_name = ? AND name = ?`,
		moduleType, fieldName, name,
	).Scan(&d.ID, &d.ModuleType, &d.FieldName, &d.Name, &d.PayloadKind, &d.Payload, &d.Note)
	if err == sql.ErrNoRows {
		return d, false, nil
	}
	if err != nil {
		return d, false, fmt.Errorf("lecture de la définition %q impossible : %v", name, err)
	}
	return d, true, nil
}

// findModulesUsingValue retourne les GPO dont un module utilise cette valeur.
//
// Les paramètres sont stockés en JSON : la recherche se fait sur le motif
// "field":"value", ce qui est exact pour des noms sans caractère spécial (le
// format des noms de définition l'impose déjà).
func findModulesUsingValue(db *sql.DB, moduleType, fieldName, value string) ([]string, error) {
	needle := `"` + fieldName + `":"` + value + `"`
	rows, err := db.Query(
		`SELECT DISTINCT g.gpo_name FROM gpo g
		 INNER JOIN gpo_module m ON m.d_id_gpo = g.id_gpo
		 WHERE m.module_type = ? AND m.params LIKE CONCAT('%', ?, '%')
		 ORDER BY g.gpo_name`,
		moduleType, needle)
	if err != nil {
		return nil, fmt.Errorf("recherche des utilisateurs de %q impossible : %v", value, err)
	}
	defer closeRows(rows)

	var out []string
	for rows.Next() {
		var name string
		if err := rows.Scan(&name); err != nil {
			return nil, err
		}
		out = append(out, name)
	}
	return out, rows.Err()
}

// oneLine condense un contenu multiligne pour le journal d'audit.
func oneLine(payload string) string {
	compact := strings.Join(strings.Fields(strings.ReplaceAll(payload, "\n", " ; ")), " ")
	if len(compact) > 200 {
		return compact[:200] + "…"
	}
	return compact
}

// ListRestrictionsByKind retourne les lignes d'une catégorie, pour l'interface.
func ListRestrictionsByKind(db *sql.DB, kind string) ([]RestrictionRow, error) {
	rows, err := db.Query(
		`SELECT id_gpo_restriction, kind, module_type, field_name, scope, value,
		        COALESCE(note, ''), COALESCE(updated_by, ''), updated_at
		 FROM gpo_restriction WHERE kind = ?
		 ORDER BY module_type, field_name, scope, value`, kind)
	if err != nil {
		return nil, fmt.Errorf("lecture des restrictions (%s) impossible : %v", kind, err)
	}
	defer closeRows(rows)

	var out []RestrictionRow
	for rows.Next() {
		var r RestrictionRow
		var updatedAt sql.NullTime
		if err := rows.Scan(&r.ID, &r.Kind, &r.ModuleType, &r.FieldName, &r.Scope, &r.Value, &r.Note, &r.UpdatedBy, &updatedAt); err != nil {
			return nil, err
		}
		if updatedAt.Valid {
			r.UpdatedAt = updatedAt.Time
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

// ListAllowedValuesForField retourne les valeurs autorisées d'un champ précis.
func ListAllowedValuesForField(db *sql.DB, moduleType, fieldName string) ([]RestrictionRow, error) {
	rows, err := db.Query(
		`SELECT id_gpo_restriction, kind, module_type, field_name, scope, value,
		        COALESCE(note, ''), COALESCE(updated_by, ''), updated_at
		 FROM gpo_restriction WHERE kind = ? AND module_type = ? AND field_name = ?
		 ORDER BY value`, KindAllowValue, moduleType, fieldName)
	if err != nil {
		return nil, fmt.Errorf("lecture des valeurs autorisées de %s/%s impossible : %v", moduleType, fieldName, err)
	}
	defer closeRows(rows)

	var out []RestrictionRow
	for rows.Next() {
		var r RestrictionRow
		var updatedAt sql.NullTime
		if err := rows.Scan(&r.ID, &r.Kind, &r.ModuleType, &r.FieldName, &r.Scope, &r.Value, &r.Note, &r.UpdatedBy, &updatedAt); err != nil {
			return nil, err
		}
		if updatedAt.Valid {
			r.UpdatedAt = updatedAt.Time
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

// GetFieldRule retourne la règle enregistrée pour un champ.
func GetFieldRule(db *sql.DB, moduleType, fieldName string) (FieldRuleRow, error) {
	var r FieldRuleRow
	var updatedAt sql.NullTime
	err := db.QueryRow(
		`SELECT id_gpo_field_rule, module_type, field_name, mode,
		        COALESCE(allow_pattern, ''), COALESCE(deny_pattern, ''), COALESCE(note, ''), COALESCE(updated_by, ''), updated_at
		 FROM gpo_field_rule WHERE module_type = ? AND field_name = ?`, moduleType, fieldName,
	).Scan(&r.ID, &r.ModuleType, &r.FieldName, &r.Mode, &r.AllowPattern, &r.DenyPattern, &r.Note, &r.UpdatedBy, &updatedAt)
	if err == sql.ErrNoRows {
		return FieldRuleRow{ModuleType: moduleType, FieldName: fieldName, Mode: gpo.FieldModeList}, nil
	}
	if err != nil {
		return r, fmt.Errorf("lecture de la règle %s/%s impossible : %v", moduleType, fieldName, err)
	}
	if updatedAt.Valid {
		r.UpdatedAt = updatedAt.Time
	}
	return r, nil
}

// ---------------------------------------------------------------------------
// Écriture (réservée au groupe superadmin)
// ---------------------------------------------------------------------------

// AddAllowedValue ajoute une valeur autorisée à un champ.
// C'est le point d'entrée pour déclarer un besoin custom : une unité systemd
// maison, un paquet interne, un identifiant de tâche propre au client.
func AddAllowedValue(db *sql.DB, actor, moduleType, fieldName, value, label string) error {
	if err := requireSuperadmin(db, actor, "l'ajout d'une valeur autorisée"); err != nil {
		return err
	}
	value = strings.TrimSpace(value)
	if err := validateFieldTarget(moduleType, fieldName); err != nil {
		return err
	}
	// Sur un champ à contenu, un nom sans contenu serait accepté ici mais rejeté
	// à la validation de la GPO (« jeu vide »). Autant refuser tout de suite avec
	// le bon message, plutôt que de laisser une entrée inutilisable en base.
	if gpo.FieldHasPayload(moduleType, fieldName) {
		return fmt.Errorf("le champ %s/%s attend une définition avec son contenu, pas un simple nom", moduleType, fieldName)
	}
	if err := validateRestrictionValue(value, 512); err != nil {
		return err
	}
	// Le type de module et le nom de champ sont des identifiants du catalogue.
	// La valeur, elle, peut être un chemin, un nom de paquet ou un motif : elle
	// est déjà bornée par validateRestrictionValue juste au-dessus.
	if err := database.SanitizeIdentifier(moduleType, fieldName); err != nil {
		return err
	}
	if err := database.SanitizeInput(value); err != nil {
		return err
	}

	res, err := db.Exec(
		`INSERT IGNORE INTO gpo_restriction (kind, module_type, field_name, scope, value, note, updated_by)
		 VALUES (?, ?, ?, 'any', ?, ?, ?)`,
		KindAllowValue, moduleType, fieldName, value, nullIfEmpty(strings.TrimSpace(label)), actor)
	if err != nil {
		return fmt.Errorf("ajout de la valeur %q impossible : %v", value, err)
	}
	if affected, _ := res.RowsAffected(); affected == 0 {
		return fmt.Errorf("la valeur %q est déjà autorisée pour %s/%s", value, moduleType, fieldName)
	}
	auditRestriction(actor, "ajout de valeur autorisée", fmt.Sprintf("%s/%s += %q", moduleType, fieldName, value))
	return nil
}

// DeleteRestriction supprime une ligne de restriction par son identifiant.
//
// Le retrait est journalisé avec la valeur exacte retirée : supprimer un refus
// de chemin élargit ce que le parc entier accepte d'écrire, il faut pouvoir
// retracer qui l'a fait et quoi.
func DeleteRestriction(db *sql.DB, actor string, id int) error {
	if err := requireSuperadmin(db, actor, "la suppression d'une restriction"); err != nil {
		return err
	}
	var kind, moduleType, fieldName, scope, value string
	err := db.QueryRow(
		`SELECT kind, module_type, field_name, scope, value FROM gpo_restriction WHERE id_gpo_restriction = ?`, id,
	).Scan(&kind, &moduleType, &fieldName, &scope, &value)
	if err == sql.ErrNoRows {
		return fmt.Errorf("restriction %d introuvable", id)
	}
	if err != nil {
		return fmt.Errorf("lecture de la restriction %d impossible : %v", id, err)
	}
	if _, err := db.Exec(`DELETE FROM gpo_restriction WHERE id_gpo_restriction = ?`, id); err != nil {
		return fmt.Errorf("suppression de la restriction %d impossible : %v", id, err)
	}
	auditRestriction(actor, "suppression de restriction",
		fmt.Sprintf("kind=%s %s/%s scope=%s valeur=%q", kind, moduleType, fieldName, scope, value))
	return nil
}

// SetFieldRule définit le mode de validation d'un champ et ses motifs.
//
// Les motifs sont compilés avant écriture : un motif invalide en base bloquerait
// ensuite toute validation du champ, avec un message incompréhensible pour
// l'administrateur suivant.
func SetFieldRule(db *sql.DB, actor, moduleType, fieldName, mode, allowPattern, denyPattern string) error {
	if err := requireSuperadmin(db, actor, "la modification d'une règle de champ"); err != nil {
		return err
	}
	if err := validateFieldTarget(moduleType, fieldName); err != nil {
		return err
	}
	if !gpo.IsValidFieldMode(mode) {
		return fmt.Errorf("mode %q invalide (attendu : %s)", mode, strings.Join(gpo.AllFieldModes(), ", "))
	}
	allowPattern = strings.TrimSpace(allowPattern)
	denyPattern = strings.TrimSpace(denyPattern)
	if err := gpo.ValidatePatternSyntax(allowPattern); err != nil {
		return fmt.Errorf("motif d'autorisation : %v", err)
	}
	if err := gpo.ValidatePatternSyntax(denyPattern); err != nil {
		return fmt.Errorf("motif d'exclusion : %v", err)
	}
	if mode == gpo.FieldModePattern && allowPattern == "" {
		return fmt.Errorf("le mode motif exige un motif d'autorisation")
	}

	previous, _ := GetFieldRule(db, moduleType, fieldName)

	if _, err := db.Exec(
		`INSERT INTO gpo_field_rule (module_type, field_name, mode, allow_pattern, deny_pattern, updated_by)
		 VALUES (?, ?, ?, ?, ?, ?)
		 ON DUPLICATE KEY UPDATE mode = VALUES(mode), allow_pattern = VALUES(allow_pattern),
		   deny_pattern = VALUES(deny_pattern), updated_by = VALUES(updated_by)`,
		moduleType, fieldName, mode, nullIfEmpty(allowPattern), nullIfEmpty(denyPattern), actor,
	); err != nil {
		return fmt.Errorf("enregistrement de la règle %s/%s impossible : %v", moduleType, fieldName, err)
	}

	auditRestriction(actor, "modification de règle de champ", fmt.Sprintf(
		"%s/%s : mode %s→%s, allow %q→%q, deny %q→%q",
		moduleType, fieldName, previous.Mode, mode,
		previous.AllowPattern, allowPattern, previous.DenyPattern, denyPattern))
	return nil
}

// AddPathRule ajoute une règle de chemin (autorisation ou refus).
func AddPathRule(db *sql.DB, actor, scope string, deny bool, prefix, note string) error {
	operation := "l'ajout d'une autorisation de chemin"
	if deny {
		operation = "l'ajout d'un refus de chemin"
	}
	if err := requireSuperadmin(db, actor, operation); err != nil {
		return err
	}
	if scope != gpo.PathScopeAny && scope != string(gpo.ScopeMachine) && scope != string(gpo.ScopeUser) {
		return fmt.Errorf("scope %q invalide (attendu : any, machine ou user)", scope)
	}
	prefix = strings.TrimSpace(prefix)
	if !strings.HasPrefix(prefix, "/") {
		return fmt.Errorf("un préfixe de chemin doit être absolu : %q", prefix)
	}
	if err := validateRestrictionValue(prefix, 512); err != nil {
		return err
	}
	if err := database.SanitizeInput(prefix); err != nil {
		return err
	}

	kind := KindPathAllow
	if deny {
		kind = KindPathDeny
	}
	res, err := db.Exec(
		`INSERT IGNORE INTO gpo_restriction (kind, scope, value, note, updated_by) VALUES (?, ?, ?, ?, ?)`,
		kind, scope, prefix, nullIfEmpty(strings.TrimSpace(note)), actor)
	if err != nil {
		return fmt.Errorf("ajout de la règle de chemin %q impossible : %v", prefix, err)
	}
	if affected, _ := res.RowsAffected(); affected == 0 {
		return fmt.Errorf("cette règle existe déjà pour le préfixe %q", prefix)
	}
	auditRestriction(actor, "ajout de règle de chemin",
		fmt.Sprintf("kind=%s scope=%s préfixe=%q", kind, scope, prefix))
	return nil
}

// AddEnvDeny interdit une variable d'environnement en scope user.
func AddEnvDeny(db *sql.DB, actor, name, note string) error {
	if err := requireSuperadmin(db, actor, "l'interdiction d'une variable d'environnement"); err != nil {
		return err
	}
	name = strings.ToUpper(strings.TrimSpace(name))
	if name == "" {
		return fmt.Errorf("nom de variable requis")
	}
	if err := validateRestrictionValue(name, 64); err != nil {
		return err
	}
	if err := database.SanitizeIdentifier(name); err != nil {
		return err
	}

	res, err := db.Exec(
		`INSERT IGNORE INTO gpo_restriction (kind, scope, value, note, updated_by) VALUES (?, 'any', ?, ?, ?)`,
		KindEnvDeny, name, nullIfEmpty(strings.TrimSpace(note)), actor)
	if err != nil {
		return fmt.Errorf("interdiction de %s impossible : %v", name, err)
	}
	if affected, _ := res.RowsAffected(); affected == 0 {
		return fmt.Errorf("la variable %s est déjà interdite", name)
	}
	auditRestriction(actor, "interdiction de variable d'environnement", name)
	return nil
}

// ---------------------------------------------------------------------------
// Utilitaires
// ---------------------------------------------------------------------------

// validateFieldTarget vérifie que le couple module/champ existe et que son
// domaine est bien géré en base. Sans ce contrôle, on pourrait accumuler des
// restrictions sur un champ inexistant, qui ne s'appliqueraient jamais tout en
// donnant l'illusion d'une protection.
func validateFieldTarget(moduleType, fieldName string) error {
	if _, ok := gpo.BaseSchemaFor(moduleType); !ok {
		return fmt.Errorf("module inconnu : %s", moduleType)
	}
	for _, f := range gpo.DynamicFields() {
		if f.ModuleType == moduleType && f.FieldName == fieldName {
			return nil
		}
	}
	return fmt.Errorf("le champ %s/%s n'a pas de domaine géré en base", moduleType, fieldName)
}

// validateRestrictionValue vérifie la forme d'une valeur de restriction.
func validateRestrictionValue(value string, maxLen int) error {
	if value == "" {
		return fmt.Errorf("valeur vide")
	}
	if len(value) > maxLen {
		return fmt.Errorf("valeur trop longue (%d caractères maximum)", maxLen)
	}
	if strings.ContainsAny(value, "\x00\n\r\t") {
		return fmt.Errorf("valeur contenant un caractère de contrôle")
	}
	return nil
}

// nullIfEmpty convertit une chaîne vide en NULL SQL, pour distinguer « pas de
// note » d'une note vide.
func nullIfEmpty(s string) interface{} {
	if strings.TrimSpace(s) == "" {
		return nil
	}
	return s
}
