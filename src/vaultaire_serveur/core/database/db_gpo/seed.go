package dbgpo

import (
	"database/sql"
	"embed"
	"fmt"
	"regexp"
	"strings"

	"vaultaire/core/gpo"
	"vaultaire/core/logs"
)

// Peuplement initial des restrictions GPO.
//
// Deux garanties tiennent tout ce fichier :
//
//  1. Les valeurs ne vivent nulle part dans le code Go. Elles sont dans
//     seed/gpo_seed.sql, embarqué dans le binaire. Le code Go ne connaît que la
//     structure des champs (core/gpo/dynamicfields.go), jamais leur contenu.
//
//  2. Une instruction de peuplement n'est exécutée que si sa table cible vient
//     d'être créée. C'est le point crucial : une valeur supprimée depuis
//     l'interface web ne peut pas réapparaître au redémarrage, puisque sa table
//     existait déjà et qu'aucune instruction ne la vise. Un marqueur en base
//     n'aurait pas suffi — il est lui-même supprimable.
//
// Cette granularité par table permet aussi de rattraper une base créée par une
// version antérieure : si gpo_value_definition est la seule table manquante,
// seules les définitions sont écrites, sans toucher aux listes existantes.

//go:embed seed/gpo_seed.sql
var seedFS embed.FS

const seedFilePath = "seed/gpo_seed.sql"

// restrictionTables liste les tables de restrictions, dans l'ordre de création.
var restrictionTables = []string{"gpo_restriction", "gpo_field_rule", "gpo_value_definition"}

var (
	// lineCommentRe retire les commentaires SQL en fin ou en début de ligne.
	lineCommentRe = regexp.MustCompile(`(?m)^\s*--.*$`)
	// insertTargetRe extrait la table visée par une instruction INSERT.
	insertTargetRe = regexp.MustCompile(`(?is)^\s*INSERT\s+(?:IGNORE\s+)?INTO\s+([A-Za-z0-9_]+)`)
)

// tableExists indique si une table existe dans la base courante.
func tableExists(db *sql.DB, table string) (bool, error) {
	var count int
	err := db.QueryRow(
		`SELECT COUNT(*) FROM information_schema.tables
		 WHERE table_schema = DATABASE() AND table_name = ?`, table,
	).Scan(&count)
	if err != nil {
		return false, fmt.Errorf("vérification de l'existence de %s impossible : %v", table, err)
	}
	return count > 0, nil
}

// missingRestrictionTables retourne les tables de restrictions absentes.
// Appelée AVANT la création des tables : c'est ce qui distingue un premier
// démarrage d'un redémarrage.
func missingRestrictionTables(db *sql.DB) (map[string]bool, error) {
	missing := map[string]bool{}
	for _, table := range restrictionTables {
		exists, err := tableExists(db, table)
		if err != nil {
			return nil, err
		}
		if !exists {
			missing[table] = true
		}
	}
	return missing, nil
}

// splitSQLStatements découpe le fichier de peuplement en instructions.
//
// Le découpage respecte les chaînes entre apostrophes (les contenus de
// définitions en contiennent, avec des séquences \n échappées) : un point-virgule
// à l'intérieur d'une chaîne ne termine pas l'instruction.
func splitSQLStatements(script string) []string {
	script = lineCommentRe.ReplaceAllString(script, "")

	var statements []string
	var current strings.Builder
	inString := false

	for i := 0; i < len(script); i++ {
		c := script[i]
		if inString {
			current.WriteByte(c)
			switch c {
			case '\\':
				// Séquence échappée : le caractère suivant est littéral, y compris
				// une apostrophe. Sans ça, '\'' fermerait la chaîne à tort.
				if i+1 < len(script) {
					i++
					current.WriteByte(script[i])
				}
			case '\'':
				inString = false
			}
			continue
		}
		switch c {
		case '\'':
			inString = true
			current.WriteByte(c)
		case ';':
			if s := strings.TrimSpace(current.String()); s != "" {
				statements = append(statements, s)
			}
			current.Reset()
		default:
			current.WriteByte(c)
		}
	}
	if s := strings.TrimSpace(current.String()); s != "" {
		statements = append(statements, s)
	}
	return statements
}

// seedStatement est une instruction de peuplement et sa table cible.
type seedStatement struct {
	Table string
	SQL   string
}

// loadSeedStatements lit et découpe le script de peuplement embarqué.
func loadSeedStatements() ([]seedStatement, error) {
	raw, err := seedFS.ReadFile(seedFilePath)
	if err != nil {
		return nil, fmt.Errorf("script de peuplement GPO illisible : %v", err)
	}

	var out []seedStatement
	for _, stmt := range splitSQLStatements(string(raw)) {
		match := insertTargetRe.FindStringSubmatch(stmt)
		if match == nil {
			return nil, fmt.Errorf("instruction de peuplement non reconnue (INSERT attendu) : %.80s…", stmt)
		}
		out = append(out, seedStatement{Table: strings.ToLower(match[1]), SQL: stmt})
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("script de peuplement GPO vide")
	}
	return out, nil
}

// runSeed exécute les instructions de peuplement visant les tables indiquées.
//
// tables nil signifie « toutes » : utilisé par la réinitialisation, qui a purgé
// les tables au préalable.
func runSeed(db *sql.DB, tables map[string]bool) error {
	statements, err := loadSeedStatements()
	if err != nil {
		return err
	}

	applied := 0
	perTable := map[string]int{}
	for _, stmt := range statements {
		if tables != nil && !tables[stmt.Table] {
			continue
		}
		if _, err := db.Exec(stmt.SQL); err != nil {
			logs.Write_LogCode("ERROR", logs.CodeDBGeneric,
				"gpo: peuplement de "+stmt.Table+" échoué : "+err.Error())
			return fmt.Errorf("gpo: peuplement de %s échoué : %v", stmt.Table, err)
		}
		applied++
		perTable[stmt.Table]++
	}

	if applied > 0 {
		var parts []string
		for _, table := range restrictionTables {
			if n := perTable[table]; n > 0 {
				parts = append(parts, fmt.Sprintf("%s: %d", table, n))
			}
		}
		logs.Write_Log("INFO", "gpo: peuplement initial des restrictions appliqué ("+strings.Join(parts, ", ")+")")
		gpo.InvalidateRestrictionCache()
	}
	return nil
}

// ensureFieldRules garantit qu'un champ déclaré a toujours une règle en base.
//
// Exécuté à CHAQUE démarrage, contrairement au reste du peuplement, et c'est
// volontaire : une règle de champ n'est pas une valeur, c'est la définition de la
// façon dont le champ se valide. Un champ sans règle retombe en mode liste avec
// une liste vide, donc refuse tout — un nouveau champ ajouté au catalogue
// casserait son module sur les bases existantes.
//
// Les INSERT du script sont en INSERT IGNORE : une règle déjà présente, y compris
// modifiée par un administrateur, n'est jamais écrasée. Et comme l'interface ne
// permet pas de supprimer une règle (seulement de la modifier), il n'y a pas de
// risque de rétablir un réglage volontairement retiré.
func ensureFieldRules(db *sql.DB) error {
	statements, err := loadSeedStatements()
	if err != nil {
		return err
	}
	for _, stmt := range statements {
		if stmt.Table != "gpo_field_rule" {
			continue
		}
		res, err := db.Exec(stmt.SQL)
		if err != nil {
			logs.Write_LogCode("ERROR", logs.CodeDBGeneric,
				"gpo: vérification des règles de champ échouée : "+err.Error())
			return fmt.Errorf("gpo: vérification des règles de champ échouée : %v", err)
		}
		if affected, _ := res.RowsAffected(); affected > 0 {
			logs.Write_Log("INFO", fmt.Sprintf(
				"gpo: %d règle(s) de champ manquante(s) créée(s) avec leur mode initial", affected))
			gpo.InvalidateRestrictionCache()
		}
	}
	return checkDeclaredFieldsHaveRules(db)
}

// checkDeclaredFieldsHaveRules signale un champ déclaré au catalogue mais absent
// du script de peuplement — une incohérence de développement qui se traduirait
// par un module inutilisable, et qu'il vaut mieux voir dans les journaux au
// démarrage que découvrir en production.
func checkDeclaredFieldsHaveRules(db *sql.DB) error {
	for _, field := range gpo.DynamicFields() {
		var count int
		err := db.QueryRow(
			`SELECT COUNT(*) FROM gpo_field_rule WHERE module_type = ? AND field_name = ?`,
			field.ModuleType, field.FieldName,
		).Scan(&count)
		if err != nil {
			return fmt.Errorf("gpo: vérification de la règle %s/%s impossible : %v",
				field.ModuleType, field.FieldName, err)
		}
		if count == 0 {
			logs.Write_Log("WARNING", fmt.Sprintf(
				"gpo: le champ %s/%s est déclaré au catalogue mais n'a pas de règle dans le script de peuplement — "+
					"il refusera toute valeur jusqu'à ce qu'une règle soit définie dans Admin → GPO → Restrictions",
				field.ModuleType, field.FieldName))
		}
	}
	return nil
}

// pruneOrphanAllowValues supprime les valeurs de liste simple posées sur un champ
// qui porte désormais des définitions à contenu.
//
// Rattrapage nécessaire pour les bases créées par une version antérieure, où les
// jeux de commandes sudo étaient de simples noms. Ces lignes apparaîtraient
// encore dans le menu déroulant du module alors qu'aucune définition ne leur
// correspond : la GPO serait sélectionnable puis refusée à l'enregistrement.
func pruneOrphanAllowValues(db *sql.DB) error {
	for _, field := range gpo.DynamicFields() {
		if !field.HasPayload() {
			continue
		}
		res, err := db.Exec(
			`DELETE FROM gpo_restriction WHERE kind = ? AND module_type = ? AND field_name = ?`,
			KindAllowValue, field.ModuleType, field.FieldName)
		if err != nil {
			return fmt.Errorf("gpo: nettoyage des valeurs orphelines de %s/%s impossible : %v",
				field.ModuleType, field.FieldName, err)
		}
		if affected, _ := res.RowsAffected(); affected > 0 {
			logs.Write_Log("INFO", fmt.Sprintf(
				"gpo: %d valeur(s) de liste simple retirée(s) de %s/%s — ce champ utilise désormais des définitions à contenu",
				affected, field.ModuleType, field.FieldName))
			gpo.InvalidateRestrictionCache()
		}
	}
	return nil
}
