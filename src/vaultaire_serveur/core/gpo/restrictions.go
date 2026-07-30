package gpo

import (
	"fmt"
	"regexp"
	"sort"
	"strings"
	"sync"
)

// Restrictions GPO : listes d'autorisation, règles de champ, règles de chemin et
// variables d'environnement interdites.
//
// Ces restrictions ne sont plus codées en dur : elles vivent en base et sont
// éditables par les membres du groupe superadmin `vaultaire`. Ce fichier ne
// connaît pas la base — il définit la forme des restrictions, un fournisseur
// injectable et un cache. La couche base (core/database/db_gpo) enregistre son
// fournisseur au démarrage, ce qui évite un cycle d'import : core/gpo reste le
// socle sans dépendance, db_gpo dépend de lui.
//
// Conséquence assumée du choix « tout éditable » : le groupe `vaultaire` peut
// autoriser n'importe quel chemin, service ou variable, donc il dispose de fait
// d'un pouvoir root sur l'ensemble du parc. Les contreparties sont ici :
//   - le fournisseur par défaut reproduit exactement l'ancien socle en dur, donc
//     une base neuve démarre avec les mêmes protections qu'avant ;
//   - toute modification est journalisée en SECURITY avec son auteur (côté db_gpo) ;
//   - le mode `deny` permet de reconstruire soi-même un socle non contournable
//     par les autres administrateurs.

// Modes de validation d'un champ.
const (
	// FieldModeList : la valeur doit figurer dans la liste d'autorisation en base.
	FieldModeList = "list"
	// FieldModePattern : la valeur doit satisfaire allow_pattern (et éviter deny_pattern).
	// C'est le mode qui permet les besoins custom — un service de monitoring
	// maison, par exemple — sans énumérer chaque valeur à l'avance.
	FieldModePattern = "pattern"
	// FieldModeFree : aucune contrainte de domaine au-delà du type et de deny_pattern.
	FieldModeFree = "free"
)

// AllFieldModes retourne les modes assignables à un champ.
func AllFieldModes() []string { return []string{FieldModeList, FieldModePattern, FieldModeFree} }

// IsValidFieldMode indique si un mode de champ est reconnu.
func IsValidFieldMode(mode string) bool {
	switch mode {
	case FieldModeList, FieldModePattern, FieldModeFree:
		return true
	}
	return false
}

// PathScopeAny étend Scope avec une portée « any », pour les règles de chemin
// valables dans les deux contextes.
const PathScopeAny = "any"

// FieldRule est la règle de validation d'un champ d'un module.
type FieldRule struct {
	ModuleType   string `json:"module_type"`
	FieldName    string `json:"field_name"`
	Mode         string `json:"mode"`
	AllowPattern string `json:"allow_pattern,omitempty"`
	DenyPattern  string `json:"deny_pattern,omitempty"`
	Note         string `json:"note,omitempty"`
	UpdatedBy    string `json:"updated_by,omitempty"`
}

// PathRule est une règle de chemin : autorisation ou refus d'un préfixe, pour un
// scope donné (machine, user, ou any).
type PathRule struct {
	Scope  string `json:"scope"`
	Deny   bool   `json:"deny"`
	Prefix string `json:"prefix"`
	Note   string `json:"note,omitempty"`
}

// EnvRule est une variable d'environnement explicitement interdite.
type EnvRule struct {
	Name string `json:"name"`
	Note string `json:"note,omitempty"`
}

// AllowedValue est une entrée de liste d'autorisation pour un champ.
type AllowedValue struct {
	ModuleType string `json:"module_type"`
	FieldName  string `json:"field_name"`
	Value      string `json:"value"`
	Label      string `json:"label,omitempty"`
}

// PayloadKind décrit la nature du contenu porté par une définition de valeur.
//
// Certains champs ne se contentent pas d'un nom : un « jeu de commandes sudo »,
// par exemple, n'a de sens que si l'on sait quelles commandes il autorise. Pour
// ces champs, la valeur utilisée dans une GPO est le NOM d'une définition, et le
// contenu réel vit à côté, dans la même table de restrictions.
//
// Le mécanisme est générique par construction : ajouter un futur module dont un
// champ a besoin d'un contenu se fait en déclarant un nouveau PayloadKind et son
// validateur dans payloadValidators — sans toucher à la couche base, à
// l'interface web ni au reste du catalogue.
type PayloadKind string

const (
	// PayloadNone : la valeur est un simple nom, sans contenu associé
	// (unités systemd, clés sysctl, paquets, identifiants de tâche).
	PayloadNone PayloadKind = ""
	// PayloadCommandList : une commande par ligne, ou le mot-clé ALL.
	// Utilisé par les jeux de commandes sudo.
	PayloadCommandList PayloadKind = "command_list"
)

// ValueDefinition est une valeur nommée accompagnée de son contenu.
type ValueDefinition struct {
	ModuleType string      `json:"module_type"`
	FieldName  string      `json:"field_name"`
	Name       string      `json:"name"`
	Kind       PayloadKind `json:"kind"`
	Payload    string      `json:"payload"`
	Note       string      `json:"note,omitempty"`
	UpdatedBy  string      `json:"updated_by,omitempty"`
}

// Lines découpe la charge utile en lignes utiles (vides et commentaires exclus).
func (d ValueDefinition) Lines() []string {
	var out []string
	for _, l := range strings.Split(d.Payload, "\n") {
		t := strings.TrimSpace(l)
		if t == "" || strings.HasPrefix(t, "#") {
			continue
		}
		out = append(out, t)
	}
	return out
}

// RestrictionSet est l'ensemble complet des restrictions en vigueur.
type RestrictionSet struct {
	// AllowedValues est indexé par clé "module_type/field_name".
	AllowedValues map[string][]AllowedValue
	// Definitions est indexé par clé "module_type/field_name" et contient les
	// valeurs nommées porteuses d'un contenu.
	Definitions map[string][]ValueDefinition
	// FieldRules est indexé par clé "module_type/field_name".
	FieldRules map[string]FieldRule
	// PathRules regroupe autorisations et refus de préfixes de chemins.
	PathRules []PathRule
	// EnvDenied liste les variables d'environnement interdites.
	EnvDenied []EnvRule
}

// DefinitionsFor retourne les définitions d'un champ.
func (rs RestrictionSet) DefinitionsFor(moduleType, fieldName string) []ValueDefinition {
	return rs.Definitions[FieldKey(moduleType, fieldName)]
}

// Definition retourne une définition par son nom.
func (rs RestrictionSet) Definition(moduleType, fieldName, name string) (ValueDefinition, bool) {
	for _, d := range rs.DefinitionsFor(moduleType, fieldName) {
		if d.Name == name {
			return d, true
		}
	}
	return ValueDefinition{}, false
}

// FieldKey construit la clé d'indexation d'un champ.
func FieldKey(moduleType, fieldName string) string { return moduleType + "/" + fieldName }

// Rule retourne la règle d'un champ, ou une règle en mode liste par défaut.
func (rs RestrictionSet) Rule(moduleType, fieldName string) FieldRule {
	if r, ok := rs.FieldRules[FieldKey(moduleType, fieldName)]; ok && IsValidFieldMode(r.Mode) {
		return r
	}
	return FieldRule{ModuleType: moduleType, FieldName: fieldName, Mode: FieldModeList}
}

// Values retourne les valeurs autorisées d'un champ, triées et dédupliquées.
//
// Les deux sources sont fusionnées : les entrées de liste simple et les noms des
// définitions porteuses de contenu. Un champ n'utilise en pratique qu'une des
// deux, mais fusionner évite à l'appelant d'avoir à savoir laquelle.
func (rs RestrictionSet) Values(moduleType, fieldName string) []string {
	key := FieldKey(moduleType, fieldName)
	seen := map[string]bool{}
	var out []string
	add := func(v string) {
		if v == "" || seen[v] {
			return
		}
		seen[v] = true
		out = append(out, v)
	}
	for _, e := range rs.AllowedValues[key] {
		add(e.Value)
	}
	for _, d := range rs.Definitions[key] {
		add(d.Name)
	}
	sort.Strings(out)
	return out
}

// EnvIsDenied indique si une variable d'environnement est interdite.
func (rs RestrictionSet) EnvIsDenied(name string) bool {
	upper := strings.ToUpper(strings.TrimSpace(name))
	for _, e := range rs.EnvDenied {
		if strings.ToUpper(e.Name) == upper {
			return true
		}
	}
	return false
}

// PathPrefixes retourne les préfixes applicables à un scope : ceux du scope
// demandé plus ceux marqués « any ».
func (rs RestrictionSet) PathPrefixes(scope Scope, deny bool) []string {
	var out []string
	for _, r := range rs.PathRules {
		if r.Deny != deny {
			continue
		}
		if r.Scope != PathScopeAny && r.Scope != string(scope) {
			continue
		}
		out = append(out, r.Prefix)
	}
	sort.Strings(out)
	return out
}

// RestrictionProvider est la source des restrictions. Implémenté par la couche
// base ; remplaçable en test.
type RestrictionProvider interface {
	LoadRestrictions() (RestrictionSet, error)
}

var (
	providerMu   sync.RWMutex
	provider     RestrictionProvider
	cacheMu      sync.RWMutex
	cached       *RestrictionSet
	cacheErrOnce string
)

// SetRestrictionProvider installe la source des restrictions et vide le cache.
// Appelée une fois au démarrage par la couche base.
func SetRestrictionProvider(p RestrictionProvider) {
	providerMu.Lock()
	provider = p
	providerMu.Unlock()
	InvalidateRestrictionCache()
}

// InvalidateRestrictionCache force une relecture au prochain accès.
// À appeler après toute écriture sur les restrictions, sinon les validations
// continueraient d'utiliser l'ancien jeu de règles jusqu'au redémarrage.
func InvalidateRestrictionCache() {
	cacheMu.Lock()
	cached = nil
	cacheErrOnce = ""
	cacheMu.Unlock()
}

// Restrictions retourne les restrictions en vigueur.
//
// Le résultat est mis en cache : la validation d'un module interroge plusieurs
// règles, et une GPO peut porter de nombreux modules — relire la base à chaque
// champ serait coûteux pour rien. Le cache est invalidé explicitement à chaque
// écriture (voir InvalidateRestrictionCache).
//
// Si aucun fournisseur n'est installé (outils CLI hors serveur, tests unitaires)
// ou si la lecture échoue, on retombe sur DefaultRestrictions() : le socle
// historique. Une panne de base ne doit pas faire disparaître les restrictions.
func Restrictions() RestrictionSet {
	cacheMu.RLock()
	if cached != nil {
		rs := *cached
		cacheMu.RUnlock()
		return rs
	}
	cacheMu.RUnlock()

	providerMu.RLock()
	p := provider
	providerMu.RUnlock()

	loaded := DefaultRestrictions()
	if p != nil {
		if rs, err := p.LoadRestrictions(); err == nil {
			loaded = rs
		} else {
			cacheMu.Lock()
			cacheErrOnce = err.Error()
			cacheMu.Unlock()
		}
	}

	cacheMu.Lock()
	cached = &loaded
	cacheMu.Unlock()
	return loaded
}

// LastRestrictionError retourne la dernière erreur de chargement, pour affichage
// dans l'interface d'administration (le repli silencieux sur les valeurs par
// défaut serait trompeur sans cette information).
func LastRestrictionError() string {
	cacheMu.RLock()
	defer cacheMu.RUnlock()
	return cacheErrOnce
}

// patternCache évite de recompiler les mêmes expressions régulières à chaque
// champ validé.
var (
	patternMu    sync.RWMutex
	patternCache = map[string]*regexp.Regexp{}
)

// compilePattern compile et mémorise une expression régulière.
func compilePattern(pattern string) (*regexp.Regexp, error) {
	patternMu.RLock()
	re, ok := patternCache[pattern]
	patternMu.RUnlock()
	if ok {
		return re, nil
	}
	re, err := regexp.Compile(pattern)
	if err != nil {
		return nil, err
	}
	patternMu.Lock()
	patternCache[pattern] = re
	patternMu.Unlock()
	return re, nil
}

// ValidatePatternSyntax vérifie qu'une expression régulière est compilable.
// Utilisée par l'interface d'administration avant enregistrement : un motif
// invalide enregistré en base bloquerait ensuite toute validation du champ.
func ValidatePatternSyntax(pattern string) error {
	if strings.TrimSpace(pattern) == "" {
		return nil
	}
	if _, err := regexp.Compile(pattern); err != nil {
		return fmt.Errorf("expression régulière invalide : %v", err)
	}
	return nil
}

// checkAgainstRule valide une valeur contre la règle d'un champ.
//
// L'ordre est important : le refus l'emporte toujours sur l'autorisation, quel
// que soit le mode. C'est ce qui permet à un administrateur d'ouvrir largement
// un champ (mode motif ou libre) tout en gardant des exclusions fermes.
func checkAgainstRule(rule FieldRule, allowed []string, value string) error {
	if rule.DenyPattern != "" {
		re, err := compilePattern(rule.DenyPattern)
		if err != nil {
			return fmt.Errorf("motif de refus illisible en base (%s) : %v", rule.DenyPattern, err)
		}
		if re.MatchString(value) {
			return fmt.Errorf("valeur %q refusée par le motif d'exclusion %s", value, rule.DenyPattern)
		}
	}

	switch rule.Mode {
	case FieldModeFree:
		return nil

	case FieldModePattern:
		if rule.AllowPattern == "" {
			return fmt.Errorf("champ en mode motif sans motif d'autorisation : configuration incomplète")
		}
		re, err := compilePattern(rule.AllowPattern)
		if err != nil {
			return fmt.Errorf("motif d'autorisation illisible en base (%s) : %v", rule.AllowPattern, err)
		}
		if !re.MatchString(value) {
			return fmt.Errorf("valeur %q non conforme au motif autorisé %s", value, rule.AllowPattern)
		}
		return nil

	default: // FieldModeList
		for _, a := range allowed {
			if a == value {
				return nil
			}
		}
		if len(allowed) == 0 {
			return fmt.Errorf("aucune valeur autorisée n'est définie pour ce champ : ajoutez-en depuis Admin → GPO → Restrictions")
		}
		return fmt.Errorf("valeur %q hors liste autorisée", value)
	}
}
