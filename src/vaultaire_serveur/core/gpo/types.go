// Package gpo définit le modèle déclaratif des GPO Vaultaire.
//
// Principe fondateur : une GPO ne contient JAMAIS de code arbitraire.
// Elle est une liste de modules typés, choisis dans un catalogue figé côté
// serveur (voir registry.go), chacun paramétré uniquement par des champs
// décrits dans son schéma. Un administrateur — même compromis — ne peut donc
// pousser que des combinaisons de briques auditées, jamais un script.
//
// Trois notions structurent le package :
//   - le scope (machine / user / both) : qui est la cible de la GPO ;
//   - le catalogue (ModuleSchema) : ce qu'un module sait faire et avec quels champs ;
//   - les garde-fous (guards.go) : ce qu'aucune GPO ne peut faire, codé en dur.
package gpo

import "time"

// Scope désigne le contexte d'application d'une GPO ou d'un module.
type Scope string

const (
	// ScopeMachine : appliqué par le daemon client au démarrage et lors des
	// rafraîchissements périodiques, indépendamment de l'utilisateur connecté.
	ScopeMachine Scope = "machine"
	// ScopeUser : appliqué après une authentification PAM réussie, pour
	// l'utilisateur authentifié uniquement.
	ScopeUser Scope = "user"
	// ScopeBoth : module utilisable dans les deux contextes (le scope effectif
	// est celui de la GPO qui le porte).
	ScopeBoth Scope = "both"
)

// AllScopes retourne les scopes assignables à une GPO.
// ScopeBoth n'est valide que pour un schéma de module, jamais pour une GPO :
// une GPO est soit machine, soit user, sinon la précédence est indécidable.
func AllScopes() []Scope {
	return []Scope{ScopeMachine, ScopeUser}
}

// IsValidPolicyScope vérifie qu'un scope est assignable à une GPO.
func IsValidPolicyScope(s Scope) bool {
	return s == ScopeMachine || s == ScopeUser
}

// FieldType décrit le type d'un champ de paramètre d'un module.
// Chaque type a un validateur dédié dans validate.go : c'est ce qui permet à
// l'interface web de générer les formulaires et au serveur de refuser toute
// valeur hors domaine sans avoir à écrire de validation ad hoc par module.
type FieldType string

const (
	FieldString  FieldType = "string"   // texte court libre, sans caractère de contrôle
	FieldText    FieldType = "text"     // texte multiligne (contenu de fichier, bannière)
	FieldInt     FieldType = "int"      // entier borné par Min/Max
	FieldBool    FieldType = "bool"     // "true" / "false"
	FieldEnum    FieldType = "enum"     // valeur obligatoirement dans Options
	FieldPath    FieldType = "path"     // chemin absolu, filtré par les garde-fous
	FieldMode    FieldType = "mode"     // permissions octales, ex. 0644
	FieldIdent   FieldType = "ident"    // nom d'utilisateur / groupe / unité POSIX
	FieldCron    FieldType = "cron"     // expression cron 5 champs
	FieldEnvName FieldType = "env_name" // nom de variable d'environnement
)

// FieldSchema décrit un champ de paramètre d'un module.
type FieldSchema struct {
	Name     string    `json:"name"`
	Label    string    `json:"label"`
	Type     FieldType `json:"type"`
	Required bool      `json:"required"`
	Default  string    `json:"default,omitempty"`
	// Options est la liste exhaustive des valeurs acceptées pour FieldEnum.
	Options []string `json:"options,omitempty"`
	// Min et Max bornent FieldInt (ignorés si Min == Max == 0).
	Min int `json:"min,omitempty"`
	Max int `json:"max,omitempty"`
	// MaxLen borne la longueur des champs texte (0 = valeur par défaut du type).
	MaxLen int    `json:"max_len,omitempty"`
	Help   string `json:"help,omitempty"`

	// Dynamic marque un champ dont le domaine de valeurs est défini en base
	// (table gpo_restriction) et non dans le code. Les trois champs suivants
	// sont renseignés à la résolution du schéma, depuis les restrictions en
	// vigueur — ils sont vides dans le catalogue de base.
	Dynamic      bool   `json:"dynamic,omitempty"`
	Mode         string `json:"mode,omitempty"`          // list | pattern | free
	AllowPattern string `json:"allow_pattern,omitempty"` // mode pattern
	DenyPattern  string `json:"deny_pattern,omitempty"`  // exclusion, tous modes
}

// IsListMode indique si le champ propose une liste fermée de valeurs (le seul
// cas où l'interface web peut afficher un menu déroulant).
func (f FieldSchema) IsListMode() bool {
	return !f.Dynamic || f.Mode == "" || f.Mode == FieldModeList
}

// ModuleSchema décrit une brique du catalogue : ce qu'elle fait, dans quel
// scope elle est autorisée, dans quel ordre elle s'applique et quels champs
// elle accepte.
type ModuleSchema struct {
	Type        string        `json:"type"`
	Label       string        `json:"label"`
	Category    string        `json:"category"`
	Description string        `json:"description"`
	Scope       Scope         `json:"scope"`
	ApplyOrder  int           `json:"apply_order"`
	Fields      []FieldSchema `json:"fields"`
}

// AllowedInScope indique si le module peut figurer dans une GPO de ce scope.
func (s ModuleSchema) AllowedInScope(policyScope Scope) bool {
	if s.Scope == ScopeBoth {
		return IsValidPolicyScope(policyScope)
	}
	return s.Scope == policyScope
}

// Field retourne le schéma d'un champ par son nom.
func (s ModuleSchema) Field(name string) (FieldSchema, bool) {
	for _, f := range s.Fields {
		if f.Name == name {
			return f, true
		}
	}
	return FieldSchema{}, false
}

// Module est une instance de module dans une GPO : un type du catalogue plus
// ses paramètres. Les paramètres sont stockés en map[string]string parce que
// c'est la forme native des formulaires web comme du JSON en base ; le typage
// réel est porté par le schéma et vérifié à la validation.
type Module struct {
	ID         int               `json:"id,omitempty"`
	PolicyID   int               `json:"policy_id,omitempty"`
	Type       string            `json:"type"`
	Scope      Scope             `json:"scope"`
	ApplyOrder int               `json:"apply_order"`
	Params     map[string]string `json:"params"`
}

// Policy est une GPO complète.
type Policy struct {
	ID          int       `json:"id,omitempty"`
	Name        string    `json:"name"`
	Description string    `json:"description,omitempty"`
	Scope       Scope     `json:"scope"`
	Version     int       `json:"version"`
	Enabled     bool      `json:"enabled"`
	Modules     []Module  `json:"modules"`
	Groups      []string  `json:"groups,omitempty"`
	CreatedAt   time.Time `json:"created_at,omitempty"`
	UpdatedAt   time.Time `json:"updated_at,omitempty"`
}
