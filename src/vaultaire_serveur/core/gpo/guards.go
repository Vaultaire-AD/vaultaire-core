package gpo

import (
	"fmt"
	"path"
	"strings"
)

// Garde-fous du système de GPO.
//
// Toutes les listes consultées ici viennent désormais de la base via
// Restrictions() (voir restrictions.go et defaults.go) et sont éditables par le
// groupe superadmin `vaultaire`. Deux règles restent structurelles, parce
// qu'elles ne sont pas des listes mais des propriétés du modèle :
//
//   - le scope d'un module est déclaré dans le catalogue (registry.go) ; un
//     module machine-only ne peut pas figurer dans une GPO user ;
//   - un refus l'emporte toujours sur une autorisation, pour que l'ouverture
//     large d'un champ reste compatible avec des exclusions fermes.

// userHomePlaceholder est le marqueur substitué par l'agent client par le home
// réel de l'utilisateur cible. Il évite d'écrire des chemins absolus vers
// /home/<user>, qui seraient justes pour un utilisateur et faux pour un autre.
const userHomePlaceholder = "/%h"

// UserHomePlaceholder expose le marqueur de home pour l'interface web.
func UserHomePlaceholder() string { return userHomePlaceholder }

// AllowedValuesFor retourne les valeurs autorisées d'un champ, telles que
// définies en base.
func AllowedValuesFor(moduleType, fieldName string) []string {
	return Restrictions().Values(moduleType, fieldName)
}

// RuleFor retourne la règle de validation d'un champ.
func RuleFor(moduleType, fieldName string) FieldRule {
	return Restrictions().Rule(moduleType, fieldName)
}

// IsForbiddenEnvName indique si une variable d'environnement est interdite.
func IsForbiddenEnvName(name string) bool {
	return Restrictions().EnvIsDenied(name)
}

// DeniedPathPrefixes retourne les préfixes refusés pour un scope.
func DeniedPathPrefixes(scope Scope) []string {
	return Restrictions().PathPrefixes(scope, true)
}

// AllowedPathPrefixes retourne les préfixes autorisés pour un scope.
// Une liste vide signifie « pas de restriction d'emplacement », une liste non
// vide transforme la validation en liste blanche pour ce scope.
func AllowedPathPrefixes(scope Scope) []string {
	return Restrictions().PathPrefixes(scope, false)
}

// CheckPath valide un chemin de fichier pour un scope donné.
//
// Ordre des vérifications :
//  1. forme du chemin (absolu, canonique, sans traversée) — structurel ;
//  2. préfixes refusés du scope et du scope « any » — le refus est prioritaire ;
//  3. préfixes autorisés du scope, s'il en existe au moins un.
func CheckPath(p string, scope Scope) error {
	raw := strings.TrimSpace(p)
	if raw == "" {
		return fmt.Errorf("chemin vide")
	}
	if strings.ContainsAny(raw, "\x00\n\r") {
		return fmt.Errorf("chemin contenant un caractère de contrôle")
	}
	if !strings.HasPrefix(raw, "/") {
		return fmt.Errorf("chemin non absolu : %s", raw)
	}
	clean := path.Clean(raw)
	if clean != raw && clean+"/" != raw {
		return fmt.Errorf("chemin non canonique (traversée ou séparateur en double) : %s", raw)
	}
	if strings.Contains(clean, "/../") || strings.HasSuffix(clean, "/..") {
		return fmt.Errorf("traversée de répertoire interdite : %s", raw)
	}

	rs := Restrictions()
	lower := strings.ToLower(clean)

	for _, prefix := range rs.PathPrefixes(scope, true) {
		lp := strings.ToLower(prefix)
		if lower == strings.TrimSuffix(lp, "/") || strings.HasPrefix(lower, lp) {
			return fmt.Errorf("chemin refusé par une règle de restriction (%s) : %s", prefix, clean)
		}
	}

	allowed := rs.PathPrefixes(scope, false)
	if len(allowed) == 0 {
		return nil
	}
	for _, prefix := range allowed {
		if strings.HasPrefix(lower, strings.ToLower(prefix)) {
			return nil
		}
	}
	return fmt.Errorf("chemin hors des emplacements autorisés pour le scope %s (%s) : %s",
		scope, strings.Join(allowed, ", "), clean)
}

// CheckModuleScope applique la règle de scope : un module réservé au scope
// machine ne peut jamais apparaître dans une GPO user.
//
// C'est la seule restriction non stockée en base, parce qu'elle n'est pas une
// liste : elle découle de la définition du module dans le catalogue. Déplacer un
// module d'un scope à l'autre se fait en modifiant son entrée de catalogue, ce
// qui met automatiquement à jour cette vérification et l'interface web.
func CheckModuleScope(moduleType string, policyScope Scope) error {
	schema, ok := BaseSchemaFor(moduleType)
	if !ok {
		return fmt.Errorf("module inconnu : %s", moduleType)
	}
	if !schema.AllowedInScope(policyScope) {
		return fmt.Errorf("le module %s est réservé au scope %s et ne peut pas figurer dans une GPO %s",
			moduleType, schema.Scope, policyScope)
	}
	return nil
}

// MachineOnlyModuleTypes retourne les types de modules réservés au scope machine.
// Dérivée du catalogue, donc toujours cohérente avec lui.
func MachineOnlyModuleTypes() []string {
	var out []string
	for _, s := range baseCatalog {
		if s.Scope == ScopeMachine {
			out = append(out, s.Type)
		}
	}
	return out
}
