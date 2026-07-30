package gpo

import (
	"fmt"
	"sort"
	"strings"
)

// Résolution des GPO applicables à une cible.
//
// Un client (ou un utilisateur sur un client) appartient généralement à
// plusieurs groupes, chacun pouvant porter plusieurs GPO. Ce fichier fusionne
// ces GPO en un jeu de modules effectif, ordonné et sans contradiction.
//
// Règles de précédence :
//   - Les GPO machine forment la baseline ; les GPO user s'appliquent par-dessus.
//   - Un module de catégorie sécurité (SSH, sudo, sysctl) n'existe qu'en scope
//     machine : une GPO user ne peut donc structurellement pas le surcharger.
//     Ce n'est pas une règle de fusion mais une conséquence du catalogue,
//     ce qui la rend impossible à contourner.
//   - Deux GPO du même scope qui règlent la même clé naturelle sont un conflit
//     signalé, pas résolu silencieusement : deviner laquelle « gagne » produirait
//     un parc dont la configuration réelle est imprévisible.

// EffectiveModule est un module retenu après résolution, avec sa provenance.
type EffectiveModule struct {
	Module     Module
	PolicyName string
	PolicyID   int
}

// Conflict décrit deux modules concurrents sur la même clé naturelle.
type Conflict struct {
	Identity string
	First    EffectiveModule
	Second   EffectiveModule
}

// Error rend le conflit lisible pour un administrateur.
func (c Conflict) Error() string {
	return fmt.Sprintf("%s est réglé à la fois par la GPO %q et par la GPO %q",
		c.Identity, c.First.PolicyName, c.Second.PolicyName)
}

// ResolveResult est le résultat d'une résolution.
type ResolveResult struct {
	// Machine contient les modules de scope machine, dans l'ordre d'application.
	Machine []EffectiveModule
	// User contient les modules de scope user, dans l'ordre d'application.
	User []EffectiveModule
	// Conflicts liste les collisions détectées. Non vide n'empêche pas la
	// lecture du résultat : les modules en conflit sont conservés pour que
	// l'administrateur voie exactement ce qui s'oppose.
	Conflicts []Conflict
	// Skipped liste les GPO écartées et pourquoi (désactivées, vides).
	Skipped map[string]string
}

// HasConflicts indique si la résolution a détecté au moins un conflit.
func (r ResolveResult) HasConflicts() bool { return len(r.Conflicts) > 0 }

// Resolve fusionne un ensemble de GPO en un jeu de modules effectif.
//
// Les GPO désactivées sont ignorées. L'ordre d'entrée n'a pas d'influence sur
// le résultat : le tri final est déterminé par ApplyOrder puis par la clé
// naturelle du module.
func Resolve(policies []Policy) ResolveResult {
	res := ResolveResult{Skipped: map[string]string{}}

	// Tri des GPO par nom pour que la détection de conflit désigne toujours la
	// même « première » GPO, quel que soit l'ordre de lecture en base.
	ordered := append([]Policy(nil), policies...)
	sort.SliceStable(ordered, func(i, j int) bool { return ordered[i].Name < ordered[j].Name })

	seenMachine := map[string]EffectiveModule{}
	seenUser := map[string]EffectiveModule{}

	for _, p := range ordered {
		if !p.Enabled {
			res.Skipped[p.Name] = "GPO désactivée"
			continue
		}
		if len(p.Modules) == 0 {
			res.Skipped[p.Name] = "GPO sans module"
			continue
		}
		for _, m := range p.Modules {
			eff := EffectiveModule{Module: m, PolicyName: p.Name, PolicyID: p.ID}

			// Filet de sécurité : même si la base contenait une incohérence
			// (module machine-only rattaché à une GPO user), la résolution le
			// refuse. Le contrôle existe déjà à l'écriture ; on ne fait pas
			// confiance à une seule couche pour une garantie de privilège.
			if err := CheckModuleScope(m.Type, p.Scope); err != nil {
				res.Skipped[p.Name+"/"+m.Type] = err.Error()
				continue
			}

			identity := moduleIdentity(m)
			target := &res.Machine
			seen := seenMachine
			if p.Scope == ScopeUser {
				target = &res.User
				seen = seenUser
			}
			if identity != "" {
				if previous, exists := seen[identity]; exists {
					res.Conflicts = append(res.Conflicts, Conflict{
						Identity: identity, First: previous, Second: eff,
					})
					continue
				}
				seen[identity] = eff
			}
			*target = append(*target, eff)
		}
	}

	sortEffective(res.Machine)
	sortEffective(res.User)
	return res
}

// sortEffective applique l'ordre d'application aux modules effectifs.
func sortEffective(list []EffectiveModule) {
	sort.SliceStable(list, func(i, j int) bool {
		a, b := list[i].Module, list[j].Module
		if a.ApplyOrder != b.ApplyOrder {
			return a.ApplyOrder < b.ApplyOrder
		}
		if a.Type != b.Type {
			return a.Type < b.Type
		}
		return moduleIdentity(a) < moduleIdentity(b)
	})
}

// BuildPolicyForDelivery construit la GPO fusionnée à transmettre pour un scope
// donné. Elle n'est pas persistée : c'est une vue calculée, dont Version est le
// cumul des versions sources afin qu'un changement dans n'importe quelle GPO
// contributrice modifie le hash et déclenche une réapplication côté agent.
func BuildPolicyForDelivery(scope Scope, policies []Policy) (Policy, error) {
	if !IsValidPolicyScope(scope) {
		return Policy{}, fmt.Errorf("scope invalide : %s", scope)
	}
	res := Resolve(policies)
	if res.HasConflicts() {
		var msgs []string
		for _, c := range res.Conflicts {
			msgs = append(msgs, c.Error())
		}
		return Policy{}, fmt.Errorf("résolution impossible : %s", strings.Join(msgs, " ; "))
	}

	source := res.Machine
	if scope == ScopeUser {
		source = res.User
	}

	merged := Policy{Name: "effective_" + string(scope), Scope: scope, Enabled: true}
	contributors := map[int]int{}
	for _, eff := range source {
		merged.Modules = append(merged.Modules, eff.Module)
		contributors[eff.PolicyID] = 0
	}
	for _, p := range policies {
		if _, used := contributors[p.ID]; used {
			merged.Version += p.Version
		}
	}
	SortModules(merged.Modules)
	return merged, nil
}
