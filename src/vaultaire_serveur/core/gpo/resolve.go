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
//   - Un conflit n'écarte que les modules qui s'opposent (TO-DO 222) : le reste
//     de la politique est livré, et le conflit est rangé pour `vlt gpo status`.
//     Avant, il faisait refuser la politique ENTIÈRE de la machine — plus rien
//     n'y était appliqué ni corrigé, y compris par les GPO sans rapport.
//   - Deux GPO qui règlent la même clé de la MÊME façon (même type, mêmes
//     paramètres) ne s'opposent pas : le module est livré une fois. Si l'une
//     est en enforce, il est en enforce — l'audit de l'autre ne retire pas une
//     correction que la première demande.

// EffectiveModule est un module retenu après résolution, avec sa provenance.
type EffectiveModule struct {
	Module     Module
	PolicyName string
	PolicyID   int
	// AussiPar : les autres GPO qui portent ce même réglage à l'identique
	// (TO-DO 222). Leur version entre dans celle de la politique livrée.
	AussiPar []int
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
	// Conflicts liste les collisions détectées. Les modules en conflit ne sont
	// PAS dans Machine ni User : écartés, ils sont décrits ici, pour que
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

	// Par identité : l'index du module retenu dans sa liste, et les identités
	// en conflit, écartées une fois toutes les GPO lues.
	seenMachine := map[string]int{}
	seenUser := map[string]int{}
	enConflit := map[Scope]map[string]bool{ScopeMachine: {}, ScopeUser: {}}

	for _, p := range ordered {
		if !p.Enabled {
			res.Skipped[p.Name] = "GPO désactivée"
			continue
		}
		if len(p.Modules) == 0 {
			res.Skipped[p.Name] = "GPO sans module"
			continue
		}
		// Le mode de dérive descend de la GPO vers chacun de ses modules.
		//
		// C'est le seul endroit où la provenance est encore connue : après la
		// fusion, un module effectif n'est plus rattaché à sa GPO d'origine, et
		// une machine qui reçoit une GPO en audit et une autre en enforce ne
		// pourrait plus appliquer la règle de chacune.
		//
		// Écrit UNIQUEMENT quand il s'écarte du défaut : voir le commentaire de
		// Module.DriftMode — un parc entièrement en enforce garde ainsi les
		// empreintes qu'il avait déjà, et ne retélécharge rien.
		mode := p.EffectiveDriftMode()

		for _, m := range p.Modules {
			if mode != DefaultDriftMode {
				m.DriftMode = mode
			}
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
				if i, exists := seen[identity]; exists {
					previous := &(*target)[i]
					if memeReglage(previous.Module, m) {
						// Le même réglage : livré une fois, enforce l'emporte.
						if m.DriftMode == "" || previous.Module.DriftMode == "" {
							previous.Module.DriftMode = ""
						}
						if p.ID != previous.PolicyID {
							previous.AussiPar = append(previous.AussiPar, p.ID)
						}
						continue
					}
					res.Conflicts = append(res.Conflicts, Conflict{
						Identity: identity, First: *previous, Second: eff,
					})
					enConflit[p.Scope][identity] = true
					continue
				}
				seen[identity] = len(*target)
			}
			*target = append(*target, eff)
		}
	}

	res.Machine = sansConflit(res.Machine, enConflit[ScopeMachine])
	res.User = sansConflit(res.User, enConflit[ScopeUser])
	sortEffective(res.Machine)
	sortEffective(res.User)
	return res
}

// memeReglage : même type et mêmes paramètres. Le mode de dérive n'en fait pas
// partie — c'est ce que Resolve arbitre.
func memeReglage(a, b Module) bool {
	if a.Type != b.Type || len(a.Params) != len(b.Params) {
		return false
	}
	for k, v := range a.Params {
		if w, ok := b.Params[k]; !ok || w != v {
			return false
		}
	}
	return true
}

// sansConflit retire les modules dont l'identité est en conflit — le PREMIER
// retenu compris : garder l'un des deux reviendrait à désigner un gagnant par
// l'ordre alphabétique des noms de GPO.
func sansConflit(liste []EffectiveModule, enConflit map[string]bool) []EffectiveModule {
	if len(enConflit) == 0 {
		return liste
	}
	out := liste[:0]
	for _, e := range liste {
		if !enConflit[moduleIdentity(e.Module)] {
			out = append(out, e)
		}
	}
	return out
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
//
// Les conflits du scope sont rendus à côté de la politique, qui ne porte pas
// les modules en conflit (TO-DO 222) : à l'appelant de les ranger et de les
// journaliser.
func BuildPolicyForDelivery(scope Scope, policies []Policy) (Policy, []Conflict, error) {
	if !IsValidPolicyScope(scope) {
		return Policy{}, nil, fmt.Errorf("scope invalide : %s", scope)
	}
	res := Resolve(policies)

	source := res.Machine
	if scope == ScopeUser {
		source = res.User
	}
	// Les appelants passent les GPO d'un seul scope : les conflits sont les siens.
	conflits := res.Conflicts

	merged := Policy{Name: "effective_" + string(scope), Scope: scope, Enabled: true}
	contributors := map[int]int{}
	for _, eff := range source {
		merged.Modules = append(merged.Modules, eff.Module)
		contributors[eff.PolicyID] = 0
		for _, id := range eff.AussiPar {
			contributors[id] = 0
		}
	}
	// Une GPO dont les modules sont tous écartés compte quand même : la
	// modifier pour lever le conflit doit changer l'empreinte.
	for _, c := range conflits {
		contributors[c.First.PolicyID] = 0
		contributors[c.Second.PolicyID] = 0
	}
	for _, p := range policies {
		if _, used := contributors[p.ID]; used {
			merged.Version += p.Version
		}
	}
	SortModules(merged.Modules)
	return merged, conflits, nil
}

// DecrireConflits : une ligne lisible, pour le journal et `gpo status`.
func DecrireConflits(conflits []Conflict) string {
	var msgs []string
	for _, c := range conflits {
		msgs = append(msgs, c.Error())
	}
	return strings.Join(msgs, " ; ")
}
