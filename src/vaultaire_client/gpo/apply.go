package gpo

import (
	"fmt"
	"strings"

	"vaultaire_client/logs"
)

// Moteur d'application des politiques.
//
// Trois responsabilités, volontairement séparées des appliqueurs eux-mêmes :
//  1. décider quels modules doivent être appliqués (comparaison d'empreintes) ;
//  2. les appliquer dans l'ordre imposé par le catalogue ;
//  3. produire le rapport remonté au serveur en trame 05_12.
//
// POINT D'EXTENSION — pour ajouter un module :
// écrire son appliqueur dans appliers_*.go et l'enregistrer dans le registre
// (voir registry.go). Rien à changer ici : un module inconnu est signalé
// « skipped » avec sa raison, jamais ignoré silencieusement.

// Result est le résultat d'application d'un module.
type Result string

const (
	ResultApplied   Result = "applied"
	ResultUnchanged Result = "unchanged"
	ResultSkipped   Result = "skipped"
	ResultFailed    Result = "failed"
)

// Status est le statut global d'une application.
type Status string

const (
	StatusApplied Status = "applied"
	StatusPartial Status = "partial"
	StatusFailed  Status = "failed"
)

// ModuleOutcome est le résultat d'un module, tel que rapporté.
type ModuleOutcome struct {
	ModuleType string
	StateKey   string
	Result     Result
	Detail     string
}

// Report est le résultat complet d'une application.
type Report struct {
	Scope       string
	Username    string
	Fingerprint string
	Status      Status
	Modules     []ModuleOutcome
}

// Counts compte les résultats par catégorie.
func (r Report) Counts() map[Result]int {
	counts := map[Result]int{}
	for _, m := range r.Modules {
		counts[m.Result]++
	}
	return counts
}

// Summary condense le rapport pour les journaux.
func (r Report) Summary() string {
	c := r.Counts()
	return fmt.Sprintf("statut=%s applique=%d inchange=%d ignore=%d echec=%d",
		r.Status, c[ResultApplied], c[ResultUnchanged], c[ResultSkipped], c[ResultFailed])
}

// Context porte ce dont un appliqueur a besoin au-delà de ses paramètres.
type Context struct {
	// Scope de la politique en cours.
	Scope string
	// Username est l'utilisateur cible en scope user, vide en scope machine.
	Username string
	// HomeDir est le home réel de l'utilisateur cible, substitué au marqueur %h.
	HomeDir string
}

// Applier applique un module et décrit ce qu'il a fait.
//
// Le détail retourné est repris tel quel dans le rapport envoyé au serveur :
// il doit rester court et compréhensible par un administrateur, pas contenir
// une trace technique.
type Applier func(ctx Context, m Module) (detail string, err error)

// ApplyPolicy applique une politique et retourne son rapport.
//
// Seuls les modules dont l'empreinte diffère de celle enregistrée sont
// réappliqués. Un module retiré de la politique n'est pas « désappliqué » : le
// modèle décrit un état voulu, pas un historique, et deviner comment défaire un
// module produirait des effets de bord pires que de laisser l'état en place.
// Retirer une configuration se fait avec un module explicite (state=absent).
func ApplyPolicy(policy *Policy, previous *ScopeState) Report {
	report := Report{
		Scope:       policy.Scope,
		Username:    policy.Username,
		Fingerprint: policy.Fingerprint,
		Status:      StatusApplied,
	}

	ctx := Context{Scope: policy.Scope, Username: policy.Username}
	if policy.Scope == ScopeUser {
		home, err := resolveHomeDir(policy.Username)
		if err != nil {
			// Sans home, aucun module user n'a de cible : on échoue proprement
			// plutôt que d'écrire des fichiers à un emplacement deviné.
			logs.Write_log("ERROR", fmt.Sprintf(
				"GPO: home de %s introuvable, aucune GPO user appliquee : %v", policy.Username, err))
			report.Status = StatusFailed
			for _, m := range policy.Modules {
				report.Modules = append(report.Modules, ModuleOutcome{
					ModuleType: m.Type, StateKey: m.StateKey, Result: ResultFailed,
					Detail: "home de l'utilisateur introuvable",
				})
			}
			return report
		}
		ctx.HomeDir = home
		logs.Write_log("DEBUG", fmt.Sprintf("GPO: home resolu pour %s : %s", policy.Username, home))
	}

	applied, failed := 0, 0

	for _, m := range policy.Modules {
		outcome := applyModule(ctx, m, previous)
		report.Modules = append(report.Modules, outcome)

		switch outcome.Result {
		case ResultApplied:
			applied++
			logs.Write_log("INFO", fmt.Sprintf(
				"GPO: module %s (%s) applique — %s", m.Type, m.StateKey, outcome.Detail))
		case ResultUnchanged:
			logs.Write_log("DEBUG", fmt.Sprintf(
				"GPO: module %s (%s) inchange, non reapplique", m.Type, m.StateKey))
		case ResultSkipped:
			logs.Write_log("WARNING", fmt.Sprintf(
				"GPO: module %s (%s) ignore — %s", m.Type, m.StateKey, outcome.Detail))
		case ResultFailed:
			failed++
			logs.Write_log("ERROR", fmt.Sprintf(
				"GPO: module %s (%s) en echec — %s", m.Type, m.StateKey, outcome.Detail))
		}
	}

	switch {
	case failed == 0:
		report.Status = StatusApplied
	case applied > 0 || failed < len(policy.Modules):
		report.Status = StatusPartial
	default:
		report.Status = StatusFailed
	}

	return report
}

// applyModule applique un module unique en tenant compte de l'état précédent.
func applyModule(ctx Context, m Module, previous *ScopeState) ModuleOutcome {
	outcome := ModuleOutcome{ModuleType: m.Type, StateKey: m.StateKey}

	if previousFP, known := previous.ModuleFingerprint(m.StateKey); known && previousFP == m.Fingerprint {
		outcome.Result = ResultUnchanged
		outcome.Detail = "empreinte identique"
		return outcome
	}

	applier, ok := ApplierFor(m.Type)
	if !ok {
		// Un module que cet agent ne sait pas appliquer : typiquement un serveur
		// plus récent que le client. Le signaler explicitement permet de le voir
		// dans l'interface plutôt que de croire la politique appliquée.
		outcome.Result = ResultSkipped
		outcome.Detail = "type de module non pris en charge par cet agent"
		return outcome
	}

	detail, err := applier(ctx, m)
	if err != nil {
		outcome.Result = ResultFailed
		outcome.Detail = sanitizeDetail(err.Error())
		return outcome
	}
	outcome.Result = ResultApplied
	outcome.Detail = sanitizeDetail(detail)
	return outcome
}

// BuildScopeState construit l'état à enregistrer après application.
//
// Les modules en échec ou ignorés ne sont PAS enregistrés : leur absence de
// l'état provoquera une nouvelle tentative au prochain cycle. Les enregistrer
// reviendrait à considérer comme appliqué ce qui ne l'est pas, et l'erreur
// deviendrait permanente.
func BuildScopeState(policy *Policy, previous *ScopeState, report Report) *ScopeState {
	modules := map[string]string{}
	if previous != nil {
		for key, fp := range previous.Modules {
			modules[key] = fp
		}
	}

	byKey := map[string]Module{}
	for _, m := range policy.Modules {
		byKey[m.StateKey] = m
	}

	// Les clés absentes de la politique courante sont retirées de l'état : le
	// module n'est plus voulu, garder son empreinte fausserait la comparaison
	// s'il revenait plus tard avec les mêmes paramètres.
	for key := range modules {
		if _, still := byKey[key]; !still {
			delete(modules, key)
		}
	}

	for _, outcome := range report.Modules {
		switch outcome.Result {
		case ResultApplied, ResultUnchanged:
			if m, ok := byKey[outcome.StateKey]; ok {
				modules[outcome.StateKey] = m.Fingerprint
			}
		default:
			delete(modules, outcome.StateKey)
		}
	}

	state := &ScopeState{
		Version: policy.Version,
		Status:  string(report.Status),
		Modules: modules,
	}
	// L'empreinte de politique n'est enregistrée que si TOUT est en place.
	// Sinon le prochain cycle croirait la machine à jour et n'y reviendrait pas.
	if report.Status == StatusApplied {
		state.Fingerprint = policy.Fingerprint
	} else if previous != nil {
		state.Fingerprint = previous.Fingerprint
	}
	return state
}

// sanitizeDetail rend un détail transportable dans une trame 05_12 : une seule
// ligne, sans le séparateur de champ, et borné en longueur.
func sanitizeDetail(detail string) string {
	clean := strings.NewReplacer("\n", " ", "\r", " ", "|", "/").Replace(strings.TrimSpace(detail))
	clean = strings.Join(strings.Fields(clean), " ")
	if len(clean) > 240 {
		return clean[:240] + "…"
	}
	return clean
}
