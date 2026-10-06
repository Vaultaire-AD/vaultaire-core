package gpo

import (
	"errors"
	"fmt"
	"os"
	"strings"

	"duckynetworkclient/V1/duckynetwork/logs"
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

	// Files sont les fichiers que ce module vient de déposer, avec leur
	// hachage. Renseigné seulement pour un module réellement appliqué : un
	// module « unchanged » n'a rien écrit, et ses fichiers sont déjà connus
	// de l'état précédent.
	//
	// N'est PAS transmis au serveur : le rapport 05_12 porte le résultat,
	// pas l'inventaire. Les chemins restent locaux à la machine.
	Files map[string]FileState

	// Checks sont les attentes d'état système que ce module vient de déclarer.
	// Même règle que Files : renseigné pour un module réellement appliqué, et
	// jamais transmis au serveur.
	Checks map[string]SystemCheck
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

	// Identité de la machine, pour la substitution des marqueurs du module
	// templated_file_deploy. Résolue une fois par cycle plutôt qu'à chaque
	// module : os.Hostname et la résolution du FQDN peuvent toucher le réseau.
	Hostname string
	FQDN     string
	Domain   string

	// Politique est la politique en cours d'application, ENTIÈRE.
	//
	// Un appliqueur ne voit d'ordinaire que son module. Un seul a besoin de
	// plus : `user_env`, dont toutes les variables partagent un fichier. Le
	// reconstruire depuis ce que le disque contient déjà reviendrait à faire
	// confiance à un fichier que l'utilisateur écrit librement — voir
	// applyUserEnv. Nil dans un test qui appelle un appliqueur à la main.
	Politique *Policy

	// inv est l'inventaire de travail de CE cycle — TO-DO 135.
	//
	// Nil vaut l'inventaire du cycle machine : c'est le cas d'un contexte
	// construit à la main par un test, et celui de tout le scope machine.
	inv *inventaire
}

// inventaire rend l'inventaire du cycle qui porte ce contexte.
func (c Context) inventaire() *inventaire {
	if c.inv == nil {
		return inventaireMachine
	}
	return c.inv
}

// recordCheck déclare un état à revérifier, dans l'inventaire de CE cycle.
//
// C'est la forme qu'emploie tout appliqueur qui connaît le scope utilisateur :
// la fonction nue du même nom inscrit dans l'inventaire du cycle MACHINE, et
// l'attente d'un compte y serait attribuée à un module de la machine — ou à
// personne.
func (c Context) recordCheck(kind, target, expect string) {
	c.inventaire().noterAttente(kind, target, expect)
}

// writeSystemFile écrit un fichier SYSTÈME pour le compte de ce cycle.
//
// Le chemin n'est pas sous un `HOME` — `/etc/systemd/system/user-<uid>.slice.d`
// pour les quotas d'un compte — mais c'est bien le cycle du compte qui l'écrit,
// et c'est donc son inventaire qui doit le retenir.
func (c Context) writeSystemFile(path, content string, mode os.FileMode) error {
	return ecrireFichierSysteme(c.inventaire(), path, content, mode)
}

// removeSystemFile retire un fichier SYSTÈME pour le compte de ce cycle.
func (c Context) removeSystemFile(path string) (bool, error) {
	return retirerFichierSysteme(c.inventaire(), path)
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

	ctx := Context{Scope: policy.Scope, Username: policy.Username, Politique: policy}
	ctx.Hostname, ctx.FQDN, ctx.Domain = machineIdentity()

	ctx.inv = inventairePour(policy.Scope)

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

// inventairePour rend l'inventaire de travail d'UNE application — TO-DO 135.
//
// Celui d'un compte est neuf et ne sert qu'à cette application : deux sessions
// ouvertes à la même seconde par deux personnes n'écrivent plus dans la même
// carte. Celui de la machine est vidé : un seul cycle machine tourne à la fois,
// et rien de ce qu'un cycle antérieur y a laissé ne doit être attribué à un
// module de celui-ci.
func inventairePour(scope string) *inventaire {
	if scope == ScopeUser {
		return nouvelInventaire()
	}
	ResetManifest()
	return inventaireMachine
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

	// Marque AVANT l'appel : ce qui sera inscrit ensuite dans l'inventaire du
	// cycle appartient à ce module. C'est ce qui permet d'attribuer un fichier
	// dérivé au module qui l'a déposé — donc de savoir quoi réappliquer — sans
	// rien demander aux appliqueurs.
	//
	// Une marque et non un relevé comparé : une réécriture à l'identique est une
	// écriture, et deux modules qui produisent le même fichier en répondent
	// tous les deux (voir inventaire.go).
	inv := ctx.inventaire()
	marque := inv.marque()

	detail, err := applier(ctx, m)
	if err != nil {
		outcome.Result = ResultFailed
		outcome.Detail = sanitizeDetail(err.Error())

		// UN CHEMIN SUSPECT N'EST PAS UNE PANNE — TO-DO 97.
		//
		// C'est le signal qu'un poste a été PRÉPARÉ : un lien symbolique planté
		// sous un dossier personnel, à l'endroit précis qu'une politique va
		// emprunter, par quelqu'un qui savait laquelle. Le confondre avec un
		// disque plein dans le journal reviendrait à ne pas le voir.
		//
		// SECURITY, et le nom du compte : c'est la seule ligne qui nommera
		// l'auteur, et le module échoue de toute façon — la trace est tout ce
		// qu'il reste.
		// Deux causes, deux messages, deux remèdes. Les confondre faisait
		// accuser l'utilisateur d'avoir planté un lien symbolique alors que son
		// `HOME` portait simplement un répertoire laissé à un autre compte — et
		// laissait l'exploitant sans rien à faire de cette accusation.
		switch {
		case errors.Is(err, ErrProprietaireAutre):
			logs.Write_log("SECURITY", fmt.Sprintf(
				"GPO: module %s (%s) ABANDONNE pour %s — %s. L'agent ne reprend PAS un "+
					"repertoire deja la : le faire en root, sans savoir d'ou il vient, est "+
					"ce que le point 97 a ferme. Rendez-le a %s (chown) pour debloquer",
				m.Type, m.StateKey, ctx.Username, outcome.Detail, ctx.Username))
		case errors.Is(err, ErrCheminSuspect):
			logs.Write_log("SECURITY", fmt.Sprintf(
				"GPO: module %s (%s) ABANDONNE pour %s — %s. Un composant du chemin "+
					"n'est pas un repertoire reel appartenant a ce compte : verifier le "+
					"poste, un lien symbolique a pu y etre pose deliberement",
				m.Type, m.StateKey, ctx.Username, outcome.Detail))
		}
		return outcome
	}
	outcome.Result = ResultApplied
	outcome.Detail = sanitizeDetail(detail)
	outcome.Files = inv.fichiersDepuis(marque, m.StateKey)
	outcome.Checks = inv.attentesDepuis(marque, m.StateKey)
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
	files := map[string]FileState{}
	checks := map[string]SystemCheck{}
	modes := map[string]string{}
	if previous != nil {
		for key, fp := range previous.Modules {
			modules[key] = fp
		}
		for path, state := range previous.Files {
			files[path] = state
		}
		for id, c := range previous.Checks {
			checks[id] = c
		}
	}

	byKey := map[string]Module{}
	for _, m := range policy.Modules {
		byKey[m.StateKey] = m
	}

	// Le mode vient de la politique COURANTE, et n'est pas repris du précédent
	// état.
	//
	// C'est ce qui fait qu'un retour d'audit vers enforce reprend effet : hériter
	// de l'ancien état laisserait la machine en audit tant qu'aucune autre
	// modification ne serait venue, c'est-à-dire précisément dans le cas où
	// l'administrateur vient de décider le contraire.
	//
	// Enforce n'est pas écrit : c'est le défaut que ModuleMode rend sur une clé
	// absente, et l'écrire mettrait une ligne par module dans le fichier d'état
	// de tous les parcs pour n'y rien dire.
	for key, m := range byKey {
		if m.Mode() != DefaultDriftMode {
			modes[key] = string(m.Mode())
		}
	}

	// Les clés absentes de la politique courante sont retirées de l'état : le
	// module n'est plus voulu, garder son empreinte fausserait la comparaison
	// s'il revenait plus tard avec les mêmes paramètres.
	for key := range modules {
		if _, still := byKey[key]; !still {
			delete(modules, key)
		}
	}

	// Les fichiers d'un module disparu quittent aussi l'inventaire.
	//
	// Les y laisser ferait signaler une dérive éternelle sur un fichier que
	// plus aucune politique ne réclame : le scan verrait un écart, la
	// correction chercherait un module qui n'existe plus, et le cycle
	// recommencerait indéfiniment.
	//
	// Un fichier PARTAGÉ ne part que lorsque son dernier propriétaire est
	// parti : tant qu'un module de la politique y écrit encore, il reste
	// surveillé (TO-DO 135, voir FileState.Owners).
	for path, state := range files {
		var restants []string
		for _, key := range state.proprietaires() {
			if _, still := byKey[key]; still {
				restants = append(restants, key)
			}
		}
		if epure, reste := state.avecProprietaires(restants); reste {
			files[path] = epure
		} else {
			delete(files, path)
		}
	}

	// Et ses attentes d'état système, pour la même raison exactement : une
	// vérification orpheline signalerait éternellement un écart que plus aucun
	// module ne sait corriger.
	for id, c := range checks {
		if _, still := byKey[c.StateKey]; !still {
			delete(checks, id)
		}
	}

	for _, outcome := range report.Modules {
		switch outcome.Result {
		case ResultApplied:
			if m, ok := byKey[outcome.StateKey]; ok {
				modules[outcome.StateKey] = m.Fingerprint
			}

			// Ce que le module vient de déclarer REMPLACE ce qu'il déclarait.
			//
			// L'ancien code se contentait d'ajouter : une entrée que le module
			// ne reproduisait plus restait dans l'état pour toujours. Le cas
			// n'est pas théorique — `user_ssh_client_config` retire le fichier
			// quand son bloc était seul, et réécrit le fichier quand
			// l'utilisateur y a ajouté les siens. L'entrée « ce fichier doit
			// être absent » de la première fois survivait à la seconde, et le
			// scan signalait à chaque passage un fichier « réapparu » que le
			// module, rejoué, laissait pourtant en place : une correction qui
			// ne converge jamais.
			//
			// C'est sans risque depuis que l'inventaire de travail repart de
			// zéro à chaque application : un module rejoué réinscrit TOUT ce
			// qu'il écrit, à l'identique ou non.
			for path, state := range files {
				if epure, reste := state.sansProprietaire(outcome.StateKey); reste {
					files[path] = epure
				} else {
					delete(files, path)
				}
			}
			for id, c := range checks {
				if c.StateKey == outcome.StateKey {
					delete(checks, id)
				}
			}

			for path, state := range outcome.Files {
				// Un autre module de la politique écrit le même fichier : ils
				// en répondent ensemble. Le dernier à avoir écrit donne le
				// hachage — c'est l'état où le disque a été laissé.
				if deja, partage := files[path]; partage {
					state, _ = state.avecProprietaires(
						append(deja.proprietaires(), outcome.StateKey))
					state.StateKey = outcome.StateKey
				}
				files[path] = state
			}
			for id, c := range outcome.Checks {
				checks[id] = c
			}
		case ResultUnchanged:
			// Rien n'a été rejoué : l'empreinte est reconduite, et ce que le
			// module avait déclaré reste ce qu'il déclare.
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
		Files:   files,
		Checks:  checks,
		Modes:   modes,
		// Un état écrit ici l'est sous la règle d'inventaire de cet agent : les
		// modules qu'il fallait rejouer pour y entrer viennent de l'être.
		Inventaire: versionInventaire,
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
	return tronquerRunes(clean, 240)
}

// tronquerRunes coupe sur une frontière de caractère, jamais au milieu.
//
// clean[:240] découpe des OCTETS. Un accent ou un caractère non latin à cheval
// sur la limite produit une séquence UTF-8 invalide, que MariaDB en utf8mb4
// refuse : l'INSERT entier échoue et le rapport est perdu — pour un message de
// diagnostic tronqué, c'est-à-dire pour rien. Les messages d'erreur système
// sont justement l'endroit où les caractères accentués abondent.
func tronquerRunes(s string, max int) string {
	if len(s) <= max {
		return s
	}
	coupe := 0
	for i := range s {
		if i > max {
			break
		}
		coupe = i
	}
	return s[:coupe] + "…"
}

// sanitizePath assainit un chemin destiné à une trame.
//
// Distinct de sanitizeDetail : celui-ci remplace « | » par « / », ce qui
// conviendrait à un message mais transformerait un chemin en un AUTRE chemin,
// plausible et faux. « | » est légal dans un nom de fichier sous Linux ;
// l'encoder en %7C garde la ligne analysable sans mentir sur ce qui a été
// constaté.
func sanitizePath(path string) string {
	clean := strings.NewReplacer("\n", " ", "\r", " ", "|", "%7C").Replace(strings.TrimSpace(path))
	return tronquerRunes(clean, 1000)
}
