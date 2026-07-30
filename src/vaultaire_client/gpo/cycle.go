package gpo

import (
	"fmt"
	"sync"
	"time"

	"vaultaire_client/logs"
)

// Cycles complets : demander, appliquer, enregistrer l'état, rapporter.
//
// Deux points d'entrée, correspondant aux deux moments de sollicitation décrits
// dans le protocole :
//   - RunMachineCycle, au démarrage du service puis périodiquement ;
//   - RunUserCycle, après authentification PAM et provisionnement du compte,
//     avant que la connexion ne soit accordée.

// MachineRefreshInterval est l'intervalle de rafraîchissement de la politique
// machine. Une heure : assez court pour qu'un changement se propage dans la
// journée, assez long pour ne pas transformer le parc en générateur de trafic.
const MachineRefreshInterval = 1 * time.Hour

var (
	cycleMu       sync.Mutex
	machineActive bool
)

// RunMachineCycle exécute un cycle complet de politique machine.
//
// Un seul cycle machine à la fois : le rafraîchissement périodique et un
// déclenchement manuel pourraient sinon appliquer les mêmes modules en parallèle.
func RunMachineCycle(sessionKey string) Report {
	cycleMu.Lock()
	if machineActive {
		cycleMu.Unlock()
		logs.Write_log("DEBUG", "GPO: cycle machine deja en cours, celui-ci est ignore")
		return Report{Scope: ScopeMachine, Status: StatusApplied}
	}
	machineActive = true
	cycleMu.Unlock()

	defer func() {
		cycleMu.Lock()
		machineActive = false
		cycleMu.Unlock()
	}()

	return runCycle(sessionKey, ScopeMachine, "")
}

// RunUserCycle exécute un cycle complet de politique utilisateur.
//
// Appelé après la création et la validation du compte local, avant que le
// résultat ne soit remis au module PAM : l'utilisateur trouve donc son
// environnement en place à l'ouverture de session.
//
// En cas d'échec ou de dépassement du délai, la connexion reste accordée et
// l'incident est journalisé. Aucun module de scope user ne touche aux
// privilèges : une variable d'environnement non posée ne crée pas de faille,
// alors qu'un annuaire qui bloque les connexions sur incident GPO est un
// incident d'exploitation majeur.
func RunUserCycle(sessionKey, username string) Report {
	return runCycle(sessionKey, ScopeUser, username)
}

// runCycle enchaîne demande, application, enregistrement et rapport.
func runCycle(sessionKey, scope, username string) Report {
	label := scope + userLabel(username)
	started := time.Now()
	logs.Write_log("DEBUG", "GPO: debut du cycle "+label)

	outcome := requestPolicy(sessionKey, scope, username)

	switch {
	case outcome.Unchanged:
		logs.Write_log("DEBUG", fmt.Sprintf("GPO: cycle %s termine en %s, rien a appliquer",
			label, time.Since(started).Round(time.Millisecond)))
		return Report{Scope: scope, Username: username, Status: StatusApplied}

	case outcome.ErrorCode != "":
		// no_shared_group est un cas normal, déjà journalisé en DEBUG à la
		// réception : le remonter en WARNING ici polluerait les journaux à
		// chaque connexion d'un utilisateur de passage.
		if outcome.ErrorCode != "no_shared_group" {
			logs.Write_log("WARNING", fmt.Sprintf(
				"GPO: cycle %s abandonne (%s) : %s", label, outcome.ErrorCode, outcome.ErrorMessage))
		}
		return Report{Scope: scope, Username: username, Status: StatusFailed}

	case outcome.Policy == nil:
		logs.Write_log("WARNING", "GPO: cycle "+label+" sans politique ni erreur, cas inattendu")
		return Report{Scope: scope, Username: username, Status: StatusFailed}
	}

	policy := outcome.Policy
	previous := LoadState().Scope(scope, username)

	report := ApplyPolicy(policy, previous)

	state := BuildScopeState(policy, previous, report)
	if err := SaveScopeState(scope, username, state); err != nil {
		// L'état non enregistré signifie que tout sera réappliqué au prochain
		// cycle. Les modules étant idempotents, c'est du travail inutile mais
		// pas dangereux : on le signale sans faire échouer le cycle.
		logs.Write_log("ERROR", "GPO: etat local non enregistre, la politique sera reappliquee : "+err.Error())
	}

	level := "INFO"
	if report.Status != StatusApplied {
		level = "WARNING"
	}
	logs.Write_log(level, fmt.Sprintf(
		"GPO: cycle %s termine en %s — empreinte %s, %s",
		label, time.Since(started).Round(time.Millisecond),
		ShortFingerprint(policy.Fingerprint), report.Summary()))

	SendApplyReport(sessionKey, report)
	return report
}

// StartMachineRefresh lance le cycle machine et son rafraîchissement périodique.
//
// sessionKeyProvider est réévalué à chaque cycle : la clé de session change au
// gré des reconnexions du tunnel, la capturer une fois enverrait des trames
// avec une clé périmée après la première rupture.
func StartMachineRefresh(sessionKeyProvider func() string) {
	go func() {
		// Premier cycle immédiat : la machine doit être conforme dès le
		// démarrage du service, pas au bout d'un intervalle.
		runMachineCycleWith(sessionKeyProvider)

		ticker := time.NewTicker(MachineRefreshInterval)
		defer ticker.Stop()
		for range ticker.C {
			runMachineCycleWith(sessionKeyProvider)
		}
	}()
	logs.Write_log("INFO", fmt.Sprintf(
		"GPO: rafraichissement machine actif (intervalle %s)", MachineRefreshInterval))
}

// runMachineCycleWith exécute un cycle si une clé de session est disponible.
func runMachineCycleWith(sessionKeyProvider func() string) {
	sessionKey := sessionKeyProvider()
	if sessionKey == "" {
		logs.Write_log("DEBUG", "GPO: pas de session vaultaire disponible, cycle machine reporte")
		return
	}
	RunMachineCycle(sessionKey)
}
