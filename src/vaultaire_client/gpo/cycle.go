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

// Attente de la session mère avant un cycle machine.
//
// Le service démarre son transport GPO avant que le tunnel ne soit monté : la
// connexion s'établit puis la session mère s'authentifie, quelques secondes plus
// tard. Sans attente, le premier cycle repartirait à vide et il faudrait
// attendre le tour de ticker suivant — une heure — pour que la machine reçoive
// sa politique.
const (
	// InitialSessionWait borne l'attente au démarrage du service. Large, parce
	// qu'un serveur central lent à répondre ne doit pas coûter une heure de
	// retard à toute une flotte qui redémarre.
	InitialSessionWait = 3 * time.Minute
	// RetrySessionWait borne l'attente des cycles périodiques. Courte : le
	// tunnel est censé être déjà établi, et le prochain tour arrive de toute façon.
	RetrySessionWait = 30 * time.Second
	// SessionPollInterval est le pas de scrutation de la session.
	SessionPollInterval = 2 * time.Second
)

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

	return runCycle(sessionKey, ScopeMachine, "", FetchTimeout)
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
	return runCycle(sessionKey, ScopeUser, username, UserFetchTimeout)
}

// runCycle enchaîne demande, application, enregistrement et rapport.
func runCycle(sessionKey, scope, username string, timeout time.Duration) Report {
	label := scope + userLabel(username)
	started := time.Now()
	logs.Write_log("DEBUG", "GPO: debut du cycle "+label)

	outcome := requestPolicy(sessionKey, scope, username, timeout)

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
		//
		// L'attente est indispensable : Bootstrap est appelé avant que le tunnel
		// ne soit monté, et la session mère n'est authentifiée que quelques
		// secondes plus tard. Sans elle, le premier cycle repartait sans rien
		// faire et le suivant n'arrivait qu'au tour de ticker, une heure après.
		runMachineCycleWith(sessionKeyProvider, InitialSessionWait)

		ticker := time.NewTicker(MachineRefreshInterval)
		defer ticker.Stop()
		for range ticker.C {
			runMachineCycleWith(sessionKeyProvider, RetrySessionWait)
		}
	}()
	logs.Write_log("INFO", fmt.Sprintf(
		"GPO: rafraichissement machine actif (intervalle %s)", MachineRefreshInterval))
}

// runMachineCycleWith attend une session utilisable puis exécute un cycle.
func runMachineCycleWith(sessionKeyProvider func() string, wait time.Duration) {
	sessionKey := waitForSessionKey(sessionKeyProvider, wait)
	if sessionKey == "" {
		logs.Write_log("WARNING", fmt.Sprintf(
			"GPO: aucune session vaultaire etablie apres %s, cycle machine abandonne "+
				"(nouvelle tentative dans %s)", wait, MachineRefreshInterval))
		return
	}
	RunMachineCycle(sessionKey)
}

// waitForSessionKey attend qu'une session mère utilisable soit disponible.
//
// Scrutation plutôt qu'événement : la session est établie par une autre
// goroutine dans un paquet qui n'expose pas de notification, et ajouter un canal
// dans la couche d'authentification pour un seul consommateur coûterait plus
// cher que ce sondage de deux secondes.
func waitForSessionKey(provider func() string, timeout time.Duration) string {
	if key := provider(); key != "" {
		return key
	}

	logs.Write_log("DEBUG", fmt.Sprintf(
		"GPO: session vaultaire pas encore etablie, attente jusqu'a %s", timeout))

	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		time.Sleep(SessionPollInterval)
		if key := provider(); key != "" {
			logs.Write_log("DEBUG", "GPO: session vaultaire disponible, demarrage du cycle machine")
			return key
		}
	}
	return ""
}
