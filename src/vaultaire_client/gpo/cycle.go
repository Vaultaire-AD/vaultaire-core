package gpo

import (
	"fmt"
	"sync"
	"time"

	"duckynetworkclient/V1/backoff"
	"duckynetworkclient/V1/duckynetwork/logs"
)

// Cycles complets : demander, appliquer, enregistrer l'état, rapporter.
//
// Deux points d'entrée, correspondant aux deux moments de sollicitation décrits
// dans le protocole :
//   - RunMachineCycle, au démarrage du service puis périodiquement ;
//   - RunUserCycle, après authentification PAM et provisionnement du compte,
//     avant que la connexion ne soit accordée.

// MachineRefreshInterval est l'intervalle de rafraîchissement machine PAR
// DÉFAUT — celui qu'un agent applique tant qu'aucun core ne lui a dit autre
// chose. Une heure : assez court pour qu'un changement se propage dans la
// journée, assez long pour ne pas transformer le parc en générateur de trafic.
//
// La valeur en vigueur est CadenceActuelle() : le core l'annonce dans 05_02 et
// 05_03 (voir cadence.go). Ce défaut ne sert donc qu'entre le démarrage du
// service et la réponse à son premier cycle.
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
	// derniereCleCycle est la clé de session du dernier cycle machine lancé.
	// Elle sert à reconnaître un tunnel rétabli : une clé différente signifie
	// une nouvelle session mère, donc une absence de durée inconnue.
	derniereCleCycle string
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
func runCycle(sessionKey, scope, username string, timeout time.Duration) (rapport Report) {
	label := scope + userLabel(username)
	started := time.Now()
	logs.Write_log("DEBUG", "GPO: debut du cycle "+label)

	motif := ""
	// Dernier cycle retenu pour le rapport de debug : rien ne le gardait, le
	// rapport n'était que journalisé puis envoyé.
	defer func() { noterCycle(scope, username, started, rapport, motif) }()

	outcome := requestPolicy(sessionKey, scope, username, timeout)
	if outcome.ErrorCode != "" {
		motif = outcome.ErrorCode + " : " + outcome.ErrorMessage
	} else if outcome.Unchanged {
		motif = "politique inchangée"
	}

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
//
// # Un minuteur, et non un ticker
//
// La boucle attendait sur un time.Ticker d'intervalle fixe. Trois choses lui
// manquaient, et aucune ne se greffe sur un ticker : une cadence que le core
// peut changer en cours de route, un cycle déclenché hors tour (trame 05_18,
// tunnel rétabli, `vlt gpo refresh`), et un nouvel essai rapproché après un
// cycle en échec plutôt qu'une heure d'attente. Un minuteur réarmé à chaque
// tour rend les trois possibles.
func StartMachineRefresh(sessionKeyProvider func() string) {
	go func() {
		defer logs.Recover("cycle GPO")
		// Premier cycle immédiat : la machine doit être conforme dès le
		// démarrage du service, pas au bout d'un intervalle.
		//
		// L'attente est indispensable : Bootstrap est appelé avant que le tunnel
		// ne soit monté, et la session mère n'est authentifiée que quelques
		// secondes plus tard. Sans elle, le premier cycle repartait sans rien
		// faire et le suivant n'arrivait qu'au tour de ticker, une heure après.
		abouti := runMachineCycleWith(sessionKeyProvider, InitialSessionWait)

		// Une suite de dégressivité par boucle, comme le veut le paquet : elle
		// n'est avancée que par les échecs, et remise à zéro dès qu'un cycle
		// aboutit.
		echecs := backoff.New()
		minuteur := time.NewTimer(prochainDelai(abouti, echecs))
		defer minuteur.Stop()

		for {
			select {
			case <-minuteur.C:
			case <-reveilCycle:
				arreter(minuteur)
			case <-reveilCadence:
				// La cadence a changé : on ne fait pas de cycle, on réarme sur
				// la nouvelle valeur. Lancer un cycle ici ferait rafraîchir tout
				// le parc à la seconde où l'administrateur touche au réglage —
				// exactement la rafale que la cadence sert à éviter.
				arreter(minuteur)
				minuteur.Reset(CadenceActuelle())
				continue
			}

			abouti = runMachineCycleWith(sessionKeyProvider, RetrySessionWait)
			minuteur.Reset(prochainDelai(abouti, echecs))
		}
	}()

	go surveillerReconnexion(sessionKeyProvider)

	logs.Write_log("INFO", fmt.Sprintf(
		"GPO: rafraichissement machine actif (intervalle %s par defaut)", MachineRefreshInterval))
}

// prochainDelai rend l'attente avant le prochain cycle.
//
// Un cycle en échec — pas de session, serveur muet, politique refusée — ne doit
// pas coûter une cadence entière : la machine resterait non conforme pendant
// une heure pour une coupure de trente secondes. La dégressivité plafonne à
// cinq minutes, soit la cadence minimale : un nouvel essai ne peut donc jamais
// être plus espacé que le tour normal.
func prochainDelai(abouti bool, echecs *backoff.Backoff) time.Duration {
	if abouti {
		echecs.Reset()
		return CadenceActuelle()
	}
	attente := echecs.Prochain()
	if cadence := CadenceActuelle(); attente > cadence {
		return cadence
	}
	return attente
}

// arreter vide un minuteur déjà armé pour pouvoir le réarmer sans fuite.
//
// Le Stop d'un minuteur qui vient de se déclencher rend false et laisse sa
// valeur dans le canal : la relire est ce qui évite que le tour suivant ne
// parte immédiatement.
func arreter(minuteur *time.Timer) {
	if !minuteur.Stop() {
		select {
		case <-minuteur.C:
		default:
		}
	}
}

// surveillerReconnexion relance un cycle quand le tunnel a été rétabli.
//
// # Pourquoi une scrutation plutôt qu'un signal
//
// Le tunnel est remonté par le superviseur, dans un paquet qui n'expose aucune
// notification ; en câbler une pour un seul consommateur ferait dépendre la
// couche de transport du paquet GPO. La clé de session est en mémoire, la lire
// ne coûte rien, et la même décision a déjà été prise pour waitForSessionKey.
//
// # Ce que cela corrige
//
// Une machine qui perd le core pendant deux heures revenait avec sa politique
// de la veille jusqu'au tour suivant. C'est précisément le moment où elle a le
// plus de chances d'avoir manqué quelque chose.
func surveillerReconnexion(sessionKeyProvider func() string) {
	defer logs.Recover("surveillance du tunnel GPO")
	for {
		time.Sleep(SessionPollInterval)
		cle := sessionKeyProvider()
		if cle == "" {
			continue
		}
		cycleMu.Lock()
		change := derniereCleCycle != "" && cle != derniereCleCycle
		if change {
			// Notée tout de suite : sans cela, la scrutation redemanderait un
			// cycle toutes les deux secondes jusqu'à ce que celui-ci ait tourné.
			derniereCleCycle = cle
		}
		cycleMu.Unlock()

		if change {
			DemanderCycleImmediat("tunnel retabli")
		}
	}
}

// runMachineCycleWith attend une session utilisable puis exécute un cycle.
//
// Rend vrai si le cycle a effectivement abouti : c'est ce qui décide si la
// prochaine attente est la cadence ou un nouvel essai rapproché.
func runMachineCycleWith(sessionKeyProvider func() string, wait time.Duration) bool {
	sessionKey := waitForSessionKey(sessionKeyProvider, wait)
	if sessionKey == "" {
		logs.Write_log("WARNING", fmt.Sprintf(
			"GPO: aucune session vaultaire etablie apres %s, cycle machine abandonne", wait))
		return false
	}

	cycleMu.Lock()
	derniereCleCycle = sessionKey
	cycleMu.Unlock()

	// Scan de conformité AVANT le cycle.
	//
	// L'ordre n'est pas indifférent. Le scan efface l'empreinte des modules
	// dérivés ; le cycle qui suit les voit donc absents de l'état et les
	// réapplique dans la foulée. Scanner APRÈS aurait fait attendre la
	// correction jusqu'au tour suivant, soit un intervalle complet.
	//
	// Le scan ne touche qu'à l'état local et ne relance aucun service : c'est
	// le cycle qui fait le travail, à un moment prévisible.
	scanMachineDrift(sessionKey)

	return RunMachineCycle(sessionKey).Status != StatusFailed
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

// scanMachineDrift vérifie la conformité et remonte les écarts.
//
// Le rapport part vers le core AVANT la correction : si la machine s'arrête
// entre les deux, l'écart reste visible côté serveur. L'inverse effacerait la
// trace d'un problème qu'on n'a pas encore résolu.
func scanMachineDrift(sessionKey string) {
	report := ScanScope(ScopeMachine, "")
	if report.Checked == 0 {
		// Aucun inventaire : rien n'a encore été appliqué, ou l'état vient d'une
		// version antérieure. Se taire plutôt que d'envoyer un rapport vide qui
		// ferait croire à une vérification réelle.
		return
	}

	if report.Conforming() {
		logs.Write_log("DEBUG", fmt.Sprintf(
			"GPO: conformite verifiee, %d fichier(s) intact(s)", report.Checked))
	}

	if err := SendDriftReport(sessionKey, report); err != nil {
		// Un rapport perdu n'empêche pas la correction : elle est locale. On
		// journalise et on continue.
		logs.Write_log("WARNING", "GPO: rapport de conformite non transmis : "+err.Error())
	}

	EnforceDrift(ScopeMachine, "", report)
}
