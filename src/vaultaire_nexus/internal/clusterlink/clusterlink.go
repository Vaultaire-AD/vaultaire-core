// Package clusterlink raccorde Nexus au cluster Vaultaire par le réseau Ducky.
//
// # Ce que fait cette version
//
//	enrôlement au premier démarrage   (01_05 → 01_08)  — clé de type vaultaire_nexus
//	authentification du service       (01_01, 02_*)    — via duckynetworkclient/V1
//	enregistrement comme SERVICE      (04_09 → 04_10 | 04_11)
//	battement de cœur                 (04_12 → 04_13 | 04_11)
//	sortie propre à l'arrêt           (04_14)
//
// Nexus est un client SERVICE : il déclare une fonction (type, version, point
// d'accès), pas une machine. Il n'emploie donc pas 04_01/04_07, réservés aux
// nœuds joignables par les agents (core, proxy). Les trois trames 04_09/12/14
// existent déjà côté core (ducky-network/host_handler/service_registry.go) ;
// le rôle écrit dans cluster_nodes est le TYPE figé à la poignée de main,
// c'est-à-dire « vaultaire_nexus ».
//
// # Pourquoi c'est désactivé par défaut
//
// Le core n'accepte une trame que si le TYPE du client l'y autorise, et le type
// « vaultaire_nexus » n'existe pas encore dans son catalogue
// (core/clienttype). Tant que CORE_CHANGEMENTS.md n'est pas appliqué, un
// enrôlement est refusé. Nexus fonctionne alors seul, sans apparaître dans
// « vlt cluster list » — ce qui ne change rien à ce qu'il sert.
package clusterlink

import (
	"context"
	"fmt"
	"log/slog"
	"strings"
	"sync"
	"time"

	"duckynetworkclient/V1/ducky"
	"duckynetworkclient/V1/duckynetwork/sendmessage"
	"duckynetworkclient/V1/duckynetwork/storage"
	"duckynetworkclient/V1/duckynetwork/storage/stosession"
	tramesmanager "duckynetworkclient/V1/duckynetwork/trames_manager"

	"vaultaire_nexus/internal/config"
)

// Capacités déclarées au core : de l'inventaire, jamais un droit.
const capabilities = "rpm,deb,docker,vaultaire,generic"

// Cadence du battement : le core marque hors ligne après 3 minutes.
const heartbeatEvery = 60 * time.Second

// Link est l'état du raccordement.
type Link struct {
	mu     sync.RWMutex
	state  string
	detail string
	since  time.Time

	version  string
	endpoint string
	log      *slog.Logger
	// registered passe à vrai sur 04_10, à faux sur 04_11 « unknown_service ».
	registered bool
}

// Status rend l'état courant.
func (l *Link) Status() (state, detail string) {
	if l == nil {
		return "désactivé", ""
	}
	l.mu.RLock()
	defer l.mu.RUnlock()
	return l.state, fmt.Sprintf("%s (depuis %s)", l.detail, l.since.Format("02/01 15:04"))
}

func (l *Link) set(state, detail string) {
	l.mu.Lock()
	l.state, l.detail, l.since = state, detail, time.Now()
	l.mu.Unlock()
}

// Start lance le raccordement en arrière-plan. Un échec n'arrête pas Nexus :
// il est journalisé, affiché dans l'administration, et retenté.
//
// endpoint est l'adresse publique de Nexus (public_url), annoncée au core.
func Start(ctx context.Context, cfg config.DuckyConfig, endpoint, componentVersion string, log *slog.Logger) *Link {
	l := &Link{version: componentVersion, endpoint: endpoint, log: log}
	l.set("démarrage", "connexion au core")
	storage.VersionComposant = componentVersion
	storage.NomJournal = "vaultaire_nexus_ducky.log"

	// Branché AVANT toute émission : l'accusé 04_10 peut arriver très vite.
	if !tramesmanager.Handled("04") {
		tramesmanager.RegisterHandler("04", l.handle)
	}

	go func() {
		delay := 10 * time.Second
		for {
			session, err := ducky.Start(ducky.Options{
				ConfigPath:    cfg.ConfigPath,
				KeyPath:       cfg.KeyPath,
				Enroll:        cfg.Enroll,
				Persistent:    true,
				SilentConsole: true,
			})
			if err == nil {
				l.set("connecté", "session "+session.SessionID+", enregistrement en cours")
				log.Info("cluster: session Ducky ouverte", "session", session.SessionID)
				l.loop(ctx)
				return
			}
			l.set("échec", err.Error())
			log.Warn("cluster: raccordement impossible — Nexus continue seul", "err", err, "nouvel_essai", delay.String())
			select {
			case <-ctx.Done():
				return
			case <-time.After(delay):
			}
			if delay < 10*time.Minute {
				delay *= 2
			}
		}
	}()
	return l
}

// loop enregistre le service, bat, et le sort proprement à l'arrêt.
// La session est persistante : le socle gère les reconnexions.
func (l *Link) loop(ctx context.Context) {
	l.send("04_09", l.version, l.endpoint, capabilities)
	t := time.NewTicker(heartbeatEvery)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			l.send("04_14")
			l.set("arrêté", "sortie du cluster envoyée")
			return
		case <-t.C:
			l.mu.RLock()
			ok := l.registered
			l.mu.RUnlock()
			if ok {
				l.send("04_12")
			} else {
				// Pas encore d'accusé : on rejoue l'enregistrement plutôt que
				// de battre pour un service que le core ne connaît pas.
				l.send("04_09", l.version, l.endpoint, capabilities)
			}
		}
	}
}

// send compose une trame client → core :
//
//	action / destination / clé de session / utilisateur / id logiciel / contenu…
func (l *Link) send(action string, content ...string) {
	s, err := stosession.SessionsUser.WaitForVaultaireSession()
	if err != nil || s == nil || s.DuckySession == nil {
		l.log.Warn("cluster: aucune session valide, trame non envoyée", "trame", action)
		return
	}
	lines := append([]string{action, "serveur_central", string(s.DuckySession.SessionKey), "vaultaire", storage.Computeur_ID}, content...)
	sendmessage.SendMessage(strings.Join(lines, "\n"), s.DuckySession)
}

// handle traite les réponses de catégorie 04.
func (l *Link) handle(t storage.Trames_struct_client, _ *storage.DuckySession) string {
	if len(t.Message_Order) < 2 {
		return ""
	}
	switch t.Message_Order[1] {
	case "10":
		l.mu.Lock()
		first := !l.registered
		l.registered = true
		l.mu.Unlock()
		l.set("enregistré", "service vaultaire_nexus, "+l.endpoint)
		if first {
			l.log.Info("cluster: service enregistré", "endpoint", l.endpoint)
		}
	case "13":
		// accusé de battement : rien à faire
	case "11":
		code, msg, _ := strings.Cut(t.Content, "\n")
		l.set("refusé", code+" : "+msg)
		l.log.Warn("cluster: refus du core", "code", code, "message", msg)
		if strings.TrimSpace(code) == "unknown_service" {
			// Rejoué au prochain battement, pas tout de suite : un refus
			// définitif (type non service) ne doit pas tourner en boucle.
			l.mu.Lock()
			l.registered = false
			l.mu.Unlock()
		}
	default:
		l.log.Debug("cluster: sous-trame 04 non gérée", "trame", "04_"+t.Message_Order[1])
	}
	return ""
}
