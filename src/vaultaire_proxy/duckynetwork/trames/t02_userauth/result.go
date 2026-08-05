package userauth

import (
	"context"
	"fmt"
	"strings"
	"sync"
)

// Result est l'issue d'une authentification.
type Result struct {
	// Username tel que le core l'a retenu, domaine compris.
	Username string
	// IsAdmin n'a de sens qu'après un 02_04 : le compte est-il administrateur
	// de CETTE machine.
	IsAdmin bool
	// PublicKeys sont les clés publiques SSH du compte, une par ligne.
	PublicKeys string
	// Service vaut vrai quand l'issue est 02_11 : c'est le programme qui s'est
	// authentifié, pas une personne.
	Service bool
	// Err est non nul en cas de 02_07.
	Err error
}

// Manager suit une authentification en cours.
//
// Il existe parce que la réception est asynchrone : AskAuthentification rend la
// main dès l'envoi, et les réponses arrivent plus tard par le Spliter. Sans
// point de rendez-vous, l'appelant n'aurait aucun moyen d'apprendre que le
// login a abouti — ni qu'il a échoué.
//
// Un Manager suit UNE authentification à la fois. Un programme qui en mène
// plusieurs de front — un agent qui traite deux ouvertures de session — en
// instancie un par flux.
type Manager struct {
	// MachineInfo fournit le contenu de 02_12. Laissé nil, DefaultMachineInfo
	// est utilisé.
	MachineInfo func() string

	mu   sync.Mutex
	done chan Result
}

// Wait attend l'issue de l'authentification.
//
// Le contexte est le seul garde-fou contre une attente infinie : si le core ne
// répond ni succès ni échec — connexion coupée entre deux trames —, personne ne
// fermera le canal.
func (m *Manager) Wait(ctx context.Context) (Result, error) {
	select {
	case <-ctx.Done():
		return Result{}, ctx.Err()
	case result, ok := <-m.channel():
		if !ok {
			return Result{}, fmt.Errorf("authentification abandonnée")
		}
		return result, result.Err
	}
}

// channel rend le canal d'issue, en le créant au besoin.
//
// Il est créé paresseusement pour qu'un Manager déclaré à zéro soit utilisable :
// un constructeur obligatoire serait une occasion d'oublier de l'appeler, et
// l'oubli se manifesterait par un blocage sans message.
func (m *Manager) channel() chan Result {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.done == nil {
		m.done = make(chan Result, 1)
	}
	return m.done
}

// resolve publie l'issue, une seule fois.
//
// L'écriture est non bloquante : le canal est tamponné à un élément, et un
// second 02_04 — un core qui rejoue — ne doit pas figer la boucle de réception.
func (m *Manager) resolve(result Result) {
	select {
	case m.channel() <- result:
	default:
	}
}

// Reset réarme le Manager pour une nouvelle authentification.
//
// À appeler à chaque reconnexion : un canal déjà servi rendrait immédiatement
// l'issue de la session PRÉCÉDENTE, et le programme croirait authentifiée une
// session qui ne l'est pas.
func (m *Manager) Reset() {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.done = nil
}

func firstLine(content string) string {
	lines := strings.Split(strings.TrimSpace(content), "\n")
	if len(lines) == 0 {
		return ""
	}
	return strings.TrimSpace(lines[0])
}
