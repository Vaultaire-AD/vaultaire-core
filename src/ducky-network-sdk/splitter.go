package duckynetwork

import (
	"errors"
	"fmt"
	"sync"
)

// Erreurs de cycle de vie remontées aux consommateurs.
var (
	// ErrIdentityRejected : le core ne reconnaît plus notre identité.
	//
	// Concrètement, sa réponse à la poignée de main est chiffrée pour une clé
	// qui n'est pas la nôtre, ou l'identifiant n'existe plus. Réessayer avec la
	// même paire ne mènera nulle part : il faut se réenrôler.
	ErrIdentityRejected = errors.New("identité refusée par le core")

	// ErrNotEnrolled : aucune identité n'est encore disponible.
	ErrNotEnrolled = errors.New("client non enrôlé")
)

// CategoryHandler traite une trame que le SDK ne connaît pas.
//
// Retourner une trame non vide la fait envoyer en réponse ; retourner la trame
// zéro ne répond rien.
type CategoryHandler func(c *Client, frame Frame) (Frame, error)

// Splitter aiguille les trames entrantes.
//
// # La règle
//
// Les catégories 01 et 02 sont COMMUNES à tous les clients : poignée de main,
// enrôlement, authentification, fermeture de session. Le SDK les traite
// lui-même, et il refuse qu'on les lui prenne — c'est ce qui garantit qu'un
// programme ne peut pas réinventer sa propre authentification, avec ses propres
// oublis.
//
// Tout le reste est délégué au consommateur : un agent branche 03, 05 et 06 ; un
// proxy branche 04 ; une interface web branchera 07. Le SDK n'a pas à savoir ce
// que ces trames signifient.
type Splitter struct {
	mu       sync.RWMutex
	handlers map[string]CategoryHandler
}

// reservedCategories ne sont jamais délégables.
var reservedCategories = map[string]string{
	"01": "poignée de main et enrôlement",
	"02": "authentification",
}

func NewSplitter() *Splitter {
	return &Splitter{handlers: map[string]CategoryHandler{}}
}

// Handle branche un gestionnaire pour une catégorie.
func (s *Splitter) Handle(category string, h CategoryHandler) error {
	if reason, reserved := reservedCategories[category]; reserved {
		return fmt.Errorf(
			"la catégorie %s (%s) est traitée par le SDK et ne peut pas être remplacée",
			category, reason)
	}
	if h == nil {
		return fmt.Errorf("gestionnaire nil pour la catégorie %s", category)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.handlers[category] = h
	return nil
}

// Dispatch aiguille une trame reçue.
func (s *Splitter) Dispatch(c *Client, frame Frame) error {
	category := frame.Category()

	if _, reserved := reservedCategories[category]; reserved {
		return s.handleReserved(c, frame)
	}

	s.mu.RLock()
	handler, ok := s.handlers[category]
	s.mu.RUnlock()
	if !ok {
		// FAIL-CLOSED, comme côté serveur : une catégorie non branchée est
		// ignorée, pas devinée. Un programme qui reçoit une trame qu'il n'a pas
		// demandé à traiter n'a aucune raison d'improviser.
		return fmt.Errorf("aucun gestionnaire pour la catégorie %s (trame %s)", category, frame.Code)
	}

	reply, err := handler(c, frame)
	if err != nil {
		return err
	}
	if reply.Code == "" {
		return nil
	}
	_, err = c.Send(reply)
	return err
}

// handleReserved traite 01 et 02.
//
// Ces trames arrivent en réponse à ce que nous avons envoyé, dans le flot
// question/réponse de Send : elles n'ont donc normalement pas à repasser par le
// splitter. Le cas est traité pour que le comportement soit défini plutôt que
// silencieux — une 02_07 non sollicitée, par exemple, signale que le core a
// invalidé notre session.
func (s *Splitter) handleReserved(c *Client, frame Frame) error {
	switch frame.Code {
	case Trame02_07:
		return fmt.Errorf("%w: le core a refusé l'authentification", ErrIdentityRejected)
	case Trame01_05, Trame01_06:
		return EnrollError{Code: frame.Line(0)}
	default:
		return nil
	}
}
