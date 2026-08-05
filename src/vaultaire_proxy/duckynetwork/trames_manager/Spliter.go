package tramesmanager

import (
	"fmt"
	"sync"

	"vaultaire_proxy/duckynetwork/logs"
	"vaultaire_proxy/duckynetwork/sendmessage"
	"vaultaire_proxy/duckynetwork/storage"
)

// Handler traite une catégorie de trames.
//
// Retourner une chaîne non vide l'envoie en réponse ; retourner la chaîne vide
// ne répond rien. C'est la même convention que le Spliter de l'agent et celui du
// core : un programme qui connaît l'un connaît les trois.
type Handler func(trames storage.Trames_struct_client, session *storage.DuckySession) string

// Spliter aiguille les trames entrantes vers les gestionnaires de catégorie.
//
// # Ce que le dossier traite lui-même
//
// Les catégories 01 et 02 sont livrées avec des gestionnaires par défaut
// (trames/t01_serveurauth et trames/t02_userauth) : poignée de main, askkey,
// enrôlement, authentification. Elles sont communes à tous les programmes.
//
// Elles restent REMPLAÇABLES, contrairement à ce que faisait la version
// précédente de ce dossier. La raison est pratique : ce dossier est copié, donc
// modifié sur place quand un programme a un besoin particulier. Interdire le
// remplacement n'empêcherait rien — il suffirait d'éditer le fichier — mais
// obligerait à le faire de façon détournée, donc invisible à la relecture.
//
// # Ce qu'il ne traite pas
//
// 03, 04, 05, 06, 07 : chaque programme branche ce dont il a besoin. Une
// catégorie non branchée est journalisée et ignorée — fail-closed, comme côté
// serveur. Un programme qui reçoit une trame qu'il n'a pas demandé à traiter n'a
// aucune raison d'improviser.
type Spliter struct {
	mu       sync.RWMutex
	handlers map[string]Handler
}

func NewSpliter() *Spliter {
	return &Spliter{handlers: map[string]Handler{}}
}

// Handle branche un gestionnaire pour une catégorie (« 04 », « 05 »...).
func (s *Spliter) Handle(category string, h Handler) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.handlers[category] = h
}

// Handled indique si une catégorie est branchée.
func (s *Spliter) Handled(category string) bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	_, ok := s.handlers[category]
	return ok
}

// Split_Action aiguille une trame et envoie la réponse éventuelle.
func (s *Spliter) Split_Action(trames storage.Trames_struct_client, session *storage.DuckySession, serverPublicKeyPEM string) error {
	category := trames.Category()

	s.mu.RLock()
	handler, ok := s.handlers[category]
	s.mu.RUnlock()

	if !ok {
		logs.Write("WARNING", fmt.Sprintf(
			"trame %s ignorée : aucun gestionnaire branché pour la catégorie %s", trames.Code(), category))
		return nil
	}

	message := handler(trames, session)
	if message == "" {
		return nil
	}
	return sendmessage.SendMessage(message, session, serverPublicKeyPEM)
}
