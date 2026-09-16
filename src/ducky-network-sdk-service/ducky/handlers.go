package ducky

import (
	"duckynetworkclient/V1/duckynetwork/storage"
	tramesmanager "duckynetworkclient/V1/duckynetwork/trames_manager"
)

// Handler traite les trames d'une catégorie.
//
// La chaîne renvoyée part au core telle quelle ; « » ne répond rien.
type Handler = tramesmanager.Handler

// Handle branche le traitement d'une catégorie de trames.
//
// # À appeler AVANT Start
//
// La boucle de réception démarre avec la connexion. Un gestionnaire branché
// après coup laisse passer sans traitement les trames arrivées entre-temps — un
// défaut de course, donc rare en test et fréquent en production.
//
//	ducky.Handle("06", gpo.Handler)
//	ducky.Handle("07", web.Handler)
//	session, err := ducky.Start(opts)
//
// Les catégories 01 et 02 sont fournies : 01 est traitée dans le fil de
// l'authentification serveur et ne passe pas par le Spliter, 02 est branchée
// d'office. Les rebrancher est permis mais journalisé.
func Handle(category string, h Handler) {
	tramesmanager.RegisterHandler(category, h)
}

// Handled indique si une catégorie a déjà un gestionnaire.
//
// Pour un programme qui veut compléter sans écraser ce qu'un autre a posé.
func Handled(category string) bool {
	return tramesmanager.Handled(category)
}

// Session est la session Ducky ouverte, telle que la manipulent les
// gestionnaires de trames.
type Session = storage.DuckySession
