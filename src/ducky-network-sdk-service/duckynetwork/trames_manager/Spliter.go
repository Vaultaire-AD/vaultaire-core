package tramesmanager

import (
	"duckynetworkclient/V1/duckynetwork/logs"
	"duckynetworkclient/V1/duckynetwork/sendmessage"
	"duckynetworkclient/V1/duckynetwork/storage"
	"duckynetworkclient/V1/duckynetwork/userauth"
	"strings"
	"sync"
)

// Handler traite les trames d'une catégorie.
//
// La chaîne renvoyée part au serveur telle quelle. Renvoyer « » ne répond rien,
// ce qui est le cas normal d'un simple accusé ou d'un traitement asynchrone.
type Handler func(trames storage.Trames_struct_client, duckysession *storage.DuckySession) string

var (
	handlersMu sync.RWMutex
	handlers   = map[string]Handler{}
)

// Catégories fournies par le paquet.
//
// 01 n'y figure pas volontairement : l'authentification du serveur lit sa
// réponse elle-même, dans le fil de AskServerAuthentification, avant que la
// boucle de réception ne démarre. Elle ne passe donc jamais par le Spliter.
func init() {
	handlers["02"] = userauth.User_Auth_Manager
}

// RegisterHandler branche le traitement d'une catégorie.
//
// # À appeler AVANT de lancer la session
//
// Le Spliter est consulté par la boucle de réception, qui tourne dès la
// connexion établie. Un gestionnaire branché après coup laisse passer sans
// traitement toutes les trames arrivées entre-temps — un défaut qui ne se voit
// qu'à la course, donc rarement en test et souvent en production.
//
// Remplacer une catégorie déjà branchée est permis : un programme peut vouloir
// son propre traitement de 02. C'est journalisé, parce que le faire par
// inadvertance rendrait l'authentification muette sans autre symptôme.
func RegisterHandler(category string, h Handler) {
	if h == nil {
		return
	}
	handlersMu.Lock()
	defer handlersMu.Unlock()
	if _, exists := handlers[category]; exists {
		logs.Write_log("WARNING", "trames: le gestionnaire de la catégorie "+category+" est remplacé")
	}
	handlers[category] = h
}

// Handled indique si une catégorie a déjà un gestionnaire.
//
// Utile à un programme qui veut compléter sans écraser : brancher son 02 SEULEMENT
// si personne ne l'a fait avant lui.
func Handled(category string) bool {
	handlersMu.RLock()
	defer handlersMu.RUnlock()
	_, exists := handlers[category]
	return exists
}

// Split_Action remet une trame reçue à son gestionnaire.
func Split_Action(trames_content storage.Trames_struct_client, duckysession *storage.DuckySession) {
	if len(trames_content.Message_Order) == 0 {
		return
	}
	category := strings.Split(trames_content.Message_Order[0], "_")[0]

	handlersMu.RLock()
	handler, exists := handlers[category]
	handlersMu.RUnlock()

	if !exists {
		// Journalisé, pas affiché.
		//
		// La version antérieure faisait un fmt.Println du contenu : sur un
		// service en arrière-plan, cela écrivait des trames applicatives sur la
		// sortie standard sans horodatage ni niveau, et la trace disparaissait
		// avec le terminal.
		logs.Write_log("WARNING", "trames: catégorie "+category+" reçue sans gestionnaire branché")
		return
	}

	sendmessage.SendMessage(handler(trames_content, duckysession), duckysession)
}
